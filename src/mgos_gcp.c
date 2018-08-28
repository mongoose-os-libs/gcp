/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common/cs_base64.h"
#include "common/cs_dbg.h"
#include "common/json_utils.h"
#include "common/mbuf.h"

#include "mbedtls/asn1.h"
#include "mbedtls/bignum.h"
#include "mbedtls/pk.h"

#include "frozen.h"
#include "mgos_mongoose_internal.h"
#include "mongoose.h"

#include "mgos_mqtt.h"
#include "mgos_sys_config.h"
#include "mgos_timers.h"

static mbedtls_pk_context s_token_key;
extern int mg_ssl_if_mbed_random(void *ctx, unsigned char *buf, size_t len);

static const char *get_device_name(void) {
  const char *result = mgos_sys_config_get_gcp_device();
  if (result == NULL) result = mgos_sys_config_get_gcp_device();
  return result;
}

struct jwt_printer_ctx {
  struct cs_base64_ctx b64_ctx;
  struct mbuf jwt;
};

struct gcp_state {
  mgos_timer_id token_ttl_timer_id;
};

static int json_printer_jwt(struct json_out *out, const char *data,
                            size_t len) {
  struct jwt_printer_ctx *ctx = (struct jwt_printer_ctx *) out->u.data;
  cs_base64_update(&ctx->b64_ctx, (const char *) data, len);
  return len;
}

static void base64url_putc(char c, void *arg) {
  struct jwt_printer_ctx *ctx = (struct jwt_printer_ctx *) arg;
  switch (c) {
    case '+':
      c = '-';
      break;
    case '/':
      c = '_';
      break;
    case '=':
      return;
  }
  mbuf_append(&ctx->jwt, &c, 1);
}

static void mgos_gcp_jwt_timeout(void *param) {
  struct gcp_state *state = (struct gcp_state *) param;
  state->token_ttl_timer_id = MGOS_INVALID_TIMER_ID;
  LOG(LL_INFO, ("Dropping MQTT connection due to imminent token expiration"));
  mgos_disconnect(mgos_mqtt_get_global_conn());
}

static void mgos_gcp_mqtt_connect(struct mg_connection *c,
                                  const char *client_id,
                                  struct mg_send_mqtt_handshake_opts *opts,
                                  void *arg) {
  struct gcp_state *state = (struct gcp_state *) arg;
  if (state->token_ttl_timer_id != MGOS_INVALID_TIMER_ID) {
    mgos_clear_timer(state->token_ttl_timer_id);
    state->token_ttl_timer_id = MGOS_INVALID_TIMER_ID;
  }

  double now = mg_time();
  struct jwt_printer_ctx ctx;
  bool is_rsa = mbedtls_pk_can_do(&s_token_key, MBEDTLS_PK_RSA);

  mbuf_init(&ctx.jwt, 200);
  struct json_out out = {.printer = json_printer_jwt, .u.data = &ctx};

  cs_base64_init(&ctx.b64_ctx, base64url_putc, &ctx);
  json_printf(&out, "{typ:%Q,alg:%Q}", "JWT", (is_rsa ? "RS256" : "ES256"));
  cs_base64_finish(&ctx.b64_ctx);
  base64url_putc('.', &ctx);
  uint64_t iat = (uint64_t) now;
  uint64_t ttl = (uint64_t) mgos_sys_config_get_gcp_token_ttl();
  uint64_t exp = iat + ttl;
  if (exp < 1500000000) {
    LOG(LL_ERROR, ("Time is not set, GCP connection will fail. "
                   "Set the time or make sure SNTP is enabled and working."));
  }
  state->token_ttl_timer_id =
      mgos_set_timer((ttl - 30) * 1000, 0, mgos_gcp_jwt_timeout, state);

  cs_base64_init(&ctx.b64_ctx, base64url_putc, &ctx);
  json_printf(&out, "{aud:%Q,iat:%llu,exp:%llu}",
              mgos_sys_config_get_gcp_project(), iat, exp);
  cs_base64_finish(&ctx.b64_ctx);

  unsigned char hash[32];
  int ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                       (const unsigned char *) ctx.jwt.buf, ctx.jwt.len, hash);
  if (ret != 0) {
    LOG(LL_ERROR, ("mbedtls_md failed: 0x%x", ret));
    c->flags |= MG_F_CLOSE_IMMEDIATELY;
    return;
  }

  size_t key_len = mbedtls_pk_get_len(&s_token_key);
  size_t sig_len = (is_rsa ? key_len : key_len * 2 + 10);
  unsigned char *sig = (unsigned char *) calloc(1, sig_len);
  if (sig == NULL) {
    c->flags |= MG_F_CLOSE_IMMEDIATELY;
    return;
  }

  ret = mbedtls_pk_sign(&s_token_key, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                        sig, &sig_len, mg_ssl_if_mbed_random, NULL);
  if (ret != 0) {
    LOG(LL_ERROR, ("mbedtls_pk_sign failed: 0x%x", ret));
    c->flags |= MG_F_CLOSE_IMMEDIATELY;
    return;
  }

  /* ECDSA signature comes as an ASN.1 sequence of R and S and needs to be
   * converted into its raw form. */
  if (!is_rsa) {
    unsigned char *p = sig;
    const unsigned char *end = sig + sig_len;
    size_t len = 0;
    mbedtls_asn1_get_tag(&p, end, &len,
                         MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    mbedtls_asn1_get_mpi(&p, end, &x); /* R */
    mbedtls_mpi_write_binary(&x, sig, key_len);
    mbedtls_asn1_get_mpi(&p, end, &x); /* S */
    mbedtls_mpi_write_binary(&x, sig + key_len, key_len);
    mbedtls_mpi_free(&x);
    sig_len = 2 * key_len;
  }

  base64url_putc('.', &ctx);
  cs_base64_init(&ctx.b64_ctx, base64url_putc, &ctx);
  cs_base64_update(&ctx.b64_ctx, (const char *) sig, sig_len);
  cs_base64_finish(&ctx.b64_ctx);
  free(sig);

  mbuf_append(&ctx.jwt, "", 1); /* NUL */

  char *cid = NULL;
  mg_asprintf(&cid, 0, "projects/%s/locations/%s/registries/%s/devices/%s",
              mgos_sys_config_get_gcp_project(),
              mgos_sys_config_get_gcp_region(),
              mgos_sys_config_get_gcp_registry(), get_device_name());

  LOG(LL_DEBUG, ("ID : %s", cid));
  LOG(LL_DEBUG, ("JWT: %s", ctx.jwt.buf));
  LOG(LL_DEBUG, ("JWT Refresh Timeout: %d", ((int) ttl - 30) * 1000));

  opts->user_name = "unused";
  opts->password = ctx.jwt.buf; /* No mbuf_free, caller owns the buffer. */
  mg_send_mqtt_handshake_opt(c, cid, *opts);
  free(cid);
  (void) client_id;
}

static void mgos_gcp_mqtt_ev(struct mg_connection *nc, int ev, void *ev_data,
                             void *user_data) {
  struct gcp_state *state = (struct gcp_state *) user_data;

  switch (ev) {
    case MG_EV_MQTT_DISCONNECT: {
      if (state->token_ttl_timer_id != MGOS_INVALID_TIMER_ID) {
        mgos_clear_timer(state->token_ttl_timer_id);
        state->token_ttl_timer_id = MGOS_INVALID_TIMER_ID;
      }

      break;
    }

    default:
      break;
  }

  (void) nc;
  (void) ev_data;
}

bool mgos_gcp_init(void) {
  if (!mgos_sys_config_get_gcp_enable()) return true;
  if (mgos_sys_config_get_gcp_project() == NULL ||
      mgos_sys_config_get_gcp_region() == NULL ||
      mgos_sys_config_get_gcp_registry() == NULL ||
      mgos_sys_config_get_gcp_key() == NULL) {
    LOG(LL_ERROR, ("gcp.project, region, registry and key are required"));
    return false;
  }
  if (get_device_name() == NULL) {
    LOG(LL_ERROR, ("Either gcp.device or device.id must be set"));
    return false;
  }
  mbedtls_pk_init(&s_token_key);
  int r = mbedtls_pk_parse_keyfile(&s_token_key, mgos_sys_config_get_gcp_key(),
                                   NULL);
  if (r != 0) {
    LOG(LL_ERROR, ("Invalid gcp.key (0x%x)", r));
    return false;
  }

  struct gcp_state *state = calloc(1, sizeof(*state));
  state->token_ttl_timer_id = MGOS_INVALID_TIMER_ID;

  mgos_mqtt_set_connect_fn(mgos_gcp_mqtt_connect, state);
  mgos_mqtt_add_global_handler(mgos_gcp_mqtt_ev, state);
  LOG(LL_INFO,
      ("GCP client for %s/%s/%s/%s, %s key in %s",
       mgos_sys_config_get_gcp_project(), mgos_sys_config_get_gcp_region(),
       mgos_sys_config_get_gcp_registry(), get_device_name(),
       mbedtls_pk_get_name(&s_token_key), mgos_sys_config_get_gcp_key()));
  struct mgos_config_mqtt mcfg = *mgos_sys_config_get_mqtt();
  mcfg.enable = true;
  mcfg.server = "mqtt.googleapis.com";
  if (mcfg.ssl_ca_cert == NULL) mcfg.ssl_ca_cert = "ca.pem";
  return mgos_mqtt_set_config(&mcfg);
}
