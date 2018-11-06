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

#pragma once

#include <stdbool.h>

#include "common/mg_str.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mg_str mgos_gcp_get_device_id(void);

/* Returns true if GCP connection is up, false otherwise. */
bool mgos_gcp_is_connected(void);

/*
 * Send a telemetry event to the default topic.
 *
 * Se documentation here:
 * https://cloud.google.com/iot/docs/how-tos/mqtt-bridge#publishing_telemetry_events
 *
 * E.g.: mgos_gcp_send_eventf("{foo: %d}", foo);
 */
bool mgos_gcp_send_event(const struct mg_str data);
bool mgos_gcp_send_eventp(const struct mg_str *data);
bool mgos_gcp_send_eventf(const char *json_fmt, ...);

/*
 * Send a telemetry event to a subfolder topic.
 *
 * E.g.: mgos_gcp_send_event_subf("foo_events", "{foo: %d}", foo);
 */
bool mgos_gcp_send_event_sub(const struct mg_str subfolder,
                             const struct mg_str data);
bool mgos_gcp_send_event_subp(const struct mg_str *subfolder,
                              const struct mg_str *data);
bool mgos_gcp_send_event_subf(const char *subfolder, const char *json_fmt, ...);

#ifdef __cplusplus
}
#endif
