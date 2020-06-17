let GCP = {
  // ## **`GCP.isConnected()`**
  // Return value: true if GCP connection is up, false otherwise.
  isConnected: ffi('bool mgos_gcp_is_connected()'),  

  // ## **`GCP.sendEvent(message)`**
  // Send a telemetry event to the default topic.
  // Return value: false on failure (e.g. no connection to server), true on success.
  sendEvent: ffi('bool mgos_gcp_send_eventp(struct mg_str *)'),

  // ## **`GCP.sendState(message)`**
  // Send a state update
  // Return value: false on failure (e.g. no connection to server), true on success.
  sendState: ffi('bool mgos_gcp_send_statep(struct mg_str *)'),

  // ## **`GCP.config(handler, userdata)`**
  // Call given handler function when config message arrives.
  // A handler receives 2 parameters: message, and userdata.
  // Return value: true if handler has registered, false otherwise.
  config: ffi('bool mgos_gcp_conf(void(*)(struct mg_str *, userdata), userdata)'),

  // ## **`GCP.command(handler, userdata)`**
  // Call given handler function when command message arrives.
  // A handler receives 3 parameters: message, subfolder,
  // and userdata.
  // Return value: true if handler has registered, false otherwise.
  command: ffi('bool mgos_gcp_cmd(void(*)(struct mg_str *, struct mg_str *, userdata), userdata)'),
};

Event.GCP = Event.baseNumber('GCP');
Event.GCP_CONNECT = Event.GCP;
Event.GCP_CLOSE = Event.GCP + 3;
  // ## **`MQTT.sub(topic, handler)`**
  // Subscribe to a topic, and call given handler function when message arrives.
  // A handler receives 4 parameters: MQTT connection, topic name,
  // message, and userdata.
  // Return value: none.
