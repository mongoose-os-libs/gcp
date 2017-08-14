# Google IoT Core integration for Mongoose OS

This library implements integration of Mongoose OS with Google IoT Core.

## Google IoT Core onboarding instructions

- Set up Google IoT Core account
- Follow the [device manager guide](https://cloud.google.com/iot/docs/device_manager_guide)
  to register your device and generate ES256 key pair
- Two files will be created: `ec_private.pem` and `ec_public.pem`
- Initialise the device:

	```bash
	mos flash esp8266       # Or esp32
	mos wifi SSID PASS      # Your WiFi network name and password
	```

- Copy the private key to the device

	```bash
	mos put ec_private.pem
	```

- Configure the device's GCP settings

  ```bash
  PROJECT=my-project
  REGION=us-central1
  REGISTRY=my-registry
  DEVICE_ID=my-es256-device

  mos config-set mqtt.enable=true mqtt.server=mqtt.googleapis.com:8883 \
    mqtt.ssl_ca_cert=ca.pem sntp.enable=true gcp.enable=true \
    gcp.project=$PROJECT gcp.region=$REGION gcp.registry=$REGISTRY \
    gcp.device=$DEVICE_ID device.id=$DEVICE_ID gcp.key=ec_private.pem \
    debug.stderr_topic=/devices/$DEVICE_ID/events/log \
    debug.stdout_topic=/devices/$DEVICE_ID/events/log
  ```

## Test

Run `mos ui` to enter Web UI. Specify your device address (serial port) to connect to your device and reboot it. You should see the following messages:

```text
...
mgos_gcp_init        GCP client for my-project/us-central1/my-registry/my-es256-device, EC key in ec_private.pem
...
mgos_mqtt_ev         MQTT Connect (1)
mgos_mqtt_ev         MQTT CONNACK 0
mgos_mqtt_ev         Subscribing to 'my-es256-device/rpc'
mgos_mqtt_ev         Subscribing to 'my-es256-device/rpc/#'
...
```

Default firmware publishes an MQTT message whenever the "Flash" button is pressed:

```text
Published: yes topic: /devices/my-es256-device/events message: {"free_ram":30080,"total_ram":51912} 
```

## Using ATECC508A crypto chip

See https://mongoose-os.com/blog/mongoose-os-google-iot-ecc508a/ on
how to use ATECC508A crypto chip with Mongoose OS and Google IoT Core.
