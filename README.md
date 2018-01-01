# Google IoT Core integration for Mongoose OS

This library implements integration of Mongoose OS with Google IoT Core.

<iframe src="https://www.youtube.com/embed/Rz6-RvYLLlk"
  width="560" height="315"  frameborder="0" allowfullscreen></iframe>


## Setup cloud side

Install [gcloud command line tool](https://cloud.google.com/sdk/gcloud/)

Install beta components:
```
gcloud components install beta
```
Authenticate with Google Cloud:
```
gcloud auth login
```
Create cloud project - choose your unique project name:
```
gcloud projects create YOUR_PROJECT_NAME
```
Add permissions for IoT Core:
```
gcloud projects add-iam-policy-binding YOUR_PROJECT_NAME --member=serviceAccount:cloud-iot@system.gserviceaccount.com --role=roles/pubsub.publisher
```
Set default values for `gcloud`:
```
gcloud config set project YOUR_PROJECT_NAME
```
Create PubSub topic for device data:
```
gcloud beta pubsub topics create iot-topic
```
Create PubSub subscription for device data:
```
gcloud beta pubsub subscriptions create --topic iot-topic iot-subscription
```
Create device registry:
```
gcloud beta iot registries create iot-registry --region europe-west1 --event-pubsub-topic=iot-topic
```

## Setup device side

Get project ID of your new project:

```
gcloud projects list
```

Register device on Google IoT Core. If a device is already registered,
this command deletes it, then registers again. Note that this command is
using `YOUR_PROJECT_ID` instead of `YOUR_PROJECT_NAME`. Take the project ID
from the result of your previous command:

```
mos gcp-iot-setup --gcp-project YOUR_PROJECT_ID --gcp-region europe-west1 --gcp-registry iot-registry
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
