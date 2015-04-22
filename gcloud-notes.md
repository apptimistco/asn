# Google App, Container, and Compute Engine notes

## Google App Engine

Follow this to start an App Engine:
https://console.developers.google.com/start/appengine?authuser=1

But the reference SDK is missing the `goapp` that had to be installed
separately.

    $ curl https://sdk.cloud.google.com/ | bash
    $ source google-cloud-sdk/completion.bash
    $ curl go_appengine_sdk_linux_amd64-1.9.18.zip > go_appengine_sdk_linux_amd64-1.9.18.zip
    $ unzip go_appengine_sdk_linux_amd64-1.9.18.zip
    $ export PATH=$HOME/go_appengine:$PATH

Create project with web console: https://console.developers.google.com/

    Create Project

Or CLI:

    $ gcloud init apptimist-test

Sign-in:

    $ gcloud auth login
    $ gcloud config set project apptimist-test
    $ PROJECT=fifth-flash-89003

Run demo locally:

    $ goapp serve go_appengine/demos/helloworld &
    $ w3m localhost:8080

Deploy demo:

    $ goapp deploy -application ${PROJECT} src/appengine-try-go
    $ w3m http://${PROJECT}.appspot.com

Shutdown with web console: https://console.developers.google.com

    Project: apptimist-test
    Compute->App Engine->Instances->Shutdown

## Google Container Engine

Unfortunately, Google App Engines don't support disk operations, only Cloud
Storage, Datastore and SQL. So instead, let's try a Container Engine.

Enable preview features in the gcloud tool:

...
$ gcloud components update preview
...

Set project, zone and cluster:

    $ gcloud config set project ${PROJECT}
    $ gcloud config set compute/zone us-central1-f
    $ gcloud config set container/cluster apptimist-cluster-1

Create a container with the web console: https://console.developers.google.com

    Project: apptimist-test
    Compute->Container Engine: Create

Or cli:

    $ gcloud preview container clusters create hello-world \
        --num-nodes 1 --machine-type g1-small

Follow this to try the hello-wordpress example:

https://cloud.google.com/container-engine/docs/hello-wordpress

    $ cat >wordpress.json <<EOF
    {
      "id": "wordpress",
      "kind": "Pod",
      "apiVersion": "v1beta1",
      "desiredState": {
        "manifest": {
          "version": "v1beta1",
          "containers": [{
            "name": "wordpress",
            "image": "tutum/wordpress",
            "ports": [{
              "containerPort": 80,
              "hostPort": 80
            }]
          }]
        }
      }
    }
    EOF
    $ gcloud preview container kubectl create -f wordpress.json
    $ gcloud preview container kubectl get pod wordpress
    $ gcloud compute firewall-rules create default-allow-http --allow tcp:80
    $ gcloud preview container kubectl get pod wordpress
    POD		IP		CONTAINER(S)	IMAGE(S)	HOS...
    wordpress	10.232.0.5	wordpress	tutum/wordpress	k8s-apptimist-cluster-1-node-1.c.fifth-flash-89003.internal/104.154.35.240

Try it: http://104.154.35.240

Stop with web console: https://console.developers.google.com

    Projects: apptimist-test
    Compute->Container Engine: apptimist-cluster-1
    Name:  k8s-apptimist-cluster-1-node-1
    Stop

Or cli:

    $ gcloud preview container kubectl stop -f wordpress.json

Cleanup with web console: https://console.developers.google.com

    Projects: apptimist-test
    Compute->Container Engine: apptimist-cluster-1
    Delete

Or cli:

    $ gcloud preview container clusters delete apptimist-cluster-1

## Google Compute Engine

To run a Google Compute Engine,

    $ gcloud auth login
    $ gcloud config set project apptimist-test
    $ gcloud config set compute/zone us-central1-f
    $ gcloud compute instances create apptimist-1 --image debian-7
    $ gcloud compute firewall-rules create default-allow-http \
        --description "Incoming http allowed." --allow tcp:80
    $ gcloud compute firewall-rules create allow-http-alt \
        --description "Incoming http-alt allowed." --allow tcp:8080
    $ gcloud compute ssh apptimist-1
    $ gcloud compute config-ssh
    $ ssh apptimist-1.us-central1-f.fifth-flash-89003 date
    $ scp ~/src/github.com/apptimistco/hello/hello \
        apptimist-1.us-central1-f.fifth-flash-89003:/tmp
    $ ssh apptimist-1.us-central1-f.fifth-flash-89003 sudo /tmp/hello &
    $ w3m -dump http://104.154.35.240:8080
    Hello Apptimist!
    $ gcloud compute instances stop apptimist-1

From:: https://cloud.google.com/compute/docs/quickstart

Attach a non-root, persistent disk,

    $ gcloud compute disks create apptimist-disk-1
    $ gcloud compute instances attach-disk apptimist-1 --disk apptimist-disk-1
    $ sudo mkdir /mnt/asn
    $ ssh apptimist-1.us-central1-f.fifth-flash-89003 sudo \
        /usr/share/google/safe_format_and_mount -m "mkfs.ext4 -F" \
        /dev/disk/by-id/google-persistent-disk-1 /mnt/asn
    $ ssh apptimist-1.us-central1-f.fifth-flash-89003 sudo \
        tee --append /etc/fstab <<EOF
    UUID=f528bb2e-23e2-40ec-bb95-75af939142c3 /mnt/asn ext4 defaults 0 2
    EOF

Promote and attach ephemeral address,

    $ gcloud compute instances describe apptimist-1
    $ gcloud compute addresses create apptimit-address-1 \
        --addresses 104.154.68.215 --region us-central1
    $ gcloud compute addresses list
    $ gcloud compute instances describe apptimist-1
    $ gcloud compute instances delete-access-config apptimist-1 \
        --access-config-name external-nat
    $ gcloud compute instances add-access-config apptimist-1 \
        --access-config-name apptimist-1-access-config \
        --address 104.154.68.215
    $ gcloud compute instances describe apptimist-1
    $ gcloud compute addresses list
