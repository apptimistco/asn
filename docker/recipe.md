# Docker/GCloud Recipe

First install tools beyone Go compiler.

    $ sudo apt-get install docker.io
    $ sudo adduser $USER docker
    $ wget sdk.cloud.google.com
    $ source sdk.cloud.google.com
    $ source google-clud-sdk/path.bash.inc
    $ source google-clud-sdk/completion.bash.inc
    $ gcloud auth login
    $ gcloud config set project asn

Build the program and its container.

    $ go build [-tags diag] -o docker/asn
    $ docker build -t asn docker

or...

    $ docker/build [-tags diag]

Test the container.

    $ docker -rm -v $PWD:/srv asn:latest --config test-sf --show-config
    $ docker -d --name=test=sf -p 127.0.0.1:6080:6080 -v $PWD:/srv \
	asn:latest --config test-sf
    $ docker -rm -v $PWD:/srv asn:latest --config test-adm ls
    $ docker -i -rm -v $PWD:/srv asn:latest --config test-adm
    $ docker/asn --config test-adm --server sf.ws users
    $ docker -d --name=test=la -p 127.0.0.1:6022:6022 -v $PWD:/srv \
	asn:latest --config test-la
    $ docker/asn --config test-adm --server la.tcp users

Add and test your own builtin or separate config file.

**FIXME** How to run in gcloud.
