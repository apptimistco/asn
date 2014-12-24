Package `asn` implements the _Apptimist Social Network Protocol_ described in
this [RFC]( https://github.com/apptimistco/rfc/blob/master/asn.md).

Fetch `asn` and its dependencies with GO tool.

    go get -t -u github.com/apptimistco/asn

(See the [MacOS](#macos) section for running `asn` on that instead of Linux)

This will install these external dependencies.
    github.com/agl/ed25519
    github.com/tgrennan/go-gnureadline
    golang.org/x/crypto
    golang.org/x/net
    gopkg.in/yaml.v1

Note: `go-gnureadline` requires libreadline-dev; so, on Ubuntu:

    sudo apt-get install libreadline-dev

Test the dependencies.

    go test -i github.com/apptimistco/asn

Run the package tests.

    go test github.com/apptimistco/asn

Install the server, admin, and key generation programs.

    go install github.com/apptimistco/asn/asnsrv
    go install github.com/apptimistco/asn/asnadm
    go install github.com/apptimistco/asn/asnkeys

Generate keys and hack a config.

    asnkeys > keys.yaml
    cp ~/src/github.com/apptimistco/asn/tests/siren-sf.yaml .
    cp ~/src/github.com/apptimistco/asn/tests/siren-adm.yaml .
    editor siren-sf.yaml
    editor siren-adm.yaml

Run the server and test with the admin program.

    asnsrv siren-sf &
    asnadm siren-adm echo hello world

Import `asn` or the versioned package into another package like this.

    import "github.com/apptimistco/asn"
    import "gopkg.in/apptimistco/asn.v0"

[![GoDoc](https://godoc.org/github.com/apptimistco/asn?status.png)](
https://godoc.org/github.com/apptimistco/asn)

#### MacOS ####
To run `asn` under MacOS, start by installing Go tools.

a. Prebuilt install
  - Download latest https://golang.org/dl/
  - Open and install `go1.*.darwin-amd64-osx10.8.pkg`
  - Setenv

    export GOROOT=/usr/local/go
    export GOPATH=${HOME}/go
    export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

b. Build from source

    export GOPATH=$HOME/go
    git clone --branch go1.4 https://go.googlesource.com/go
    (cd go/src; ./all.bash)

See http://golang.org/s/gogetcmd to download Version Control Tools
The Xcode development kit includes Git but you may need Mercurial http://mercurial.selenic.com/downloads
or, after installing Macports: https://guide.macports.org/

    sudo port install mercurial

Install readline before getting asn.

    sudo port install readline
