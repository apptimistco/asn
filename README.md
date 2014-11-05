Package `asn` implements the _Apptimist Social Network Protocol_ described in
this [RFC]( https://github.com/apptimistco/rfc/blob/master/asn.md).

Fetch, build and install `asn` or the versioned package with GO tool.

    go get -u github.com/apptimistco/asn
    go get -u gopkg.in/apptimistco/asn.v0

(See the [MacOS](#macos) section for running `asn` on that instead of Linux)

This will install these external dependencies.
    github.com/apptimistco/yab
    github.com/apptimistco/datum
    code.google.com/p/go.net/websocket
    gopkg.in/yaml.v1

Test the dependencies.

    go test -i github.com/apptimistco/asn

Run the package tests.

    go test github.com/apptimistco/asn/tests

Install the server, admin, and key generations programs.

    go install github.com/apptimistco/asn/srv/asnsrv
    go install github.com/apptimistco/asn/adm/asnadm
    go install github.com/apptimistco/asn/keys/asnkeys

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

- Download latest installer: https://golang.org/dl/
- Open and install go1.*.darwin-amd64-osx10.8.pkg
- Setenv

    export GOROOT=/usr/local/go
    export PATH=$PATH:$GOROOT/bin
    export GOPATH=${HOME}
    export GOBIN=${HOME}/.local/bin

- See http://golang.org/s/gogetcmd to download Version Control Tools
  The Xcode development kit includes Git but you'll need Mercurial
  http://mercurial.selenic.com/downloads
  or, after installing Macports: https://guide.macports.org/

    sudo port install mercurial
