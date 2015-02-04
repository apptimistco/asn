Package `asn` implements the _Apptimist Social Network Protocol_ described in
this [RFC](rfc.md).

Fetch `asn` and its dependencies with GO tool.

    go get -u github.com/apptimistco/asn

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

Run the tests with diagnostics written to `test.diag`.

    go test -tags diag github.com/apptimistco/asn

Build the `asn` command.

    go build github.com/apptimistco/asn

Build `asn` with diagnostics.

    go build -tags diag github.com/apptimistco/asn

Generate keys and hack a config.

    asn -new-keys > my-keys.yaml
    asn -config test-sf -show-config >my-srv.yaml
    echo keys: my-keys.yaml >>my-srv.yaml
    editor my-srv.yaml
    asn -config test-adm -show-config >my-adm.yaml
    echo keys: my-keys.yaml >>my-adm.yaml
    editor my-adm.yaml

Run and test.

    asn -config my-srv &
    asn -config my-adm echo hello world

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

[![GoDoc](https://godoc.org/github.com/apptimistco/asn?status.png)](
https://godoc.org/github.com/apptimistco/asn)
