// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// NOTE Usage... is the output of `./asn -h`

/*
Package "asn" implements the Apptimist Social Networks a server and
adminsttration client for the protocol described in:
https://github.com/apptimistco/rfc/blob/master/asn.md

Usage:	asn [FLAGS] [COMMAND [ARGS...]]

Flags:

  -admin=false: Run COMMAND or CLI in admin mode.
	This is the default action if the configuration doesn't have
	any listerners.
  -config="asn.yaml": Set configuration filename.
	Without this flag asn searches './' and '/etc' for 'asn.yaml'.
  -diag="": If built with the 'diag' tag, this redirects output
	to the named file instead of syslog.
  -log="": If built *without* the 'nolog' tag, this redirects
	output to the named file instead of syslog.
  -new-keys=false: Print new keys and exit.
  -nologin=false: run COMMAND w/o login
  -server="0": Connect to the configured server with the matching name,
	URL or at the given index.
  -show-config=false: Print configuration with redacted keys and exit.
  -show-errors=false: Print ASN protocol error codes and exit.
  -show-help=false: Print this and exit.
  -show-ids=false: Print ASN protocol identifiers and exit.
  -show-sums=false: Print sums of *.go files and exit.

Examples:

  $ asn -config example-sf.yaml &
  $ asn -config example-adm.yaml echo hello world
  $ asn -config example-adm.yaml -server 1 echo hello world
  $ asn -config example-adm.yaml -server sf echo hello world
  $ asn -config example-adm.yaml -server sf			# CLI
  $ asn -config example-adm.yaml -server sf - <<-EOF
	echo hello world
  EOF

Commands:

  approve BLOB...
	Before acknowledgment, the server forwards the matching blobs
	to its owner or subscriber.
  auth [-u USER] AUTH
	Record user's ED255519 authentication key.
  blob <USER|[USER/]NAME> - CONTENT
	Creates named blob.
  cat BLOB...
	Returns the contents of the named blob.
  clone [NAME][@TIME]
	Replicate or update an object repository.
  echo [STRING]...
	Returns space separated ARGS in the Ack data.
  filter FILTER [ARGS... --] [BLOB...]
	Returns STDOUT of FILTER program run with list of blobs as STDIN.
  fetch BLOB...
	Before acknowledgement the server sends all matching blobs.
  gc [-v|--verbose] [-n|--dry-run] [@TIME]
	Before acknowledgement the server purges older or all blobs
	flagged for deletion.
  iam NAME
        Show NAME instead of LOGIN key in list of Who.
	Used by servers in indirect clone request.
  ls [BLOB...]
	Returns list of matching blobs.
  mark [-u USER] [LATITUDE LONGITUDE | 7?PLACE]
	Record user's location.
  newuser <"actual"|"bridge"|"forum"|"place">
	Creates a new user and return keys in acknowledgment.
  objdump BLOB...
	Returns the decoded header of the named blob
  rm BLOB...
	Flag blobs for removal by garbage collector.
  trace [COMMAND [ARG]]
	Return and flush the PDU trace or manipulate its filter.
  users
	List all users.
  vouch USER SIG
	Vouch for or deny USER's identity.
  who
	List logged in user names, if set, or login key.

Where BLOB may be any of the following:

  -
  '$'<'*' | SUM>[@TIME]
  ['~'['*' | '.' | USER]][GLOB][@TIME]

Server CONFIG Format:
  name: STRING
  dir: PATH
  lat: FLOAT
  lon: FLOAT
  listen:
  - unix:///PATH.sock
  - tcp://:PORT
  - ws://[HOST][:PORT]/PATH.ws
  keys:
    admin:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    server:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      sec:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    nonce: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

Admin CONFIG Format:
  name: STRING
  dir: PATH
  lat: FLOAT
  lon: FLOAT
  keys:
    admin:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      sec:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    server:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    nonce: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  server:
  - name: local
    url: unix:///PATH.sock
  - name: sf
    url: ws://HOST[:PORT]/PATH.ws
    lat: 37.774929
    lon: -122.419415
  - name: la
    url: ws://HOST[:PORT]/PATH.ws
    lat: 34.052234
    lon: -118.243684
*/
package main
