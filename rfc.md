# App-Server Protocol #
This RFC describes the protocol between an Apptimist Social Networking Apps and
servers.

<!--
         1         2         3         4         5         6         7         8
12345678901234567890123456789012345678901234567890123456789012345678901234567890
-->

**Status:** proposed

## Description ##
The Apptimist Social Network (ASN) protocol is an exchange of encapsulated
data units between an App and Server along with a few, server resident access
control files. The Apps themselves extend this protocol with further
definition of the encapsulated content and other server resident data files.

## Notation ##
In this document, *"device"* refers to the App running on IOS or Android
device whereas *"service"* refers to programs running on an Apptimist
(potentially cloud based) server.

This document describes a protocol data unit (PDU) as concatenated components.

    xyz = X Y Z

The double-quote encapsulated components denote UTF-8 strings. Unlike the
C-language, such strings are not null terminated.

Comments are introduced with a C++ style double slash.

Numeric literals may be C like decimal or "0x" prefaced hexadecimal digits.

Types are described as:

    [ "[" [ number ] "]" ] {uint,float}{8,16,32,64} [ "{" value "}" ]`

The elemental component type is an 8, 16, 32, or 64-bit, big-endian, unsigned
integer with keywords `uint8`, `uint16`, `uint32` and `uint64` respectively.
A `float` is either a 32 or 64 bit, big-endian, IEEE-754 floating point
number.

An array component has a bracket-bound numbered preface indicating a sequence
of a single element type. Successive bracket-bound number prefaces indicate
multi-dimensional arrays. The number may be absent indicating a possible zero
length array defined by the number in another component.  Examples:

    owner = [32]uint8
    namelen = uint8
    name = []uint8

A composite literal component appends a brace-bond list of composite elements.
Examples:

    version = uint8{0}
    nonce = [24]uint8{ id seq }
    id = [64]uint8
    seq = uint64
    nameLen = uint8{ name.Length() }
    name = []uint8
    lat = float64{37.82022}
    lon = float64{-122.47732}

## Users ##
Apptimist Social Networks have three types of users: actual, forum, and
bridge.  An actual user is a member or administrator of the social network. A
forum or event is created by an administrator or actual user to distribute
messages and share content to subscribers. A bridge may also be created by a
member or administrator to multi-cast messages to all signed-in subscribers.

## WebSockets ##
ASN runs through non-secure WebSockets described in RFC-6455[[1](#1)].  These
are Web vs. TCP or UDP Sockets to provide the most flexible service through
carrier proxy servers and enterprise firewalls. Also, these are non-secure
HTTP sockets instead of the SSL secured HTTPS because ASN includes
ED25519[[2](#2)] authenticated signatures and NaCL[[3](#3)] authenticated
encryption to provide a user assigned web-of-trust rather than a centralized
certificate authority.

### URI ###
    URI = "ws://" host [ ":" port ] path [ "?" query ]

The initial `host` for Apptimist services has this registered domain name.

    host = app ".apptimist.co"

Where `app` is the service name; for example, `siren`.

Some service features may direct the client to establish simultaneous
WebSocket to another service engine; for example,

    sf.siren.apptimist.co
    la.siren.apptimist.co
    ny.siren.apptimist.co
    bridge.siren.apptimist.co

The `port` component is optional; the default is 80, but may be different for
testing.

The `path` component for most services is a slash prefaced, WebSocket protocol
name; e.g. `/ws/asn`.

The `query` component is unused and should be empty.

For example,

    ws://siren.apptimist.co/ws/asn

## Cryptography ##
ASN PDUs are encrypted in segments of up to 4096-bytes, including the 16-byte
encryption overhead. Each segment is preceded by a uint16 length with the most
significant bit used as a `More` flag that is set for each but the final PDU
segment.

    segment = moreLen data
    moreLen = uint16
    data = [1..4096]uint8

After connecting, the device (the App or a mirroring server) sends its
32-byte, ephemeral public key to the server. It uses this key along with the
proprietary service key and nonce to encrypt the first `login` request PDU.
The server's acknowledgment includes it's own ephemeral key and nonce to
replace the initial proprietary key/nonce in subsequent segment encryption.

The last two bytes of the initial proprietary, then following ephemeral nonce
are sequential counters following the NaCL "_Security model_"[[4](#4)] whereby
these increment by 2 for each segment sent between socket endpoints for the
connection duration.  The side with the lexicographically smaller public key
sends its first segment with 1, 3 on the second, 5 on the third, etc.;
meanwhile, the lexicographically larger public key peer uses 2, 4, 6, etc.

## Format ##
Each ASN PDU begins with version and identifier components.

    pdu = version id
    version = uint8{ 0 }
    id = uint8

There are two types of PDUs, requests and objects.

Each request has an 8-byte requester following the version, id pair.

    requester = [8]uint8

Instead of requester, the only object, a blob has this 8-byte magic string
following the version, id pair.

    magic = [8]uint8{"asnmagic"}

## States ##
The ASN protocol has very few states.

1. `opened`, prior to an acknowledged `login` or subsequent `resume`
2. `provisional`, after first `login`, prior to upload of authentication key
3. `established`, after verified `login`
4. `suspended`, after an acknowledged `pause` and before `resume`
5. `quitting`, awaiting `quit` acknowledgment
6. `closed`, received `quit` acknowledgment and terminated connection


## Identifiers ##
To support flexible protocol evolution, the App and Service use lookup tables
to map PDU identifier and error codes. Here are the most recent identifiers:
<!-- go test -v -run Ids github.com/apptimistco/asn -->

                         Version
                            0
       1.        AckReqId   1
       2.       ExecReqId   2
       3.      LoginReqId   3
       4.      PauseReqId   4
       5.       QuitReqId   5
       6.   RedirectReqId   6
       7.     ResumeReqId   7
       8.          BlobId   8

## Acknowledgment ##
Each request is acknowledged by this `AckReq`.

    ack = version id requester result data
    version = uint8{ 0 }
    id = uint8{ AckReqId }
    requester = [8]uint8
    result = uint8
    data = []uint8

Where `result` is one of these codes.
<!-- go test -v -run Errs github.com/apptimistco/asn -->

                         Version
                            0
       0.         Success   0
       1.       DeniedErr   1
       2.      FailureErr   2
       3.     IlFormatErr   3
       4. IncompatibleErr   4
       5.     RedirectErr   5
       6.        ShortErr   6
       7.   UnexpectedErr   7
       8.      UnknownErr   8
       9.  UnsupportedErr   9

A negative acknowledgment shall include a UTF-8 character string describing
the error as the `data` component except for `RedirectErr` where it's the
redirected URL for the requested service.

The `data` component of positive acknowledgments to these `exec` commands that
create blobs has the 128 hexadecimal character encoding of the blob sum.

    approve, auth, blob, mark, rm, vouch

All other command and PDU acknowledgment is described below.

## Session Management ##
The device establishes a user session with this `login` request immediately
after sending its ephemeral key.

    login = version id requester user sig
    version = uint8{ 0 }
    id = uint8{ LoginReqId }
    requester = [8]uint8
    user = [8]uint8
    sig = [64]uint8

Where `user` is the user's public (not ephemeral) encryption key and `sig` is
the user's signature of their own key. If this is the user's first login, the
session is in `provisional` state until the device uploads the user's
authentication key (see below). Once available, the service verifies the
signed user key before setting the `established` state.  The service prohibits
login with forum or bridge keys.

After session establishment the device may suspend the session with this
`pause` request to maintain the connection in a low power state until
continuing with the following `resume` request.

    pause = version id requester
    version = uint8{ 0 }
    id = uint8{ PauseReqId }
    requester = [8]uint8

    resume = version id requester
    version = uint8{ 0 }
    id = uint8{ ResumeReqId }
    requester = [8]uint8

The service may instruct the device to terminate the active connection and
reconnect (at possibly another URL) with this `redirect` request. With an
empty `url` component, the device should reconnect to the same server after
waiting 10 or more seconds.

    redirect = version id requester url
    Version = uint8{ 0 }
    id = uint8{ RedirectReqId }
    requester = [8]uint8
    url = []uint8

Either device or service may terminate the session at anytime with this `quit`
request.

    quit = version id requester
    version = uint8{ 0 }
    id = uint8{ QuitReqId }
    requester = [8]uint8

## Exec ##
This request is a command line style interface to several services.

    exec = version id requester argv
    version = uint8{ 0 }
    id = uint8{ ReqAckId }
    requester = [8]uint8
    argv = []string

Where `argv` is a null separated list of ASCII command arguments with the
optional `-\0` separating command input. All `exec` requests receive an
acknowledgment. In addition, some may have associated objects sent to the
requester.

In each of the following exec commands, SERVICE, EPHEMERAL, LOGIN, USER and
PLACE are the UTF-8, hexadecimal encoding of the respective public encryption
keys that may be abbreviated to whatever uniquely identifies them.  GIT
experience suggests that 8 characters may be sufficient.

BLOB is one of these ASN object references:

    BLOB = <FILE|SUM|USER[@EPOCH]|[USER]@EPOCH|[USER/]NAME[@EPOCH]>

The default USER is LOGIN and the wild card USER is SERVICE meaning for all
users.

FILE is a local file system name used only in testing.

NAME may have forward slash ("/") hierarchy. If the base component of the name
is hexadecimal, as with messages, it may be abbreviated like USER.
Alternatively, the base component may use shell `*` and `?` expansion
characters to match repository names (e.g. `asn/hel*` for `asn/hello`)

SUM is a UTF-8 hexadecimal encoding of the 64-byte SHA512 sum of the
referenced blob file. This may be abbreviated to as few as 8 characters.

EPOCH is a UTF-8 decimal encoding of the 64-bit integer nanoseconds since
the Unix epoch (00:00:00.000000 Jan 1, 1970)

LATITUDE and LONGITUDE are UTF-8 decimal encoding of floating point degrees.

### approve ###
    approve SUM...

A moderator's device may exec this command in the `established` state for the
server to create, process, and distribute a blob named `asn/approvals/SUM`
with the expanded SUM arguments as described in the [permission](#permission)
section.

### auth ###
    auth [-u USER] AUTH

The device must exec this command in the `provisional` state for the server to
create, process, and distribute a blob named "asn/auth" containing the user's
32-byte, public ED25519 authentication key that is decoded from the
64-character, UTF-8 hexadecimal AUTH argument string.

### blob ###
    blob <USER|[USER/]NAME> - CONTENT

The device may exec this command in the `established` state for the server to
create, process, and distribute any permitted named or derived named [blob](#blobs)
with the given content.

### cat ###
    cat BLOB...

The device may exec this command in the `established` state for the server to
acknowledge with the contents (without header) of the named or referenced
blobs.

### clone ###
    clone [URL|MIRROR][@EPOCH]

A administrator may exec this command in the `established` state to replicate
or update an ASN repository. With the URL or MIRROR argument the administrator
is requesting a remote server to clone from another; otherwise, it is updating
a local repos. The executing server sends all or dated objects before its
acknowledgment.

### echo ###
    echo [STRING]...

The device may exec this command in `open`, `provisional` or `established`
states.  The data of the server's positive acknowledgment has the joined,
space separated list of arguments suffixed by a trailing newline.

### fetch ###
    fetch BLOB...

An administrator or mirror may exec this command in the `established` state
for the server to send all matching objects before its acknowledgment.

This requests everything since EPOCH for the LOGIN user.

    fetch @EPOCH

This requests messages to the USER since EPOCH.

    fetch USER/asn/messages@EPOCH

This requests the blob containing USER's ASN authentication key.

    fetch USER/asn/auth

This requests blobs with the given SHA sums.

    fetch SUM...

### gc ###
    gc [@EPOCH]

An administrator may exec this command in the `established` state for the
server to purge older or all blobs flagged for deletion.

### ls ###
    ls BLOB...

The device may exec this command in the `established` state for the server to
acknowledge with a newline separated list of matching link names.

    ls asn

    auth
    author
    user

The device requests the list of messages since a given epoch like this.

    ls asn/messages@1412294821523593019

    1ed9d26bba5632460bd1a492a6419abb
    60b195f9a2b15f175a49e63d4647755e

Or list blobs named with a given prefix that are newer than epoch.

    ls asn@1412294821523593019

    asn/auth

### mark ###
    mark [-u USER] <LATITUDE LONGITUDE>
    mark [-u USER] <7?PLACE>

The device may exec this command in the `established` state for the server to
create, process and distribute a [Mark](#mark) blob with LOGIN as the default
USER.

The alternate form is the UTF-8 `7` character followed by an App significant
hexadecimal character then the key associated with an event or place. Use this
form to set LOGIN's location relative to the PLACE or EVENT. App's may use the
intermediate character to encode an ETA.

Permitted sessions may exec this command to mark location of events and places
with the USER argument.  The device may also make an anonymous mark using the
session ephemeral key as USER.

### newuser ###
    newuser <"actual"|"bridge"|"forum"|"place">

The device may exec this command in the `established` state to create an
actual, bridge or forum user with random keys. The acknowledgment has a string
like this:

    pub:
      encr: 5fb2d5d9552c47f02d4cfc1f3938abd4c5f685b050501e53f6bf545c05982e33
      auth: 9d30799789fb96a2d71855168d8573d2ce6f367e6a0ef7da7bcee72ab31dcc13
    sec:
      encr: f6ce8a1025b3537e3a82ab5461fa7a2db51a2729abe66cdce82b54a573de011d
      auth: 60eabf950dc926735d086f419b2571de6e95c4e1d1efe179590b1acc8ffee39c9d30799789fb96a2d71855168d8573d2ce6f367e6a0ef7da7bcee72ab31dcc13

Before acknowledgment the server creates blobs named:

    asn/author
    asn/auth
    asn/user

It's up to the App to securely store and distribute the secrete encryption and
authentication keys.

### objdump ###
    objdump BLOB...

The device may exec this command in the `established` state for the server to
acknowledge with a decoded header of the matching blob.

### rm ###
    rm BLOB...

The device may exec this command in the `established` state for the server to
create, process and distribute a [Removal](#removal) blob.  While processing,
the server doesn't immediately remove these objects; instead, it merely flags
these for later, independent purge by the garbage collector of each mirror.
The removal flags may be reverted by removing the generated removal object
(`asn/removals/SUM`) before garbage collection.

### trace ###
    trace [COMMAND [ARG]]

The device may exec this command in the `established` state to retrieve or
adjust the server's PDU trace. The default, "flush" command results in the
text PDU trace returned in the data component of the positive acknowledgment.
The other trace commands return success or error.

    trace [flush]
    trace filter ID...
    trace unfilter ID...
    trace resize RINGSIZE

The default RINGSIZE is 32.

### vouch ###
    vouch USER SIG

The device may exec this command in the `established` state for the server to
create, process, and distribute an [Authentication](#authentication) blob with
a binary decode of the UTF-8 hexadecimal SIG argument string that is LOGIN's
ED25519 signature of USER's binary key.

## Blobs ##
ASN has one type of object, a blob.  Whereas requests result in some sort of
acknowledged action, a blob conveys unacknowledged information.  The content
of blobs, with the exception of [ASN Control](#asn-control), are opaque to the
server.  These may be fetched and read by anyone so the App is generally
responsible for security, compression, content identification and
interpretation. Once written, blobs may not be modified other than being
flagged for later removal during garbage collection.

    blob = version id magic random owner author epoch namelen name content
    version = uint8{ 0 }
    id = uint8{ BlobId }
    magic = [8]uint8{"asnmagic"}
    random = [32]uint8	// random data
    owner = [32]uint8	// public encryption key
    author = [32]uint8	// "
    epoch = uint64	// Unix epoch (nanoseconds)
    namelen = uint8
    name = []uint8
    content = []uint8

Random data is used to differentiate objects with identical content.

## ASN Control ##
These are the reserved ASN blob names and sections that describe how they
control service.

[New User](#new-user): `asn/auth`, `asn/author`, `asn/user`
[Permission](#permission): `asn/editors`, `asn/moderators`, `asn/subscribers`
[Mark](#mark): `asn/mark`
[Message](#message): `asn/messages/`
[Removal](#removal): `asn/removals/`
[Authentication](#authentication): `asn/references/`, `asn/vouchers/`

### New User ###
With a `provisional` login, or `newuser` request the service creates,
processes, and distributes blobs named `asn/author` and `asn/user`. The former
has the requesting user's binary public key as CONTENT and the later has
"actual", "forum" or "bridge" to record the type of user.  While in the
`provisional` state the device must exec the `auth` command for the server to
create, process and distribute a blob named `asn/auth` with login's 32-byte
public authentication key as CONTENT.

### Permission ###
The server consults blobs named `asn/editors`, `asn/moderators`, and
`asn/subscribers` to determine those permitted to change, approve, and receive
forum or bridge content.

The `asn/author` may assign one or more editors by adding user keys to a blob
named `asn/editors`.

All LOGIN users are permitted to make empty named blobs for another owner.
Unless moderated, these are linked as OWNER/asn/messages and distributed to
any OWNER or `asn/subscribers` sessions.

Only the owner, `asn/author` and `asn/editors` are permitted to make
non-empty named blobs.

The `asn/author` and `asn/editors` may assign one or more (including
themselves) as forum and bridge moderators by adding their keys to the blob
named `asn/moderators`.  Forum or bridge messages are added to the moderators'
message list. Any moderator may then exec the `approve` command for the server
to create, process and distribute an `asn/approvals/SUM` blob that results in
the listed blobs being linked to the forums message list and sent to any
subscriber sessions.

To summarize, a device is permitted to add a blob to an ASN repository, either
by direct send or `exec blob`, if:

    LOGIN == ADMIN ||
    LOGIN == SERVICE ||
    OWNER == LOGIN ||
    ASN_AUTHOR == LOGIN ||
    ASN_EDITORS{AUTHOR} ||
    NAME == ""

A session receives newly added blobs if:

    LOGIN == SERVICE ||
    OWNER == LOGIN ||
    (NAME == "" && (ASN_SUBSCRIBERS{LOGIN} || ASN_MODERATORS{LOGIN})) ||
    (NAME == "asn/mark" && (!ASN_SUBSCRIBERS || ASN_SUBSCRIBERS{LOGIN}))
    
### Message ###
A `message` is an empty named blob (e.g. `namelen` == 0) and App specific
CONTENT.  The server makes these links to message blobs.

    OWNER/asn/messages/SUM
    AUTHOR/asn/messages/SUM

### Authentication ###
The LOGIN user may contribute to the ASN web-of-trust by vouching for or
denying another user identity with blobs named `asn/vouchers/` where OWNER and
AUTHOR are LOGIN and CONTENT is LOGIN's 64-byte, ED25519 authenticated
signature of the subject's key. To revoke or deny a subject identity,  CONTENT
is 64-bytes of random or nil data.  The server makes these links to the
vouching blob.

    USER:asn/references/LOGIN
    LOGIN:asn/vouchers/USER

### Mark ###
A location mark is a blob named `asn/mark` with this CONTENT.

    mark = user <flag eta place> | <lat lon>

    user = [8]uint8	// first 8 bytes of USER

    flag = uint4{7}	// high nibble of first byte
    eta = uint4		// low nibble of first byte
    place = [7]uint8	// first 7 bytes of USER, PLACE, or EVENT key

    lat = int32		// latitude (degree millionths)
    lon = float64	// longitude (")

To check-in or note that it is in transit to an event the device exec's the
mark command for the server to create, process and distribute the first form
of this blob that has the first 7 bytes of the event/forum key as `place` and
non-zero `eta` if in transit.  The service distributes these blobs to all
permitted sessions. Also, a newly established session may retrieve earlier
marks with this exec command.

    cat SERVICE/asn/mark[@EPOCH]

The service notes that a session has terminated or suspended by distributing a
mark blob with the associated user key (login or ephemeral) as `place` and a
zero `eta`.  The device may also exec the mark command with it's own `place`
key to stop it's location report.

### Removal ###
A `removal` is a blob named `asn/removals/` containing a list of 64-byte
binary sums referencing blobs flagged for deletion. The server deletes all
links associated with the referenced blobs before flagging these for later
purge by its garbage collector. It also distributes the `removal` to all
mirrors that repeat the process. Finally, it makes this link.

    LOGIN:asn/removals/SUM

Removals may be reverted by removing the associated removal blob before the
garbage collector has purged the referenced blobs.

### Other Derived Names ###
Any other blob named with a trailing forward slash ("/") is linked as this.

    <USER|LOGIN>/NAME[/]SUM

## Repos ##
ASN servers and administrators have and distribute blob repositories stored in
files named by the split level, 128 UTF-8 character, hexadecimal encoding of
the 64-byte SHA-512 sum.

    FILE = SUM[:2]/SUM[2:128]

### Links ###
These server repositories also have links to the blobs in directories named by
the split level, 64 UTF-8 character, hexadecimal encoding of the object
owner's 32 byte public encryption key.

    LINK = OWNER[:2]/OWNER[2:]/NAME

Empty name objects are messages with links named by the blob's abbreviated,
hexadecimal SHA sum.

    NAME = ""
    LINK = OWNER[:2]/OWNER[2:]/asn/messages/SUM[:64]

Similarly, any blob named with a trailing forward slash ("/") is linked with
its sum.

    NAME = "whatever/"
    OWNER[:2]/OWNER[2:64]/whatever/SUM[:64]

## Server Affinity ##
Before login, the App consults a proprietary table to connect with the server
(or alternate) assigned to its the current location.  Each service (siren,
coven, cutesy, etc.) have N location servers (e.g.  San Francisco, Los
Angeles, NY, London, Paris, etc.) plus at least one back-end/back-up server
designated by having Latitude <-180 or >180.  It may also have zero or more
bridge servers identified by having Latitude <-90 or >90. For example,

	// Geo from: http://www.distancesfrom.com
	[]struct{ Host string, Latitude, Longitude float64}{
		{ "sf.siren.apptimist.co", 37.774929, -122.419415 },
		{ "la.siren.apptimist.co", 34.052234, -118.243684 },
		{ "nyc.siren.apptimist.co", 40.714352, -74.0059731 },
		{ "london.siren.apptimist.co", 51.508128, -0.128005 },
		{ "paris.siren.apptimist.co", 48.856614,  2.352221 },
		{ "bridge1.siren.apptimist.co", 91,  0 },
		{ "bridge2.siren.apptimist.co", 92,  0 },
		{ "siren.apptimist.co", 181,  0 },
		{ "aws.siren.apptimist.co", 182,  0 },
	}

After login to its nearest server, the App may retrieve objects of any user.
It may also retrieve messages of the logged-in user and any of their
subscribed forums. However, to send and receive bridge messages the App must
establish another session with the assigned server. Similarly, the App must
establish sessions to the assigned server to receive marks of users in another
area.

## References ##
<a name="1">1. [RFC-6455](http://tools.ietf.org/html/rfc6455)</a>
<a name="2">2. [ED25519 authenticated signatures](http://ed25519.cr.yp.to/)</a>
<a name="3">3. [NaCL authenticated encryption](http://nacl.cr.yp.to/box.html)</a>
<a name="4">3. [NaCL "Security Model"](http://nacl.cr.yp.to/box.html)</a>

***
&copy; 2014 Apptimist, Inc. All rights reserved.
