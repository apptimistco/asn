// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package adm provides a command line ASN administrator.
It's methods are also used for progromatic ASN testing.

Usage: asnadm CONFIG[:SERVER] [COMMAND [ARGUMENTS...]]

Exmples:

	$ asnadm siren.yaml echo hello world
	$ asnadm siren.yaml:1 echo hello world
	$ asnadm siren.yaml:sf echo hello world

For CONFIG format, see:
	$ godoc github.com/apptimistco/asn/internal/asn Config
*/
package adm

import (
	"errors"
	"github.com/apptimistco/asn/internal/asn"
	"golang.org/x/net/websocket"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	Usage = "Usage: asnadm CONFIG[:SERVER] [COMMAND [ARGUMENTS...]]"
)

var (
	ErrUsage        = errors.New(Usage)
	ErrNoSuchServer = errors.New("no such server")
	ErrScheme       = errors.New("unsupported URL scheme")

	Stdin  io.Reader = os.Stdin
	Stdout io.Writer = os.Stdout
	Stderr io.Writer = os.Stderr
)

func Main(args ...string) (err error) {
	var adm Adm
	if help(args...) {
		return
	}
	if err = ErrUsage; len(args) < 1 {
		return
	}
	config := args[1]
	args = args[2:]
	server := ""
	colon := strings.Index(config, ":")
	if colon > 0 {
		config = config[:colon]
		server = config[colon+1:]
	}
	if err = adm.Config(config); err != nil {
		return
	}
	si := 0
	if len(adm.config.Server) > 1 {
		if si = serverIdx(adm.config, server); si < 0 {
			return ErrNoSuchServer
		}
	}
	if err = adm.Connect(si); err != nil {
		return
	}
	go adm.handler()
	if err = adm.Login(); err == nil {
		if len(args) > 0 {
			err = adm.Exec(args...)
		} else {
			err = adm.cli()
		}
		if qerr := adm.Quit(); err == nil && qerr != nil {
			err = qerr
		}
		adm.sigCh <- syscall.SIGTERM
	}
	if err == nil {
		err = <-adm.doneCh
	} else {
		<-adm.doneCh
	}
	asn.Diag.Println("done")
	adm.Close()
	if err == io.EOF {
		err = nil
	}
	asn.FlushPDU()
	return
}

func help(args ...string) bool {
	if len(args) > 1 &&
		(args[1] == "help" ||
			args[1] == "-help" ||
			args[1] == "--help" ||
			args[1] == "-h") {
		io.WriteString(Stdout, Usage)
		io.WriteString(Stdout, "\n")
		return true
	}
	return false
}

func serverIdx(c *asn.Config, s string) int {
	i, err := strconv.Atoi(s)
	if err == nil {
		if i < 0 || i >= len(c.Server) {
			return -1
		}
		return i
	}
	for i, se := range c.Server {
		if strings.HasPrefix(se.Name, s) {
			return i
		}
	}
	return -1
}

type Adm struct {
	config    *asn.Config
	asn       *asn.ASN
	ephemeral struct {
		pub *asn.EncrPub
		sec *asn.EncrSec
	}
	doneCh chan error
	sigCh  chan os.Signal
}

func (adm *Adm) AuthBlob() error {
	return adm.Blob("asn/auth", (*adm.config.Keys.Admin.Pub.Auth)[:])
}

func (adm *Adm) Blob(name string, v interface{}) (err error) {
	blob := asn.NewBlob(adm.config.Keys.Admin.Pub.Encr,
		adm.config.Keys.Admin.Pub.Encr, name)
	defer blob.Free()
	f, err := adm.asn.Repos.Tmp.NewFile()
	if err != nil {
		return
	}
	if _, _, err = blob.SummingWriteContentsTo(f, v); err == nil {
		adm.asn.Tx(asn.NewPDUFile(f))
		asn.Diag.Println(adm.asn.Name, asn.BlobId, name)
	}
	f = nil
	return
}

func (adm *Adm) Close() {
	if adm.asn != nil {
		adm.asn.SetStateClosed()
		if adm.asn.Conn != nil {
			t := time.NewTimer(2 * time.Second)
		flushLoop:
			for {
				select {
				case pdu := <-adm.asn.RxQ:
					if pdu == nil {
						t.Stop()
						break flushLoop
					} else {
						pdu.Free()
					}
				case <-t.C:
					break flushLoop
				}
			}
			adm.asn.Conn().Close()
			adm.asn.Repos.Free()
			adm.asn.Repos = nil
			adm.asn.Free()
			adm.asn = nil
			asn.FlushASN()
		}
	}
}

// Config[ure] the Adm from the named file or inline.
func (adm *Adm) Config(s string) (err error) {
	adm.config, err = asn.NewConfig(s)
	if os.IsNotExist(err) {
		adm.config, err = asn.NewConfig(s + ".yaml")
	}
	return
}

// Connect to the si'th server listed in the configuration.
func (adm *Adm) Connect(si int) (err error) {
	var conn net.Conn
	if si >= len(adm.config.Server) {
		return ErrNoSuchServer
	}
	for t := 100 * time.Millisecond; true; t *= 2 {
		asn.Diag.Println("dialing", adm.config.Server[si].Url, "...")
		conn, err = adm.dial(adm.config.Server[si].Url)
		if conn != nil && err == nil {
			break
		}
		if t > 3*time.Second {
			return
		}
		time.Sleep(t)
	}
	if err != nil {
		return
	}
	asn.Diag.Println("connected", adm.config.Server[si].Url)
	adm.ephemeral.pub, adm.ephemeral.sec, _ = asn.NewRandomEncrKeys()
	conn.Write(adm.ephemeral.pub[:])
	adm.asn = asn.NewASN()
	if adm.asn.Repos, err = asn.NewRepos(adm.config.Dir); err != nil {
		return
	}
	adm.asn.Name = adm.config.Name + "[" + adm.config.Server[si].Name + "]"
	adm.asn.SetBox(asn.NewBox(2,
		adm.config.Keys.Nonce,
		adm.config.Keys.Server.Pub.Encr,
		adm.ephemeral.pub,
		adm.ephemeral.sec))
	adm.asn.SetConn(conn)
	adm.doneCh = make(chan error, 1)
	adm.sigCh = make(chan os.Signal, 1)
	signal.Notify(adm.sigCh, syscall.SIGINT, syscall.SIGTERM)
	return
}

func (adm *Adm) dial(durl *asn.URL) (net.Conn, error) {
	switch scheme := durl.Scheme; scheme {
	case "tcp":
		addr, err := net.ResolveTCPAddr(scheme, durl.Host)
		if err != nil {
			return nil, err
		}
		return net.DialTCP(scheme, nil, addr)
	case "unix":
		path := asn.UrlPathSearch(durl.Path)
		addr, err := net.ResolveUnixAddr(scheme, path)
		if err != nil {
			return nil, err
		}
		return net.DialUnix(scheme, nil, addr)
	case "ws":
		turl := durl.String()
		nc, err := net.Dial("tcp", durl.Host)
		if err != nil {
			return nil, err
		}
		origin := "http://localhost" // FIXME
		wscfg, err := websocket.NewConfig(turl, origin)
		if err != nil {
			nc.Close()
			return nil, err
		}
		return websocket.NewClient(wscfg, nc)
	default:
		return nil, ErrScheme
	}
}

func (adm *Adm) DN() string {
	return adm.config.Dir
}

func (adm *Adm) File(pdu *asn.PDU) {
	blob, err := asn.NewBlobFrom(pdu)
	if err != nil {
		asn.Diag.Println(adm.asn.Name, "Error:", err)
		return
	}
	sum, fn, err := adm.asn.Repos.File(blob, pdu)
	if err != nil {
		asn.Diag.Println(adm.asn.Name, err)
	}
	links, err := adm.asn.Repos.MkLinks(blob, sum, fn)
	for i := range links {
		if links[i] != nil {
			asn.Diag.Println(adm.asn.Name, "saved", links[i].FN)
			links[i].Free()
			links[i] = nil
		}
	}
	links = nil
	blob.Free()
	pdu.Free()
}

func (adm *Adm) handler() {
	var (
		err error
		pdu *asn.PDU
		v   asn.Version
		id  asn.Id
	)
	defer func() {
		adm.doneCh <- err
	}()
	for err == nil {
		for pdu == nil {
			select {
			case pdu = <-adm.asn.RxQ:
				if pdu == nil {
					err = io.EOF
					return
				}
			case <-adm.sigCh:
				adm.asn.SetStateClosed()
				err = io.EOF
				return
			}
		}
		if err = pdu.Open(); err != nil {
			return
		}
		v.ReadFrom(pdu)
		if v < adm.asn.Version() {
			adm.asn.SetVersion(v)
		}
		id.ReadFrom(pdu)
		id.Internal(v)
		asn.Diag.Println("handle", id)
		switch id {
		case asn.AckReqId:
			err = adm.asn.Acker.Rx(pdu)
		case asn.BlobId:
			adm.File(pdu)
		default:
			asn.Diag.Println(adm.asn.Name, id)
			err = asn.ErrUnsupported
		}
		pdu.Free()
		pdu = nil
	}
}

func (adm *Adm) IsAdmin(key *asn.EncrPub) bool {
	return *key == *adm.config.Keys.Admin.Pub.Encr
}

func (adm *Adm) IsService(key *asn.EncrPub) bool {
	return *key == *adm.config.Keys.Server.Pub.Encr
}
