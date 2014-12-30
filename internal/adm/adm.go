// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package adm provides a command line ASN administrator.
It's methods are also used for progromatic ASN testing.

Usage: asnadm [-nologin] CONFIG[:SERVER] [- | COMMAND [ARGUMENTS...]]

Exmples:

	$ asnadm siren.yaml echo hello world
	$ asnadm siren.yaml:1 echo hello world
	$ asnadm siren.yaml:sf echo hello world
	$ asnadm siren.yaml:sf - <<EOF
	echo hello world
	EOF
	$ asnadm siren.yaml:sf	# gnu-readline CLI

For CONFIG format, see:
	$ godoc github.com/apptimistco/asn/internal/asn Config
*/
package adm

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/apptimistco/asn/internal/asn"
	"golang.org/x/net/websocket"
)

const (
	Usage = "Usage: asnadm [-nologin] CONFIG[:SERVER] [COMMAND [ARGS...]]"
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
	nologin := false
	err = ErrUsage
	if help(args...) {
		return
	}
	if len(args) < 2 {
		return
	}
	args = args[1:] // strip progam name
	if args[0] == "-nologin" || args[0] == "--nologin" {
		nologin = true
		args = args[1:]
	}
	config := args[0]
	args = args[1:]
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
	if nologin == false {
		err = adm.Login()
	}
	if err == nil {
		if len(args) > 0 {
			if args[0] == "-" {
				err = adm.script(Stdin)
			} else {
				err = adm.Exec(args...)
			}
		} else {
			err = adm.cli()
		}
		if err == io.EOF {
			err = nil
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
		adm.asn.Diag(asn.BlobId, name)
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

// command process given line as space separated args
func (adm *Adm) cmdLine(line string) error {
	args := strings.Split(line, " ")
	if len(args) == 0 || args[0] == "" {
		return nil
	}
	switch args[0] {
	case "quit":
		return io.EOF
	case "auth-blob":
		return adm.AuthBlob()
	case "login":
		return adm.Login()
	case "pause":
		return adm.Pause()
	case "resume":
		return adm.Resume()
	default:
		if err := adm.Exec(args...); err != nil {
			fmt.Println(err)
		}
	}
	return nil
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
		asn.Diag.Println(adm.config.Name, "dialing",
			adm.config.Server[si].Url, "...")
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
	asn.Diag.Println(adm.config.Name, "connected to",
		adm.config.Server[si].Url)
	adm.ephemeral.pub, adm.ephemeral.sec, _ = asn.NewRandomEncrKeys()
	conn.Write(adm.ephemeral.pub[:])
	adm.asn = asn.NewASN()
	if adm.asn.Repos, err = asn.NewRepos(adm.config.Dir); err != nil {
		return
	}
	adm.asn.Name.Local = adm.config.Name
	adm.asn.Name.Remote = adm.config.Server[si].Name
	adm.asn.Name.Session = adm.asn.Name.Local + ":" + adm.asn.Name.Remote
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
		adm.asn.Diag("NewBlob", err)
		return
	}
	sum, fn, err := adm.asn.Repos.File(blob, pdu)
	if err != nil {
		adm.asn.Diag("File", err)
	}
	links, err := adm.asn.Repos.MkLinks(blob, sum, fn)
	for i := range links {
		if links[i] != nil {
			adm.asn.Diag("saved", links[i].FN)
			links[i].Free()
			links[i] = nil
		}
	}
	links = nil
	blob.Free()
	pdu.Free()
}

// handler processes pdu RxQ until EOF or kill signal
func (adm *Adm) handler() {
	var (
		err error
		pdu *asn.PDU
		v   asn.Version
		id  asn.Id
	)
	defer func() {
		adm.asn.Diag("handler", err)
		adm.doneCh <- err
	}()
	adm.asn.Diag("handler...")
	for err == nil {
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
		adm.asn.Diagf("handle %p\n", pdu)
		if err = pdu.Open(); err != nil {
			return
		}
		v.ReadFrom(pdu)
		if v < adm.asn.Version() {
			adm.asn.SetVersion(v)
		}
		id.ReadFrom(pdu)
		id.Internal(v)
		adm.asn.Diag("handle", id)
		switch id {
		case asn.AckReqId:
			err = adm.asn.Acker.Rx(pdu)
		case asn.BlobId:
			adm.File(pdu)
		default:
			adm.asn.Diag(id)
			err = asn.ErrUnsupported
		}
		pdu.Free()
	}
}

func (adm *Adm) IsAdmin(key *asn.EncrPub) bool {
	return *key == *adm.config.Keys.Admin.Pub.Encr
}

func (adm *Adm) IsService(key *asn.EncrPub) bool {
	return *key == *adm.config.Keys.Server.Pub.Encr
}

func (adm *Adm) script(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if err := adm.cmdLine(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}
