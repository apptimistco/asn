// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package adm provides a command line ASN administrator.
It's methods are also used for progromatic ASN testing.

Usage: asnadm CONFIG [SERVER] [COMMAND [ARGUMENTS...]]

Exmples:

	$ asnadm siren 0 echo hello world
	$ asnadm siren 1 echo hello world
	$ asnadm siren sf echo hello world

Or if CONFIG has a single server,

	$ asnadm siren echo hello world

See github.com/apptimistco/asn/adm/config for CONFIG.
*/
package adm

import (
	"code.google.com/p/go.net/websocket"
	"errors"
	"fmt"
	"github.com/apptimistco/asn"
	"github.com/apptimistco/asn/adm/config"
	"github.com/apptimistco/box"
	"github.com/apptimistco/encr"
	"github.com/apptimistco/url"
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
	Usage  = "Usage: asnadm CONFIG [SERVER] [COMMAND [ARGUMENTS...]]"
	Inline = config.Inline
)

var (
	ErrUsage        = errors.New(Usage)
	ErrNoServer     = errors.New("need server argument")
	ErrNoSuchServer = errors.New("no such server")
	ErrScheme       = errors.New("unsupported URL scheme")

	Stdout io.Writer = os.Stdout
	Stderr io.Writer = os.Stderr
)

func Main(args ...string) (err error) {
	var adm Adm
	if help(args...) {
		return
	}
	if n := len(args); n < 2 {
		return ErrUsage
	}
	if err = adm.Config(args[1]); err != nil {
		return
	}
	args = args[2:]
	si := 0
	if len(adm.config.Server) > 1 {
		if len(args) == 0 {
			return ErrNoServer
		} else if si = serverIdx(adm.config, args[0]); si < 0 {
			return ErrNoSuchServer
		} else {
			args = args[1:]
		}
	}
	if err = adm.Connect(si); err != nil {
		return
	}
	if err = adm.Login(); err == nil {
		if len(args) > 0 {
			err = adm.Cmd(args...)
		} else {
			err = adm.Cli()
		}
		if qerr := adm.Quit(); err == nil && qerr != nil {
			err = qerr
		}
	}
	adm.Close()
	if err == io.EOF {
		err = nil
	}
	if err != nil {
		fmt.Fprintln(Stderr, "PDU trace...")
		asn.TraceFlush(Stderr)
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

func serverIdx(c *config.Config, s string) int {
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
	config    *config.Config
	asn       *asn.ASN
	ephemeral struct {
		pub *encr.Pub
		sec *encr.Sec
	}
	sigCh chan os.Signal
}

func (adm *Adm) Cli() error {
	return errors.New("FIXME CLI")
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
			adm.asn.Free()
			adm.asn = nil
			asn.FlushASN()
		}
	}
}

func (adm *Adm) Cmd(args ...string) error {
	switch args[0] {
	case "exec":
		return adm.Exec(args[1:]...)
	}
	return errors.New("unknown command")
}

// Config[ure] the Adm from the named file or inline.
func (adm *Adm) Config(s string) (err error) {
	adm.config, err = config.New(s)
	return
}

// Connect to the si'th server listed in the configuration.
func (adm *Adm) Connect(si int) (err error) {
	var conn net.Conn
	for t := 100 * time.Millisecond; true; t *= 2 {
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
	adm.ephemeral.pub, adm.ephemeral.sec, _ = encr.NewRandomKeys()
	conn.Write(adm.ephemeral.pub[:])
	adm.asn = asn.NewASN()
	adm.asn.Name = adm.config.Name + "[" + adm.config.Server[si].Name + "]"
	adm.asn.SetBox(box.New(2,
		adm.config.Keys.Nonce,
		adm.config.Keys.Server.Pub.Encr,
		adm.ephemeral.pub,
		adm.ephemeral.sec))
	adm.asn.SetConn(conn)
	adm.sigCh = make(chan os.Signal, 1)
	signal.Notify(adm.sigCh, syscall.SIGINT, syscall.SIGTERM)
	return
}

func (adm *Adm) dial(durl *url.URL) (net.Conn, error) {
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

func (adm *Adm) Exec(args ...string) (err error) {
	pdu := asn.NewPDU()
	v := adm.asn.Version()
	v.WriteTo(pdu)
	asn.ExecReqId.Version(v).WriteTo(pdu)
	asn.NewRequesterString("exec").WriteTo(pdu)
	pdu.Write([]byte(strings.Join(args, "\x00")))
	// FIXME append STDIN if last arg --
	adm.asn.Tx(pdu)
	asn.Trace(adm.asn.Name, "Tx", asn.ExecReqId, strings.Join(args, " "))
	pdu, err, _ = adm.UntilAck()
	if pdu != nil {
		pdu.WriteTo(Stdout)
		if len(args) > 0 && args[0] == "echo" {
			Stdout.Write([]byte{'\n'})
		}
		pdu.Free()
	}
	return
}

func (adm *Adm) Login() (err error) {
	pdu := asn.NewPDU()
	key := adm.config.Keys.Admin.Pub.Encr
	sig := adm.config.Keys.Admin.Sec.Auth.Sign(key[:])
	v := adm.asn.Version()
	v.WriteTo(pdu)
	asn.LoginReqId.Version(v).WriteTo(pdu)
	asn.NewRequesterString("login").WriteTo(pdu)
	pdu.Write(key[:])
	pdu.Write(sig[:])
	adm.asn.Tx(pdu)
	asn.Trace(adm.asn.Name, "Tx", asn.LoginReqId)
	pdu, err, _ = adm.UntilAck()
	adm.rekey(pdu)
	return
}

func (adm *Adm) Pause() (err error) {
	pdu := asn.NewPDU()
	v := adm.asn.Version()
	v.WriteTo(pdu)
	asn.PauseReqId.Version(v).WriteTo(pdu)
	asn.NewRequesterString("pause").WriteTo(pdu)
	adm.asn.Tx(pdu)
	asn.Trace(adm.asn.Name, "Tx", asn.PauseReqId)
	pdu, err, _ = adm.UntilAck()
	pdu.Free()
	adm.asn.SetStateSuspended()
	return
}

func (adm *Adm) rekey(pdu *asn.PDU) {
	var peer encr.Pub
	var nonce box.Nonce
	if pdu != nil {
		pdu.Read(peer[:])
		pdu.Read(nonce[:])
		pdu.Free()
		adm.asn.SetBox(box.New(2, &nonce, &peer,
			adm.ephemeral.pub, adm.ephemeral.sec))
		adm.asn.SetStateEstablished()
	}
}

func (adm *Adm) Resume() (err error) {
	pdu := asn.NewPDU()
	v := adm.asn.Version()
	v.WriteTo(pdu)
	asn.ResumeReqId.Version(v).WriteTo(pdu)
	asn.NewRequesterString("resume").WriteTo(pdu)
	adm.asn.Tx(pdu)
	asn.Trace(adm.asn.Name, "Tx", asn.ResumeReqId)
	pdu, err, _ = adm.UntilAck()
	adm.rekey(pdu)
	return
}

func (adm *Adm) Quit() (err error) {
	pdu := asn.NewPDU()
	v := adm.asn.Version()
	v.WriteTo(pdu)
	asn.QuitReqId.Version(v).WriteTo(pdu)
	asn.NewRequesterString("quit").WriteTo(pdu)
	adm.asn.Tx(pdu)
	asn.Trace(adm.asn.Name, "Tx", asn.QuitReqId)
	adm.asn.SetStateQuitting()
	pdu, err, _ = adm.UntilAck()
	pdu.Free()
	return err
}

func (adm *Adm) UntilAck() (pdu *asn.PDU, err error, req asn.Requester) {
	for {
		var v asn.Version
		var id asn.Id
	selectLoop:
		for {
			select {
			case pdu = <-adm.asn.RxQ:
				if pdu == nil {
					err = io.EOF
					return
				}
				break selectLoop
			case sig := <-adm.sigCh:
				fmt.Println("caught", sig)
				adm.asn.SetStateClosed()
			}
		}
		v.ReadFrom(pdu)
		if v < adm.asn.Version() {
			adm.asn.SetVersion(v)
		}
		id.ReadFrom(pdu)
		id.Internal(v)
		switch id {
		case asn.AckReqId:
			var e asn.Err
			req.ReadFrom(pdu)
			e.ReadFrom(pdu)
			e.Internal(adm.asn.Version())
			err = e.Error()
			return
		default:
			fmt.Println("fixme", adm.asn.Name, "Rx", id)
			pdu.Free()
		}

	}
}
