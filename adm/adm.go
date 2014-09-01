// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package adm provides a command line ASN administrator.

Usage: asnadm CONFIG [SERVER] [COMMAND [ARGUMENTS...]]

Exmples:

	$ asnadm siren 0 echo hello world
	$ asnadm siren sf echo hello world
	$ asnadm siren 1 echo hello world
	$ asnadm siren la echo hello world

Or if the config file has a single server,

	$ asnadm siren echo hello world

See github.com/apptimistco/asn/adm/config for CONFIG.
*/
package adm

import (
	"code.google.com/p/go.net/websocket"
	"errors"
	"github.com/apptimistco/asn"
	"github.com/apptimistco/asn/adm/config"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/asn/pdu/ack"
	"github.com/apptimistco/asn/pdu/exec"
	"github.com/apptimistco/asn/pdu/session"
	"github.com/apptimistco/box"
	"github.com/apptimistco/datum"
	"github.com/apptimistco/url"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
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
	if help(args...) {
		return
	}
	if n := len(args); n < 2 {
		return ErrUsage
	}
	cfg, err := config.New(args[1])
	if err != nil {
		return
	}
	args = args[2:]
	si := 0
	if len(cfg.Server) > 1 {
		if len(args) == 0 {
			return ErrNoServer
		} else if si = serverIdx(cfg, args[0]); si < 0 {
			return ErrNoSuchServer
		} else {
			args = args[1:]
		}
	}
	pdu.TraceUnfilter(pdu.NpduIds)
	pdu.TraceFilter(pdu.RawId)
	conn, err := dial(cfg.Server[si].Url, cfg.Keys.Admin.Pub.Encr.String())
	for t := 100 * time.Millisecond; err != nil; t *= 2 {
		time.Sleep(t)
		conn, err = dial(cfg.Server[si].Url,
			cfg.Keys.Admin.Pub.Encr.String())
		if t > 2*time.Second {
			return
		}
	}
	adm := &admin{
		config: cfg,
		asn:    asn.Pull(),
	}
	defer func() {
		asn.Push(&adm.asn)
		datum.Flush()
		if err != nil {
			pdu.TraceFlush(Stderr)
		}
	}()
	adm.asn.Name = cfg.Name + "[" + cfg.Server[si].Name + "]"
	adm.asn.SetBox(box.New(2, cfg.Keys.Nonce, cfg.Keys.Server.Pub.Encr,
		cfg.Keys.Admin.Pub.Encr, cfg.Keys.Admin.Sec.Encr))
	adm.asn.SetConn(conn)
	if err = adm.login(); err != nil {
		return err
	}
	err = adm.exec(args...)
	if qerr := adm.quit(); err == nil && qerr != nil {
		err = qerr
	}
	if err == io.EOF {
		err = nil
	}
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

type admin struct {
	config *config.Config
	asn    *asn.ASN
}

func dial(durl *url.URL, key string) (net.Conn, error) {
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
		turl := durl.String() + "?key=" + key
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

func (adm *admin) exec(args ...string) error {
	err := adm.asn.Tx(exec.NewExec(args...), nil)
	if err != nil {
		return err
	}
	d, err := adm.rxack()
	defer datum.Push(&d)
	if d != nil {
		d.WriteTo(Stdout)
		Stdout.Write([]byte{'\n'})
	}
	return err
}

func (adm *admin) login() (err error) {
	k := adm.config.Keys.Admin.Pub.Encr
	sig := adm.config.Keys.Admin.Sec.Auth.Sign(k[:])
	err = adm.asn.Tx(session.NewLoginReq(k, sig), nil)
	if err != nil {
		return
	}
	d, err := adm.rxack()
	datum.Push(&d)
	return err
}

func (adm *admin) quit() error {
	err := adm.asn.Tx(session.NewQuitReq(), nil)
	if err != nil {
		return err
	}
	d, err := adm.rxack()
	datum.Push(&d)
	return err
}

func (adm *admin) rxack() (*datum.Datum, error) {
	vpdu, d, err := adm.asn.Rx()
	if err != nil {
		return d, err
	}
	if vpdu.Id() != pdu.AckId {
		return d, pdu.ErrUnexpected
	}
	xack, ok := vpdu.(*ack.Ack)
	if !ok {
		return d, pdu.ErrParse
	}
	if xack.Err != pdu.Success {
		if uint(xack.Err) < pdu.Nerrors {
			err = pdu.Errors[xack.Err]
		} else {
			err = pdu.Errors[pdu.DeniedErr]
		}
	}
	return d, err
}
