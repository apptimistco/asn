// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// asn_test's:
//	Box	Seal/Open
//	.*Echo	Echo with Pipe and Unix, TCP, and Web Sockets
package asn_test

import (
	"bytes"
	"code.google.com/p/go.net/websocket"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/apptimistco/asn"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/asn/pdu/echo"
	"github.com/apptimistco/asn/pdu/session"
	"github.com/apptimistco/auth"
	"github.com/apptimistco/box"
	"github.com/apptimistco/datum"
	"github.com/apptimistco/encr"
	"github.com/apptimistco/nbo"
	"github.com/apptimistco/pipe"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var (
	out = os.Stdout

	appPub, srvPub *encr.Pub
	appSec, srvSec *encr.Sec

	nonce *box.Nonce

	bsample []byte

	ErrMismatch = errors.New("Mismatch")
)

func init() {
	var err error
	defer func() {
		if err != nil {
			os.Stderr.Write([]byte("Error: "))
			os.Stderr.Write([]byte(err.Error()))
		}
	}()
	appPub, appSec, err = encr.NewRandomKeys()
	if err != nil {
		return
	}
	srvPub, srvSec, err = encr.NewRandomKeys()
	if err != nil {
		return
	}
	_, secAuth, err := auth.NewRandomKeys()
	if err != nil {
		return
	}
	nonce, _ = box.Noncer(secAuth.Sign(srvPub[:]))
	bsample, _ = hex.DecodeString("0123456789abcdef")
	asn.Diag = out
}

func N() int {
	n := 10 << 10
	if testing.Short() {
		n = 16
	}
	return n
}

func TestBox(t *testing.T) {
	var err error
	defer func() {
		if err != nil && err != io.EOF {
			t.Error(err)
		}
	}()

	appBox := newAppBox()
	srvBox := newSrvBox()
	sample := []byte("the quick brown fox")
	red, err := appBox.Seal(nil, sample)
	if err != nil {
		return
	}
	black, err := srvBox.Open(nil, red)
	if err != nil {
		return
	}
	if !bytes.Equal(black, sample) {
		err = ErrMismatch
	}
}

type APPer interface {
	Handler(conn net.Conn)
	Return(error)
	Wait() error
}

type SRVer interface {
	Handler(conn net.Conn)
	Return(error)
	Wait() error
}

type echoApp struct {
	asn  *asn.ASN
	done chan error
	i, n int
}

func (app *echoApp) Handler(conn net.Conn) {
	defer conn.Close()
	app.asn.SetBox(newAppBox())
	app.asn.SetConn(conn)
	zero := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	app.asn.Tx(echo.NewEcho(echo.Request), zero)
	app.Return(app.asn.UntilQuit())
}

func (app *echoApp) Return(err error) {
	app.done <- err
}

func (app *echoApp) echo(vpdu pdu.PDUer, rxdata *datum.Datum) (err error) {
	xecho, ok := vpdu.(*echo.Echo)
	if !ok {
		err = pdu.ErrParse
		return
	}
	var seq uint64
	if _, err = (nbo.Reader{rxdata}).ReadNBO(&seq); err != nil {
		return
	}
	if seq != uint64(app.i) {
		app.asn.Tx(session.NewQuitReq(), nil)
		return ErrMismatch
	} else if seq == uint64(app.n) {
		app.asn.Tx(session.NewQuitReq(), nil)
	} else {
		app.i += 1
		ibuf := []byte{0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(ibuf, uint64(app.i))
		xecho.Reply = echo.Request
		app.asn.Tx(xecho, ibuf)
	}
	return nil
}

func (app *echoApp) Wait() error { return <-app.done }

type echoSrv struct {
	asn  *asn.ASN
	done chan error
}

func (srv *echoSrv) Handler(conn net.Conn) {
	defer conn.Close()
	if ws, ok := conn.(*websocket.Conn); ok {
		q := ws.Config().Location.RawQuery
		qkey := "key="
		if !strings.HasPrefix(q, qkey) {
			srv.Return(pdu.ErrQuery)
			return
		}
		s := strings.TrimPrefix(q, qkey)
		peer, err := encr.NewPubString(s)
		if err != nil {
			srv.Return(err)
			return
		}
		srv.asn.SetBox(box.New(2, nonce, peer, srvPub, srvSec))
	} else {
		srv.asn.SetBox(box.New(2, nonce, appPub, srvPub, srvSec))
	}
	srv.asn.SetConn(conn)
	srv.Return(srv.asn.UntilQuit())
}

func (srv *echoSrv) Return(err error) {
	srv.done <- err
}

func (srv *echoSrv) Wait() error { return <-srv.done }

func egress(t *testing.T, err error) {
	if err != nil && err != io.EOF {
		t.Error(err)
		pdu.TraceFlush(out)
	} else if testing.Verbose() {
		pdu.TraceFlush(out)
	}
}

func TestPipeEcho(t *testing.T) {
	pdu.TraceUnfilter(pdu.EchoId)
	app := &echoApp{n: N(), done: make(chan error)}
	srv := &echoSrv{done: make(chan error)}
	app.asn = asn.New("PipeEchoApp")
	defer app.asn.Close()
	app.asn.Register(pdu.EchoId, app.echo)
	srv.asn = asn.New("PipeEchoSrv")
	defer srv.asn.Close()
	appConn, srvConn := pipe.New(4 << 10)
	go srv.Handler(srvConn)
	go app.Handler(appConn)
	egress(t, wait(app, srv))
}

func TestUnixEcho(t *testing.T) {
	pdu.TraceUnfilter(pdu.EchoId)
	pdu.TraceResize(64)
	app := &echoApp{n: N(), done: make(chan error)}
	srv := &echoSrv{done: make(chan error)}
	app.asn = asn.New("UnixEchoApp")
	defer app.asn.Close()
	app.asn.Register(pdu.EchoId, app.echo)
	srv.asn = asn.New("UnixEchoSrv")
	defer srv.asn.Close()
	egress(t, netTest(app, srv, "unix", "asn.sock"))
}

func TestTCPEcho(t *testing.T) {
	pdu.TraceUnfilter(pdu.EchoId)
	pdu.TraceResize(16)
	app := &echoApp{n: N(), done: make(chan error)}
	srv := &echoSrv{done: make(chan error)}
	app.asn = asn.New("TCPEchoApp")
	defer app.asn.Close()
	app.asn.Register(pdu.EchoId, app.echo)
	srv.asn = asn.New("TCPEchoSrv")
	defer srv.asn.Close()
	egress(t, netTest(app, srv, "tcp", "localhost:6060"))
}

func TestWebEcho(t *testing.T) {
	var err error
	defer func() { egress(t, err) }()

	pdu.TraceUnfilter(pdu.EchoId)
	pdu.TraceResize(32)
	path := "/ws/asn"
	app := &echoApp{n: N(), done: make(chan error)}
	srv := &echoSrv{done: make(chan error)}
	app.asn = asn.New("WebEchoApp")
	defer app.asn.Close()
	app.asn.Register(pdu.EchoId, app.echo)
	srv.asn = asn.New("WebEchoSrv")
	defer srv.asn.Close()
	http.Handle(path, websocket.Handler(func(ws *websocket.Conn) {
		srv.Handler(ws)
	}))
	server := httptest.NewServer(nil)
	defer server.Close()
	serverAddr := server.Listener.Addr().String()

	appConnTCP, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return
	}
	turl := fmt.Sprintf("ws://%s%s?key=%s", serverAddr, path, appPub.String())
	config, _ := websocket.NewConfig(turl, "http://localhost")
	appConn, err := websocket.NewClient(config, appConnTCP)
	if err != nil {
		return
	}
	go app.Handler(appConn)
	err = wait(app, srv)
}

func netTest(app APPer, srv SRVer, stream, addr string) error {
	rmSockFile := func() {}
	if stream == "unix" {
		rmSockFile = func() { os.Remove(addr) }
	}
	rmSockFile()
	ln, err := net.Listen(stream, addr)
	if err != nil {
		return err
	}
	defer func() {
		ln.Close()
		rmSockFile()
	}()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srv.Return(err)
			return
		}
		go srv.Handler(conn)
	}()
	appConn, err := net.Dial(stream, addr)
	if err != nil {
		return err
	}
	go app.Handler(appConn)
	return wait(app, srv)
}

func newAppBox() *box.Box {
	return box.New(asn.SizeUint16, nonce, srvPub, appPub, appSec)
}

func newSrvBox() *box.Box {
	return box.New(asn.SizeUint16, nonce, appPub, srvPub, srvSec)
}

func setup() {
}

func wait(app APPer, srv SRVer) error {
	for _, err := range []error{app.Wait(), srv.Wait()} {
		if err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}
