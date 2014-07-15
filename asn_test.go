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
	"github.com/apptimistco/asn/echo"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/asn/session"
	"github.com/apptimistco/auth"
	"github.com/apptimistco/box"
	"github.com/apptimistco/encr"
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

	zero, bsample []byte

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
	zero = make([]byte, asn.SizeUint64)
	bsample, _ = hex.DecodeString("0123456789abcdef")
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
	i, n uint64
}

func (app *echoApp) Handler(conn net.Conn) {
	defer conn.Close()
	app.asn.SetBox(newAppBox())
	app.asn.SetConn(conn)
	app.asn.Tx(echo.NewEcho(0), zero)
	err := app.asn.RxUntilErr()
	app.Return(err)
}

func (app *echoApp) Return(err error) {
	app.done <- err
}

func (app *echoApp) echo(vpdu pdu.PDUer, data []byte) error {
	xecho, ok := vpdu.(*echo.Echo)
	if !ok {
		return pdu.ErrParse
	}
	if seq := binary.BigEndian.Uint64(data); seq != app.i {
		app.asn.Tx(session.NewQuitReq(), []byte{})
		return ErrMismatch
	} else if seq == app.n {
		app.asn.Tx(session.NewQuitReq(), []byte{})
	} else {
		app.i += 1
		binary.BigEndian.PutUint64(data, app.i)
		xecho.Reply = echo.Request
		app.asn.Tx(xecho, data)
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
	err := srv.asn.RxUntilErr()
	srv.Return(err)
}

func (srv *echoSrv) Return(err error) {
	srv.done <- err
}

func (srv *echoSrv) Wait() error { return <-srv.done }

func TestPipeEcho(t *testing.T) {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.EchoId)

	var err error
	defer func() {
		if err != nil && err != io.EOF {
			t.Error(err)
		}
	}()

	app := &echoApp{n: iterations(), done: make(chan error)}
	srv := &echoSrv{done: make(chan error)}
	app.asn = asn.New("PipeEchoApp")
	app.asn.Register(pdu.EchoId, app.echo)
	srv.asn = asn.New("PipeEchoSrv")
	appConn, srvConn := pipe.New(4 << 10)
	go srv.Handler(srvConn)
	go app.Handler(appConn)
	err = wait(app, srv)
}

func TestUnixEcho(t *testing.T) {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.EchoId)
	pdu.TraceResize(64)

	var err error
	defer func() {
		if err != nil && err != io.EOF {
			t.Error(err)
		}
	}()

	app := &echoApp{n: iterations(), done: make(chan error)}
	srv := &echoSrv{done: make(chan error)}
	app.asn = asn.New("UnixEchoApp")
	app.asn.Register(pdu.EchoId, app.echo)
	srv.asn = asn.New("UnixEchoSrv")
	err = netTest(app, srv, "unix", "asn.sock")
}

func TestTCPEcho(t *testing.T) {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.EchoId)
	pdu.TraceResize(16)

	var err error
	defer func() {
		if err != nil && err != io.EOF {
			t.Error(err)
		}
	}()

	app := &echoApp{n: iterations(), done: make(chan error)}
	srv := &echoSrv{done: make(chan error)}
	app.asn = asn.New("TCPEchoApp")
	app.asn.Register(pdu.EchoId, app.echo)
	srv.asn = asn.New("TCPEchoSrv")
	err = netTest(app, srv, "tcp", "localhost:6060")
}

func TestWebEcho(t *testing.T) {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.EchoId)
	pdu.TraceResize(32)

	var err error
	defer func() {
		if err != nil && err != io.EOF {
			t.Error(err)
		}
	}()

	path := "/ws/asn"
	app := &echoApp{n: iterations(), done: make(chan error)}
	srv := &echoSrv{done: make(chan error)}
	app.asn = asn.New("WebEchoApp")
	app.asn.Register(pdu.EchoId, app.echo)
	srv.asn = asn.New("WebEchoSrv")
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

func iterations() uint64 {
	if testing.Short() {
		return uint64(16)
	}
	return uint64(16 << 10)
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
