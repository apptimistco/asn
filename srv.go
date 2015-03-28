// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/mutex"
	"golang.org/x/net/websocket"
)

const (
	ldl = 100 * time.Millisecond
)

type nopCloserWriter struct {
	io.Writer
}

func (nopCloserWriter) Close() error { return nil }

// NopCloserWriter returns a WriteCloser with a no-op Close method wrapping
// the provided writer.
func NopCloserWriter(w io.Writer) io.WriteCloser {
	return nopCloserWriter{w}
}

type SrvListener struct {
	ln    Listener
	stop  chan struct{}
	done  chan error
	ws    bool
	clean string
}

type Server struct {
	mutex.Mutex
	cmd       *Command
	repos     Repos
	listeners []*SrvListener
	sessions  []*Ses

	listening struct {
		stop chan struct{}
		done chan struct{}
	}
}

func (cmd *Command) Server(args ...string) {
	srv := &Server{
		cmd:       cmd,
		listeners: make([]*SrvListener, 0),
		sessions:  make([]*Ses, 0),
	}
	err := cmd.Cfg.Check(ServerMode)
	defer func() { cmd.Done <- err }()
	if err != nil {
		runtime.Goexit()
	}
	srv.Mutex.Set(cmd.Cfg.Name)
	if err = srv.repos.Set(cmd.Cfg.Dir); err != nil {
		runtime.Goexit()
	}
	srv.repos.Set(cmd.Cfg.Keys)
	defer func() { srv.repos.Reset() }()
	for _, k := range []*UserKeys{
		srv.cmd.Cfg.Keys.Admin,
		srv.cmd.Cfg.Keys.Server,
	} {
		user := srv.repos.users.User(k.Pub.Encr)
		if user == nil {
			user, err = srv.repos.NewUser(k.Pub.Encr)
			if err != nil {
				runtime.Goexit()
			}
			user.cache.Auth().Set(k.Pub.Auth)
			user.cache.Author().Set(k.Pub.Encr)
		}
		user = nil
	}
	if len(args) > 0 {
		// local server command line exec
		var ses Ses
		// FIXME ses.asn.Init()
		// FIXME defer ses.Reset()
		ses.Set(srv)
		ses.Set(&srv.cmd.Cfg)
		ses.Set(&srv.repos)
		ses.Set(srv.ForEachLogin)
		admin := srv.cmd.Cfg.Keys.Admin.Pub.Encr
		ses.Keys.Client.Login = *admin
		ses.asnsrv = true
		ses.user = ses.asn.repos.users.User(admin)
		v := ses.Exec(NewReqString("exec"), cmd.Stdin, args...)
		err, _ = v.(error)
		AckOut(cmd.Stdout, v)
		v = nil
		runtime.Goexit()
	}
	if err = srv.Listen(); err != nil {
		runtime.Goexit()
	}
	cmd.Stdin.Close()
	cmd.Stdout.Close()
	cmd.Stdout = NopCloserWriter(ioutil.Discard)
	cmd.Stderr.Close()
	cmd.Stderr = NopCloserWriter(ioutil.Discard)
	for {
		sig := <-srv.cmd.Sig
		srv.Diag("caught", sig)
		switch {
		case IsINT(sig):
			debug.Trace.WriteTo(debug.Log)
			srv.Close()
			srv.Hangup()
			runtime.Goexit()
		case IsTERM(sig):
			srv.Close()
		case IsUSR1(sig):
			debug.Trace.WriteTo(debug.Log)
		}
	}
}

func (srv *Server) AddListener(l *SrvListener) {
	srv.Lock()
	defer srv.Unlock()
	for _, p := range srv.listeners {
		if p == nil {
			p = l
			return
		}
	}
	srv.listeners = append(srv.listeners, l)
}

func (srv *Server) Close() {
	for i, le := range srv.listeners {
		if le.ws {
			le.ln.Close()
		} else {
			le.stop <- struct{}{}
			<-le.done
		}
		close(le.stop)
		close(le.done)
		le.ln = nil
		srv.listeners[i] = nil
	}
	srv.listeners = nil
}

func (srv *Server) ForEachLogin(f func(*Ses)) {
	srv.Lock()
	defer srv.Unlock()
	for _, ses := range srv.sessions {
		if ses != nil && ses.asn.state == established {
			f(ses)
		}
	}
}

func (srv *Server) handler(conn net.Conn) {
	var ses Ses
	svc := srv.cmd.Cfg.Keys
	ses.asn.Init()
	ses.Set(&srv.cmd.Cfg)
	ses.Set(&srv.repos)
	ses.Set(srv.ForEachLogin)
	srv.add(&ses)
	ses.asn.Set(conn)
	defer func() {
		r := recover()
		ses.Lock()
		ses.Unlock()
		if r != nil {
			err := r.(error)
			ses.asn.Diag(debug.Depth(3), err)
		}
		for i := 0; ses.asn.tx.going; i += 1 {
			if i == 0 {
				close(ses.asn.tx.ch)
			}
			time.Sleep(100 * time.Millisecond)
			if i == 3 {
				panic("can't close connection")
			}
		}
		user := srv.repos.users.User(&ses.Keys.Client.Login)
		if user != nil && user.logins > 0 {
			user.logins -= 1
		}
		srv.rm(&ses)
		srv.Log("disconnected", &ses.Keys.Client.Ephemeral)
		ses.Reset()
	}()
	if WithDeadline {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	n, err := conn.Read(ses.Keys.Client.Ephemeral[:])
	if err != nil {
		srv.Log(err)
		panic(err)
	}
	if n != PubEncrSz {
		panic(Error{"Oops!", "incomplete ephemeral key"})
	}
	ses.asn.Set(NewBox(2, srv.cmd.Cfg.Keys.Nonce,
		&ses.Keys.Client.Ephemeral, svc.Server.Pub.Encr,
		svc.Server.Sec.Encr))
	srv.Log("connected", &ses.Keys.Client.Ephemeral)
	for {
		pdu, opened := <-ses.asn.rx.ch
		if !opened {
			runtime.Goexit()
		}
		err := pdu.Open()
		if err != nil {
			pdu.Free()
			panic(err)
		}
		var v Version
		v.ReadFrom(pdu)
		// FIXME to adjust version ... ses.asn.Set(v)
		var id Id
		id.ReadFrom(pdu)
		id.Internal(v)
		ses.asn.time.out = time.Now()
		switch id {
		case AckReqId:
			err = ses.asn.AckerRx(pdu)
		case ExecReqId:
			err = ses.RxExec(pdu)
		case LoginReqId:
			if err = ses.RxLogin(pdu); err != nil {
				panic(err)
			}
			ses.asn.Log("login, ephemeral:",
				&ses.Keys.Client.Login,
				&ses.Keys.Client.Ephemeral)
		case BlobId:
			if bytes.Equal(ses.Keys.Client.Login.Bytes(),
				svc.Admin.Pub.Encr.Bytes()) ||
				bytes.Equal(ses.Keys.Client.Login.Bytes(),
					svc.Server.Pub.Encr.Bytes()) {
				_, err = ses.asn.repos.Store(&ses, v, nil, pdu)
			} else {
				err = os.ErrPermission
			}
			if err != nil {
				ses.asn.Diag(err)
			}
		default:
			if id >= Nids {
				panic(ErrIncompatible)
			} else {
				panic(ErrUnsupported)
			}
		}
		pdu.Free()
		pdu = nil
		if err != nil {
			panic(err)
		}
	}
}

func (srv *Server) Hangup() {
	srv.Lock()
	for _, ses := range srv.sessions {
		if ses != nil && ses.asn.tx.going {
			close(ses.asn.tx.ch)
		}
	}
	srv.Unlock()
	for {
		active := 0
		srv.Lock()
		for _, ses := range srv.sessions {
			if ses != nil {
				active += 1
			}
		}
		srv.Unlock()
		if active == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	srv.sessions = nil
}

func (srv *Server) Listen() error {
	for _, lurl := range srv.cmd.Cfg.Listen {
		l := &SrvListener{
			stop: make(chan struct{}, 1),
			done: make(chan error, 1),
		}
		switch lurl.Scheme {
		case "tcp":
			addr, err := net.ResolveTCPAddr(lurl.Scheme, lurl.Host)
			if err != nil {
				return err
			}
			l.ln, err = net.ListenTCP(lurl.Scheme, addr)
			if err != nil {
				return err
			}
			srv.AddListener(l)
			srv.Diag("listening on", addr)
			go l.listen(srv)
		case "unix":
			path := UrlPathSearch(lurl.Path)
			os.Remove(path)
			addr, err := net.ResolveUnixAddr(lurl.Scheme, path)
			if err != nil {
				return err
			}
			l.ln, err = net.ListenUnix(lurl.Scheme, addr)
			if err != nil {
				return err
			}
			srv.AddListener(l)
			l.clean = path
			srv.Diag("listening on", addr)
			go l.listen(srv)
		case "ws":
			l.ws = true
			if lurl.Host == "" {
				lurl.Host = ":http"
			}
			addr, err := net.ResolveTCPAddr("tcp", lurl.Host)
			if err != nil {
				return err
			}
			if l.ln, err = net.ListenTCP("tcp", addr); err != nil {
				return err
			}
			srv.AddListener(l)
			f := func(ws *websocket.Conn) {
				srv.handler(ws)
			}
			/*
				FIXME should use a custom handler
				h := func (w http.ResponseWriter, req *http.Request) {
					s := websocket.Server{Handler: websocket.Handler(webHandler)}
					s.ServeHTTP(w, req)
				});
				s := &http.Server{
					Addr:           ":8080",
					Handler:        h,
					ReadTimeout:    10 * time.Second,
					WriteTimeout:   10 * time.Second,
					MaxHeaderBytes: 1 << 20,
				}
				return s.Serve(l)
			*/
			mux := http.NewServeMux()
			mux.Handle(lurl.Path, websocket.Handler(f))
			srv.Diag("listening on", lurl.String())
			go http.Serve(l.ln, mux)
		default:
			err := &Error{lurl.Scheme, "unsupported"}
			srv.Diag(err)
			return err
		}
	}
	return nil
}

func (srv *Server) add(ses *Ses) {
	srv.Lock()
	defer srv.Unlock()
	for i := range srv.sessions {
		if srv.sessions[i] == nil {
			srv.sessions[i] = ses
			return
		}
	}
	srv.sessions = append(srv.sessions, ses)
}

func (srv *Server) rm(ses *Ses) {
	srv.Lock()
	defer srv.Unlock()
	for i := range srv.sessions {
		if srv.sessions[i] == ses {
			srv.sessions[i] = nil
			break
		}
	}
}

func (l *SrvListener) listen(srv *Server) {
	for {
		select {
		case <-l.stop:
			err := l.ln.Close()
			if len(l.clean) > 0 {
				os.Remove(l.clean)
			}
			l.done <- err
			return
		default:
			l.ln.SetDeadline(time.Now().Add(ldl))
			conn, err := l.ln.Accept()
			if err == nil {
				l.ln.SetDeadline(time.Time{})
				go srv.handler(conn)
			} else if !IsNetOpTimeout(err) {
				srv.Diag("accept", err)
				runtime.Goexit()
			}
		}
	}
}

func IsNetOpTimeout(err error) bool {
	e, ok := err.(*net.OpError)
	return ok && e.Timeout()
}
