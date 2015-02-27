// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

const (
	ldl = 100 * time.Millisecond
)

type SrvListener struct {
	ln    Listener
	stop  chan struct{}
	done  chan error
	ws    bool
	clean string
}

type Server struct {
	cmd       *Command
	repos     *Repos
	listeners []*SrvListener
	sessions  []*Ses
	mutex     *sync.Mutex

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
		mutex:     &sync.Mutex{},
	}
	err := cmd.Cfg.Check(ServerMode)
	defer func() { cmd.Done <- err }()
	if err != nil {
		runtime.Goexit()
	}
	if srv.repos, err = NewRepos(srv.cmd.Cfg.Dir); err != nil {
		runtime.Goexit()
	}
	defer func() {
		srv.repos.Free()
		srv.repos = nil
	}()
	for _, k := range []*UserKeys{
		srv.cmd.Cfg.Keys.Admin,
		srv.cmd.Cfg.Keys.Server,
	} {
		user := srv.repos.Users.Search(k.Pub.Encr)
		if user == nil {
			user, err = srv.repos.NewUser(k.Pub.Encr)
			if err != nil {
				runtime.Goexit()
			}
			user.ASN.Auth = *k.Pub.Auth
			user.ASN.Author = *k.Pub.Encr
		}
		user = nil
	}
	if len(args) > 0 {
		// local server command line exec
		ses := NewSes()
		ses.srv = srv
		ses.ASN.Repos = srv.repos
		ses.Keys.Client.Login = *srv.cmd.Cfg.Keys.Admin.Pub.Encr
		ses.asnsrv = true
		v := ses.Exec(Requester{}, cmd.In, args...)
		err, _ = v.(error)
		AckOut(cmd.Out, v)
		v = nil
		runtime.Goexit()
	}
	if err = srv.Listen(); err != nil {
		runtime.Goexit()
	}
	cmd.In.Close()
	cmd.Out.Close()
	// FIXME should we close os.Stderr?
	for {
		sig := <-srv.cmd.Sig
		Diag.Println("caught", sig)
		switch {
		case IsINT(sig):
			TraceFlush(Diag)
			srv.Close()
			srv.Hangup()
			runtime.Goexit()
		case IsTERM(sig):
			srv.Close()
		case IsUSR1(sig):
			TraceFlush(Log)
		}
	}
}

func (srv *Server) AddListener(l *SrvListener) {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
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

func (srv *Server) ForEachSession(f func(*Ses)) {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
	for _, ses := range srv.sessions {
		if ses != nil {
			f(ses)
		}
	}
}

func (srv *Server) handler(conn net.Conn) {
	ses := srv.NewSes()
	ses.ASN.SetConn(conn)
	defer func() {
		r := recover()
		ses.ExecMutex.Lock()
		ses.ExecMutex.Unlock()
		for i := 0; !ses.ASN.Go.Tx.X; i += 1 {
			if i == 0 {
				close(ses.ASN.Go.Tx.C)
			}
			time.Sleep(100 * time.Millisecond)
			if i == 3 {
				panic("can't close connection")
			}
		}
		ses.Free()
		srv.mutex.Lock()
		for i := range srv.sessions {
			if srv.sessions[i] == ses {
				srv.sessions[i] = nil
				break
			}
		}
		srv.mutex.Unlock()
		if r != nil {
			err := r.(error)
			Diag.Output(4, ses.ASN.Name.Session+" "+err.Error())
		}
	}()
	conn.Read(ses.Keys.Client.Ephemeral[:])
	ses.ASN.SetBox(NewBox(2, srv.cmd.Cfg.Keys.Nonce,
		&ses.Keys.Client.Ephemeral,
		srv.cmd.Cfg.Keys.Server.Pub.Encr,
		srv.cmd.Cfg.Keys.Server.Sec.Encr))
	for {
		pdu, opened := <-ses.ASN.Go.Rx.C
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
		if v > ses.ASN.Version() {
			ses.ASN.SetVersion(v)
		}
		var id Id
		id.ReadFrom(pdu)
		id.Internal(v)
		ses.ASN.Time.Out = time.Now()
		switch id {
		case AckReqId:
			err = ses.ASN.AckerRx(pdu)
		case ExecReqId:
			err = ses.RxExec(pdu)
		case LoginReqId:
			if err = ses.RxLogin(pdu); err != nil {
				panic(err)
			}
		case BlobId:
			err = ses.RxBlob(pdu)
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
	srv.mutex.Lock()
	for _, ses := range srv.sessions {
		if ses != nil && !ses.ASN.Go.Tx.X {
			close(ses.ASN.Go.Tx.C)
		}
	}
	srv.mutex.Unlock()
	for {
		active := 0
		srv.mutex.Lock()
		for _, ses := range srv.sessions {
			if ses != nil {
				active += 1
			}
		}
		srv.mutex.Unlock()
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
			Diag.Println(srv.cmd.Cfg.Name, "listening on", addr)
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
			Diag.Println(srv.cmd.Cfg.Name, "listening on", addr)
			go l.listen(srv)
		case "ws":
			l.ws = true
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
			/*
				http.Handle(lurl.Path, websocket.Handler(f))
				go http.Serve(l.ln, nil)
			*/
			mux := http.NewServeMux()
			mux.Handle(lurl.Path, websocket.Handler(f))
			Diag.Println(srv.cmd.Cfg.Name, "listening on", addr)
			go http.Serve(l.ln, mux)
		default:
			Log.Println("lurl:", lurl.String())
			return errors.New("unsupported scheme: " + lurl.Scheme)
		}
	}
	return nil
}

func (srv *Server) NewSes() (ses *Ses) {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
	ses = NewSes()
	ses.srv = srv
	ses.ASN.Repos = srv.repos
	ses.ASN.Name.Local = srv.cmd.Cfg.Name
	ses.ASN.Name.Remote = "unnamed"
	ses.ASN.NameSession()
	for i := range srv.sessions {
		if srv.sessions[i] == nil {
			srv.sessions[i] = ses
			return
		}
	}
	srv.sessions = append(srv.sessions, ses)
	return
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
				go srv.handler(conn)
			} else if opErr, ok := err.(*net.OpError); !ok ||
				!opErr.Timeout() {
				Diag.Println("accept", err)
			}
		}
	}
}
