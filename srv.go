// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"net"
	"net/http"
	"os"
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
	if err != nil {
		goto egress
	}
	if srv.repos, err = NewRepos(srv.cmd.Cfg.Dir); err != nil {
		goto egress
	}
	defer srv.repos.Free()
	for _, q := range []*Quad{
		srv.cmd.Cfg.Keys.Admin,
		srv.cmd.Cfg.Keys.Server,
	} {
		user := srv.repos.Users.Search(q.Pub.Encr)
		if user == nil {
			user, err = srv.repos.NewUser(q.Pub.Encr)
			if err != nil {
				goto egress
			}
			user.ASN.Auth = *q.Pub.Auth
			user.ASN.Author = *q.Pub.Encr
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
	} else {
		if err = srv.Listen(); err == nil {
			cmd.In.Close()
			cmd.Out.Close()
			// FIXME should we close or os.Stderr?
			Log.Println("started", cmd.Cfg.Name,
				"with", len(srv.listeners), "listener(s)")
			for {
				sig := <-srv.cmd.Sig
				Diag.Println("caught", sig)
				TraceFlush(Diag)
				if IsINT(sig) || IsTERM(sig) {
					srv.Close()
				}
				if IsINT(sig) {
					srv.Hangup()
					break
				}
			}
			Log.Println("stopped", cmd.Cfg.Name)
		}
	}
egress:
	if err != nil {
		Log.Println("ERROR:", cmd.Cfg.Name, err)
		Diag.Println("oops", err)
	}
	cmd.Done <- err
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
		f(ses)
	}
}

func (srv *Server) Free(ses *Ses) {
	srv.mutex.Lock()
	for i := range srv.sessions {
		if srv.sessions[i] == ses {
			copy(srv.sessions[i:], srv.sessions[i+1:])
			srv.sessions[len(srv.sessions)-1] = nil
			srv.sessions = srv.sessions[:len(srv.sessions)-1]
			break
		}
	}
	ses.Free()
	srv.mutex.Unlock()
}

func (srv *Server) handler(conn net.Conn) {
	ses := srv.newSes()
	defer func() {
		ses.ASN.Println("closed")
		ses.ASN.Repos = nil
		ses.ASN.Free()
		ses.ASN = nil
		srv.Free(ses)
	}()
	ses.ASN.SetConn(conn)
	conn.Read(ses.Keys.Client.Ephemeral[:])
	ses.ASN.Println("connected",
		ses.Keys.Client.Ephemeral.String()[:8]+"...")
	ses.ASN.SetBox(NewBox(2, srv.cmd.Cfg.Keys.Nonce,
		&ses.Keys.Client.Ephemeral,
		srv.cmd.Cfg.Keys.Server.Pub.Encr,
		srv.cmd.Cfg.Keys.Server.Sec.Encr))
	for {
		pdu := <-ses.ASN.RxQ
		if pdu == nil {
			break
		}
		err := pdu.Open()
		if err != nil {
			pdu.Free()
			break
		}
		var (
			v  Version
			id Id
		)
		v.ReadFrom(pdu)
		if v > ses.ASN.Version() {
			ses.ASN.SetVersion(v)
		}
		id.ReadFrom(pdu)
		id.Internal(v)
		switch id {
		case AckReqId:
			err = ses.ASN.Acker.Rx(pdu)
		case ExecReqId:
			err = ses.RxExec(pdu)
		case LoginReqId:
			err = ses.RxLogin(pdu)
		case PauseReqId:
			err = ses.RxPause(pdu)
		case ResumeReqId:
			err = ses.RxResume(pdu)
		case QuitReqId:
			err = ses.RxQuit(pdu)
		case BlobId:
			err = ses.RxBlob(pdu)
		default:
			if id >= Nids {
				err = ErrIncompatible
			} else {
				err = ErrUnsupported
			}
		}
		if id != ExecReqId {
			pdu.Free() // otherwise free in RxExec go routine
		}
		pdu = nil
		if err != nil {
			ses.ASN.Println("Error:", err)
			break
		}
	}
}

func (srv *Server) Hangup() {
	for len(srv.sessions) > 0 {
		srv.mutex.Lock()
		ses := srv.sessions[0]
		srv.mutex.Unlock()
		ses.ASN.SetStateClosed()
		for {
			time.Sleep(100 * time.Millisecond)
			if len(srv.sessions) == 0 || srv.sessions[0] != ses {
				break
			}
		}
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

func (srv *Server) newSes() (ses *Ses) {
	srv.mutex.Lock()
	ses = NewSes()
	srv.sessions = append(srv.sessions, ses)
	ses.srv = srv
	ses.ASN.Repos = srv.repos
	ses.ASN.Name.Local = srv.cmd.Cfg.Name
	ses.ASN.Name.Remote = "unnamed"
	ses.ASN.Name.Session = ses.ASN.Name.Local + ":" + ses.ASN.Name.Remote
	srv.mutex.Unlock()
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
