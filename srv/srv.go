// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package srv provides an ASN server.
//
// Usage: asnsrv CONFIG
//
// This flushes the PDU trace to the configured log with SIGUSR1; stops all
// listeners with SIGTERM; and stops both listeners and accepted connections
// with SIGINT.
//
// See github.com/apptimistco/asn/srv/config for CONFIG.
package srv

import (
	"code.google.com/p/go.net/websocket"
	"errors"
	"fmt"
	"github.com/apptimistco/asn"
	"github.com/apptimistco/asn/srv/config"
	"github.com/apptimistco/box"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	Usage  = "Usage: asnsrv CONFIG"
	ldl    = 100 * time.Millisecond
	Inline = config.Inline
)

var (
	ErrUsage = errors.New(Usage)
	mutex    = &sync.Mutex{}
	rxers    = [asn.Nids]func(*server, *ses, *asn.PDU) error{
		asn.ExecReqId:   rxExec,
		asn.LoginReqId:  rxLogin,
		asn.PauseReqId:  rxPause,
		asn.ResumeReqId: rxResume,
		asn.QuitReqId:   rxQuit,

		asn.BlobId:  rxBlob,
		asn.IndexId: rxIndex,
	}
	servers []*server
)

func init() {
	servers = make([]*server, 0)
}

func Main(args ...string) (err error) {
	if help(args...) {
		return
	}
	if len(args) != 2 {
		err = ErrUsage
		return
	}
	srv := &server{
		sig:       make(chan os.Signal, 1),
		listeners: make([]*srvListener, 0),
		sessions:  make([]*ses, 0),
		mutex:     &sync.Mutex{},
	}
	if srv.config, err = config.New(args[1]); err != nil {
		return
	}
	if err = srv.newLogger(); err != nil {
		return
	}
	if err = srv.WritePidFile(); err != nil {
		return
	}
	defer func() {
		if err != nil {
			srv.log.Println("ERROR", err)
		}
		srv.RemovePidFile()
		srv.closeLogger()
	}()
	addSrv(srv)
	if err = srv.listen(); err != nil {
		return
	}
	srv.log.Println("started", os.Getpid(), "with", len(srv.listeners),
		"listener(s)")
	signal.Notify(srv.sig, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)
	for {
		sig := <-srv.sig
		srv.log.Println("caught", sig)
		if srv.logf != nil {
			srv.log.Println("PDU Trace...")
			asn.TraceFlush(srv.logf)
		}
		if sig == syscall.SIGINT || sig == syscall.SIGTERM {
			srv.stopListening()
		}
		if sig == syscall.SIGINT {
			srv.hangup()
			break
		}
	}
	delSrv(srv)
	asn.FlushASN()
	asn.FlushPDU()
	srv.log.Println("stopped")
	return
}

func KillAll(sig os.Signal) {
	if sig == syscall.SIGTERM {
		for _, srv := range servers {
			srv.sig <- sig
		}
	} else {
		for len(servers) > 0 {
			mutex.Lock()
			srv := servers[0]
			mutex.Unlock()
			srv.sig <- syscall.SIGINT
			for {
				time.Sleep(100 * time.Millisecond)
				if len(servers) == 0 || servers[0] != srv {
					break
				}
			}
		}
	}
}

func help(args ...string) bool {
	if len(args) > 1 &&
		(args[1] == "help" ||
			args[1] == "-help" ||
			args[1] == "--help" ||
			args[1] == "-h") {
		fmt.Println(Usage)
		return true
	}
	return false
}

func addSrv(srv *server) {
	mutex.Lock()
	servers = append(servers, srv)
	mutex.Unlock()
}

func delSrv(srv *server) {
	mutex.Lock()
	for i := range servers {
		if servers[i] == srv {
			copy(servers[i:], servers[i+1:])
			servers[len(servers)-1] = nil
			servers = servers[:len(servers)-1]
			break
		}
	}
	mutex.Unlock()
}

type server struct {
	config    *config.Config
	log       *log.Logger
	logf      *os.File
	sig       chan os.Signal
	listeners []*srvListener
	sessions  []*ses
	mutex     *sync.Mutex

	listening struct {
		stop chan struct{}
		done chan struct{}
	}
}

func (srv *server) newLogger() (err error) {
	switch srv.config.Log {
	case "": // use syslog
		srv.log, err = syslog.NewLogger(syslog.LOG_NOTICE, 0)
		if err != nil {
			return
		}
		srv.log.SetPrefix(srv.config.Name + " ")
	case os.DevNull:
		srv.log = log.New(ioutil.Discard, "", log.LstdFlags)
	default:
		srv.logf, err = os.Create(srv.config.Log)
		if err != nil {
			return
		}
		if err = srv.logf.Chmod(0664); err != nil {
			return
		}
		srv.log = log.New(srv.logf, "", log.LstdFlags)
	}
	return
}

func (srv *server) closeLogger() {
	if srv.logf != nil {
		srv.logf.Close()
	}
}

func (srv *server) addSes(ses *ses) {
	srv.mutex.Lock()
	srv.sessions = append(srv.sessions, ses)
	srv.mutex.Unlock()
}

func (srv *server) delSes(ses *ses) {
	srv.mutex.Lock()
	for i := range srv.sessions {
		if srv.sessions[i] == ses {
			copy(srv.sessions[i:], srv.sessions[i+1:])
			srv.sessions[len(srv.sessions)-1] = nil
			srv.sessions = srv.sessions[:len(srv.sessions)-1]
			break
		}
	}
	srv.mutex.Unlock()
}

func (srv *server) handler(conn net.Conn) {
	ses := pullSes()
	defer pushSes(&ses)
	srv.addSes(ses)
	defer func() {
		srv.log.Println("closed", ses.peer.String()[:8]+"...")
		srv.delSes(ses)
		pushSes(&ses)
		conn.Close()
	}()
	ses.asn.Name = srv.config.Name + "[unnamed]"
	ses.asn.SetConn(conn)
	conn.Read(ses.peer[:])
	srv.log.Println("connected", ses.peer.String()[:8]+"...")
	ses.asn.SetBox(box.New(2, srv.config.Keys.Nonce, &ses.peer,
		srv.config.Keys.Server.Pub.Encr,
		srv.config.Keys.Server.Sec.Encr))
	for {
		var err error
		var v asn.Version
		var id asn.Id
		pdu := <-ses.asn.RxQ
		if pdu == nil {
			break
		}
		v.ReadFrom(pdu)
		if v > ses.asn.Version() {
			ses.asn.SetVersion(v)
		}
		id.ReadFrom(pdu)
		if id.Internal(v); id >= asn.Nids {
			err = asn.ErrIncompatible
		} else {
			asn.Trace(ses.asn.Name, "Rx", id)
			if rx := rxers[id]; rx == nil {
				err = asn.ErrUnsupported
			} else {
				err = rx(srv, ses, pdu)
			}
		}
		pdu.Free()
		if err != nil {
			srv.log.Println("Error:", ses.asn.Name, err)
			break
		}
	}
}

func (srv *server) listen() error {
	for _, lurl := range srv.config.Listen {
		l := &srvListener{
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
			srv.listeners = append(srv.listeners, l)
			go l.listen(srv)
		case "unix":
			path := asn.UrlPathSearch(lurl.Path)
			os.Remove(path)
			addr, err := net.ResolveUnixAddr(lurl.Scheme, path)
			if err != nil {
				return err
			}
			l.ln, err = net.ListenUnix(lurl.Scheme, addr)
			if err != nil {
				return err
			}
			srv.listeners = append(srv.listeners, l)
			l.clean = path
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
			srv.listeners = append(srv.listeners, l)
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
			go http.Serve(l.ln, mux)
		default:
			srv.log.Println("lurl:", lurl.String())
			return errors.New("unsupported scheme: " + lurl.Scheme)
		}
	}
	return nil
}

func (srv *server) stopListening() {
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

func (srv *server) hangup() {
	for len(srv.sessions) > 0 {
		srv.mutex.Lock()
		ses := srv.sessions[0]
		srv.mutex.Unlock()
		ses.asn.SetStateClosed()
		for {
			time.Sleep(100 * time.Millisecond)
			if len(srv.sessions) == 0 || srv.sessions[0] != ses {
				break
			}
		}
	}
	srv.sessions = nil
}

func (srv *server) RemovePidFile() error {
	if len(srv.config.Pid) == 0 {
		return nil
	}
	return os.Remove(srv.config.Pid)
}

func (srv *server) WritePidFile() error {
	if len(srv.config.Pid) == 0 {
		return nil
	}
	f, err := os.Create(srv.config.Pid)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Chmod(0664); err != nil {
		return err
	}
	fmt.Fprintln(f, os.Getpid())
	return nil
}

// listener extends the net.Listener interface with SetDeadline
type listener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (net.Conn, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr

	// SetDeadline sets the deadline associated with the listener. A zero
	// time value disables the deadline.
	SetDeadline(time.Time) error
}

type srvListener struct {
	ln    listener
	stop  chan struct{}
	done  chan error
	ws    bool
	clean string
}

func (l *srvListener) listen(srv *server) {
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
				srv.log.Println("Accept error:", err)
			}
		}
	}
}
