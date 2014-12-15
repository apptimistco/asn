// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package srv provides an ASN server.

Usage: asnsrv CONFIG

This flushes the PDU trace to the configured log with SIGUSR1; stops all
listeners with SIGTERM; and stops both listeners and accepted connections
with SIGINT.

For CONFIG format, see:
	$ godoc github.com/apptimistco/asn Config
*/
package srv

import (
	"errors"
	"fmt"
	"io"
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

	"github.com/apptimistco/asn"
	"golang.org/x/net/websocket"
)

const (
	Usage = "Usage: asnsrv CONFIG"
	ldl   = 100 * time.Millisecond
)

var (
	Stdin  io.Reader = os.Stdin
	Stdout io.Writer = os.Stdout
	Stderr io.Writer = os.Stderr

	ErrUsage = errors.New(Usage)
	mutex    = &sync.Mutex{}
	servers  []*Server
	// CleanRepos is only used in testing;
	// it isn't a command flag
	CleanRepos = false
)

func init() {
	servers = make([]*Server, 0)
}

func Main(args ...string) (err error) {
	if help(args...) {
		return
	}
	if len(args) < 2 {
		err = ErrUsage
		return
	}
	syscall.Umask(0007)
	srv := &Server{
		sig:       make(chan os.Signal, 1),
		listeners: make([]*srvListener, 0),
		sessions:  make([]*Ses, 0),
		mutex:     &sync.Mutex{},
	}
	srv.Config, err = asn.NewConfig(args[1])
	if os.IsNotExist(err) {
		srv.Config, err = asn.NewConfig(args[1] + ".yaml")
	}
	if err != nil {
		return
	}
	if err = srv.loggerOpen(); err != nil {
		return
	}
	if err = srv.pidFileWrite(); err != nil {
		return
	}
	defer func() {
		if err != nil {
			srv.log.Println("ERROR", err)
		}
		srv.pidFileRemove()
		srv.loggerClose()
	}()
	if CleanRepos {
		os.RemoveAll(srv.Config.Dir)
	}
	if srv.repos, err = asn.NewRepos(srv.Config.Dir); err != nil {
		return
	}
	for _, q := range []*asn.Quad{
		srv.Config.Keys.Admin,
		srv.Config.Keys.Server,
	} {
		user := srv.repos.Users.Search(q.Pub.Encr)
		if user == nil {
			user, err = srv.repos.NewUser(q.Pub.Encr)
			if err != nil {
				return
			}
			user.ASN.Auth = *q.Pub.Auth
			user.ASN.Author = *q.Pub.Encr
		}
		user = nil
	}
	defer srv.repos.Free()
	if len(args) > 2 {
		// local server command line exec
		ses := NewSes()
		ses.srv = srv
		ses.ASN.Repos = srv.repos
		ses.Keys.Client.Login = *srv.Config.Keys.Admin.Pub.Encr
		ses.asnsrv = true
		v := ses.Exec(asn.Requester{}, Stdin, args[2:]...)
		err, _ = v.(error)
		asn.AckOut(Stdout, v)
		v = nil
		return
	}
	srvAdd(srv)
	if err = srv.listenStart(); err != nil {
		return
	}
	srv.log.Println("started", os.Getpid(), "with", len(srv.listeners),
		"listener(s)")
	signal.Notify(srv.sig, syscall.SIGUSR1, syscall.SIGINT, syscall.SIGTERM)
	for {
		sig := <-srv.sig
		srv.log.Println("caught", sig)
		if srv.logf != nil {
			srv.log.Println("Trace...")
			asn.TraceFlush(srv.logf)
		}
		if sig == syscall.SIGINT || sig == syscall.SIGTERM {
			srv.listenStop()
		}
		if sig == syscall.SIGINT {
			srv.hangup()
			break
		}
	}
	srvDel(srv)
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

func srvAdd(srv *Server) {
	mutex.Lock()
	servers = append(servers, srv)
	mutex.Unlock()
}

func srvDel(srv *Server) {
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

type Server struct {
	Config    *asn.Config
	repos     *asn.Repos
	log       *log.Logger
	logf      *os.File
	sig       chan os.Signal
	listeners []*srvListener
	sessions  []*Ses
	mutex     *sync.Mutex

	listening struct {
		stop chan struct{}
		done chan struct{}
	}
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
	ses.ASN.Repos = srv.repos
	ses.ASN.Name = srv.Config.Name + "[unnamed]"
	ses.ASN.SetConn(conn)
	conn.Read(ses.Keys.Client.Ephemeral[:])
	ses.ASN.Println("connected",
		ses.Keys.Client.Ephemeral.String()[:8]+"...")
	ses.ASN.SetBox(asn.NewBox(2, srv.Config.Keys.Nonce,
		&ses.Keys.Client.Ephemeral,
		srv.Config.Keys.Server.Pub.Encr,
		srv.Config.Keys.Server.Sec.Encr))
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
			v  asn.Version
			id asn.Id
		)
		v.ReadFrom(pdu)
		if v > ses.ASN.Version() {
			ses.ASN.SetVersion(v)
		}
		id.ReadFrom(pdu)
		id.Internal(v)
		asn.Diag.Println("Rx", id)
		switch id {
		case asn.AckReqId:
			err = ses.ASN.Acker.Rx(pdu)
		case asn.ExecReqId:
			err = ses.RxExec(pdu)
		case asn.LoginReqId:
			err = ses.RxLogin(pdu)
		case asn.PauseReqId:
			err = ses.RxPause(pdu)
		case asn.ResumeReqId:
			err = ses.RxResume(pdu)
		case asn.QuitReqId:
			err = ses.RxQuit(pdu)
		case asn.BlobId:
			err = ses.RxBlob(pdu)
		default:
			if id >= asn.Nids {
				err = asn.ErrIncompatible
			} else {
				err = asn.ErrUnsupported
			}
		}
		if id != asn.ExecReqId {
			pdu.Free() // otherwise free in RxExec go routine
		}
		pdu = nil
		if err != nil {
			ses.ASN.Println("Error:", err)
			break
		}
	}
}

func (srv *Server) hangup() {
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

func (srv *Server) listenStart() error {
	for _, lurl := range srv.Config.Listen {
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

func (srv *Server) listenStop() {
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

func (srv *Server) loggerClose() {
	if srv.logf != nil {
		srv.logf.Close()
	}
}

func (srv *Server) loggerOpen() (err error) {
	switch srv.Config.Log {
	case "": // use syslog
		srv.log, err = syslog.NewLogger(syslog.LOG_NOTICE, 0)
		if err != nil {
			return
		}
		srv.log.SetPrefix(srv.Config.Name + " ")
	case os.DevNull:
		srv.log = log.New(ioutil.Discard, "", log.LstdFlags)
	default:
		srv.logf, err = os.Create(srv.Config.Log)
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

func (srv *Server) newSes() (ses *Ses) {
	srv.mutex.Lock()
	ses = NewSes()
	srv.sessions = append(srv.sessions, ses)
	ses.srv = srv
	srv.mutex.Unlock()
	return
}

func (srv *Server) pidFileRemove() error {
	if len(srv.Config.Pid) == 0 {
		return nil
	}
	return os.Remove(srv.Config.Pid)
}

func (srv *Server) pidFileWrite() error {
	if len(srv.Config.Pid) == 0 {
		return nil
	}
	f, err := os.Create(srv.Config.Pid)
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

type srvListener struct {
	ln    asn.Listener
	stop  chan struct{}
	done  chan error
	ws    bool
	clean string
}

func (l *srvListener) listen(srv *Server) {
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
				asn.Println("Accept error:", err)
			}
		}
	}
}
