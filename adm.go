// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"io"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/file"
	"golang.org/x/net/websocket"
)

type Adm struct {
	debug.Debug
	cmd       *Command
	asn       asn
	ephemeral struct {
		pub *PubEncr
		sec *SecEncr
	}
	done struct {
		req, handler Done
	}
	repos Repos
	rxq   chan *PDU
	store bool
}

func (cmd *Command) Admin(args ...string) {
	adm := Adm{
		cmd: cmd,
	}
	err := cmd.Cfg.Check(AdminMode)
	defer func() {
		cmd.Done <- err
	}()
	if err != nil {
		runtime.Goexit()
	}
	url, err := cmd.Cfg.ServerURL(cmd.Flag.Server)
	if err != nil {
		runtime.Goexit()
	}
	adm.Debug.Set(cmd.Cfg.Name)
	if err = adm.repos.Set(cmd.Cfg.Dir); err != nil {
		runtime.Goexit()
	}
	defer func() { adm.repos.Reset() }()
	adm.asn.Init()
	adm.asn.Set(&adm.repos)
	if err = adm.Connect(url); err != nil {
		runtime.Goexit()
	}
	adm.done.handler = make(Done, 1)
	adm.done.req = make(Done, 1)
	go adm.handler()
	defer func() {
		close(adm.asn.tx.ch)
		if err == nil {
			err = <-adm.done.handler
		} else {
			<-adm.done.handler
		}
		close(adm.done.handler)
		close(adm.done.req)
		if err == io.EOF {
			err = nil
		}
		adm.asn.Reset()
	}()
	if cmd.Flag.NoLogin == false {
		if err = adm.Login(); err != nil {
			runtime.Goexit()
		}
	}
	if len(args) > 0 {
		if args[0] == "-" {
			err = adm.script()
		} else {
			err = adm.Exec(args...)
		}
	} else {
		err = adm.CLI()
	}
}

func (adm *Adm) AuthBlob() (err error) {
	f := adm.repos.tmp.New()
	defer func() {
		if err != nil {
			adm.repos.tmp.Free(f)
		}
	}()
	_, err = NewFH(adm.cmd.Cfg.Keys.Admin.Pub.Encr,
		adm.cmd.Cfg.Keys.Admin.Pub.Encr, AsnAuth).WriteTo(f)
	if err != nil {
		return
	}
	_, err = adm.cmd.Cfg.Keys.Admin.Pub.Auth.WriteTo(f)
	if err != nil {
		return
	}
	adm.asn.Tx(NewPDUFile(f))
	return
}

func (adm *Adm) Blobber(_ func(string) error, _ io.Reader, _ ...string) error {
	return nil
}

// command process given line as space separated args
func (adm *Adm) cmdLine(line string) (err error) {
	args := strings.Split(line, " ")
	if len(args) == 0 || args[0] == "" {
		return
	}
	switch args[0] {
	case "quit":
		err = io.EOF
	case "auth-blob":
		err = adm.AuthBlob()
	case "login":
		err = adm.Login()
	default:
		err = adm.Exec(args...)
	}
	return
}

// Connect to the given server.
func (adm *Adm) Connect(url *URL) (err error) {
	var conn net.Conn
	for t := 100 * time.Millisecond; true; t *= 2 {
		conn, err = adm.Dial(url)
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
	adm.ephemeral.pub, adm.ephemeral.sec, _ = NewRandomEncrKeys()
	conn.Write(adm.ephemeral.pub[:])
	adm.asn.name.local = adm.cmd.Cfg.Name
	adm.asn.Set(url.String())
	adm.asn.Set(NewBox(2,
		adm.cmd.Cfg.Keys.Nonce,
		adm.cmd.Cfg.Keys.Server.Pub.Encr,
		adm.ephemeral.pub,
		adm.ephemeral.sec))
	adm.asn.Set(conn)
	adm.asn.Diag("connected")
	return
}

func (adm *Adm) Dial(durl *URL) (net.Conn, error) {
	switch scheme := durl.Scheme; scheme {
	case "tcp":
		addr, err := net.ResolveTCPAddr(scheme, durl.Host)
		if err != nil {
			return nil, err
		}
		adm.Diag("dialing", scheme, addr)
		return net.DialTCP(scheme, nil, addr)
	case "unix":
		path := UrlPathSearch(durl.Path)
		addr, err := net.ResolveUnixAddr(scheme, path)
		if err != nil {
			return nil, err
		}
		adm.Diag("dialing", scheme, addr)
		return net.DialUnix(scheme, nil, addr)
	case "ws":
		turl := durl.String()
		adm.Diag("dialing", turl)
		if durl.Host == "" {
			durl.Host = "localhost:http"
		}
		nc, err := net.Dial("tcp", durl.Host)
		if err != nil {
			adm.Diag(err)
			return nil, err
		}
		origin := "http://localhost" // FIXME
		wscfg, err := websocket.NewConfig(turl, origin)
		if err != nil {
			adm.Diag(err)
			nc.Close()
			return nil, err
		}
		ws, err := websocket.NewClient(wscfg, nc)
		if err != nil {
			adm.Diag(err)
		}
		return ws, err
	default:
		return nil, &Error{scheme, "unsupported URL scheme"}
	}
}

func (adm *Adm) DN() string {
	return adm.cmd.Cfg.Dir
}

// handler processes Rx.Q until closed or kill signal
func (adm *Adm) handler() {
	defer func() {
		r := recover()
		if adm.asn.tx.going {
			close(adm.asn.tx.ch)
		}
		if r != nil {
			err := r.(error)
			adm.done.handler <- err
			adm.done.req <- err
		}
	}()
	for {
		select {
		case <-adm.cmd.Sig:
			close(adm.asn.tx.ch)
		case pdu, opened := <-adm.asn.rx.ch:
			if !opened {
				if adm.asn.rx.err != nil {
					panic(adm.asn.rx.err)
				}
				panic(io.EOF)
			}
			if err := pdu.Open(); err != nil {
				panic(err)
			}
			var v Version
			v.ReadFrom(pdu)
			var id Id
			id.ReadFrom(pdu)
			id.Internal(v)
			switch id {
			case AckReqId:
				if err := adm.asn.AckerRx(pdu); err != nil {
					adm.Diag(err)
				}
			case BlobId:
				if adm.store {
					_, err := adm.repos.Store(adm, v, nil,
						pdu)
					if err != nil {
						panic(err)
					}
				} else if adm.rxq != nil {
					pdu.Clone()
					adm.rxq <- pdu
				} else {
					adm.ObjDump(pdu)
				}
			default:
				adm.Diag("unsupported pdu:", id)
			}
			pdu.Free()
		}
	}
}

func (adm *Adm) IsAdmin(key *PubEncr) bool {
	return *key == *adm.cmd.Cfg.Keys.Admin.Pub.Encr
}

func (adm *Adm) IsService(key *PubEncr) bool {
	return *key == *adm.cmd.Cfg.Keys.Server.Pub.Encr
}

func (adm *Adm) Exec(args ...string) (err error) {
	var pdu *PDU
	for _, arg := range args {
		if arg == "-" {
			pdu = NewPDUFile(adm.repos.tmp.New())
			break
		}
	}
	if pdu == nil {
		pdu = NewPDUBuf()
	}
	v := adm.asn.Version()
	v.WriteTo(pdu)
	ExecReqId.Version(v).WriteTo(pdu)
	req := NewReqString("exec")
	req.WriteTo(pdu)
	pdu.Write([]byte(strings.Join(args, "\x00")))
	for _, arg := range args {
		if arg == "-" {
			pdu.Write([]byte{0, 0}[:])
			pdu.ReadFrom(adm.cmd.Stdin)
			break
		}
	}
	adm.asn.acker.Map(req, func(req Req, err error, ack *PDU) error {
		adm.asn.acker.UnMap(req)
		if err == nil {
			ack.WriteTo(adm.cmd.Stdout)
		}
		adm.done.req <- err
		return err
	})
	adm.asn.Diag("exec", args[0], "...")
	if args[0] == "clone" {
		adm.store = true
	} else {
		adm.store = false
	}
	adm.asn.Tx(pdu)
	if err = <-adm.done.req; err != nil {
		adm.asn.Diag("exec", args[0], err)
	} else {
		adm.asn.Diag("exec", args[0], "success")
	}
	return
}

func (adm *Adm) Login() (err error) {
	login := NewPDUBuf()
	key := adm.cmd.Cfg.Keys.Admin.Pub.Encr
	sig := adm.cmd.Cfg.Keys.Admin.Sec.Auth.Sign(key[:])
	v := adm.asn.Version()
	v.WriteTo(login)
	LoginReqId.Version(v).WriteTo(login)
	req := NewReqString("login")
	req.WriteTo(login)
	login.Write(key[:])
	login.Write(sig[:])
	adm.asn.Diag("login", key, sig)
	adm.asn.acker.Map(req, func(req Req, err error, ack *PDU) error {
		adm.asn.acker.UnMap(req)
		if err == nil {
			var peer PubEncr
			var nonce Nonce
			ack.Read(peer[:])
			ack.Read(nonce[:])
			adm.asn.Diag("rekey, nonce:", peer, nonce)
			adm.asn.Set(NewBox(2, &nonce, &peer, adm.ephemeral.pub,
				adm.ephemeral.sec))
			adm.asn.state = established
		}
		adm.done.req <- err
		return err
	})
	adm.asn.Tx(login)
	if err = <-adm.done.req; err != nil {
		adm.asn.Diag("login", err)
	} else {
		adm.asn.Diag("login success")
	}
	return
}

func (adm *Adm) ObjDump(pdu *PDU) {
	defer pdu.Free()
	ObjDump(adm.cmd.Stdout, pdu)
}

func (adm *Adm) Send(_ *PubEncr, _ *file.File) {}

func (adm *Adm) script() error {
	scanner := bufio.NewScanner(adm.cmd.Stdin)
	for scanner.Scan() {
		if err := adm.cmdLine(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}
