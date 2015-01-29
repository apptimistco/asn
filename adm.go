// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

func (cmd *Command) Admin(args ...string) {
	adm := Adm{cmd: cmd}
	err := cmd.Cfg.Check(AdminMode)
	si := 0
	if err != nil {
		goto egress
	}
	si, err = cmd.Cfg.SI(cmd.Flag.Server)
	if err != nil {
		goto egress
	}
	if err = adm.Connect(si); err != nil {
		goto egress
	}
	go adm.handler()
	if cmd.Flag.Nologin == false {
		if err = adm.Login(); err != nil {
			goto egress
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
	if err == io.EOF {
		err = nil
	}
	if qerr := adm.Quit(); err == nil && qerr != nil {
		err = qerr
	}
	cmd.Sig.TERM()
	if err == nil {
		err = <-adm.doneCh
	} else {
		<-adm.doneCh
	}
egress:
	adm.Close()
	if err == io.EOF {
		err = nil
	}
	cmd.Done <- err
}

type Adm struct {
	cmd       *Command
	asn       *ASN
	ephemeral struct {
		pub *PubEncr
		sec *SecEncr
	}
	doneCh chan error
}

func (adm *Adm) AuthBlob() error {
	return adm.Blob("asn/auth", (*adm.cmd.Cfg.Keys.Admin.Pub.Auth)[:])
}

func (adm *Adm) Blob(name string, v interface{}) (err error) {
	blob := NewBlob(adm.cmd.Cfg.Keys.Admin.Pub.Encr,
		adm.cmd.Cfg.Keys.Admin.Pub.Encr, name)
	defer blob.Free()
	f, err := adm.asn.Repos.Tmp.NewFile()
	if err != nil {
		return
	}
	if _, _, err = blob.SummingWriteContentsTo(f, v); err == nil {
		adm.asn.Tx(NewPDUFile(f))
		adm.asn.Diag(BlobId, name)
	}
	f = nil
	return
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
			adm.asn.Repos.Free()
			adm.asn.Repos = nil
			adm.asn.Free()
			adm.asn = nil
			FlushASN()
		}
	}
}

// command process given line as space separated args
func (adm *Adm) cmdLine(line string) error {
	args := strings.Split(line, " ")
	if len(args) == 0 || args[0] == "" {
		return nil
	}
	switch args[0] {
	case "quit":
		return io.EOF
	case "auth-blob":
		return adm.AuthBlob()
	case "login":
		return adm.Login()
	case "pause":
		return adm.Pause()
	case "resume":
		return adm.Resume()
	default:
		if err := adm.Exec(args...); err != nil {
			fmt.Println(err)
		}
	}
	return nil
}

// Connect to the si'th server listed in the configuration.
func (adm *Adm) Connect(si int) (err error) {
	var conn net.Conn
	for t := 100 * time.Millisecond; true; t *= 2 {
		conn, err = adm.Dial(adm.cmd.Cfg.Server[si].Url)
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
	Diag.Println(adm.cmd.Cfg.Name, "connected to",
		adm.cmd.Cfg.Server[si].Url)
	adm.ephemeral.pub, adm.ephemeral.sec, _ = NewRandomEncrKeys()
	conn.Write(adm.ephemeral.pub[:])
	adm.asn = NewASN()
	if adm.asn.Repos, err = NewRepos(adm.cmd.Cfg.Dir); err != nil {
		return
	}
	adm.asn.Name.Local = adm.cmd.Cfg.Name
	adm.asn.Name.Remote = adm.cmd.Cfg.Server[si].Name
	adm.asn.Name.Session = adm.asn.Name.Local + ":" + adm.asn.Name.Remote
	adm.asn.SetBox(NewBox(2,
		adm.cmd.Cfg.Keys.Nonce,
		adm.cmd.Cfg.Keys.Server.Pub.Encr,
		adm.ephemeral.pub,
		adm.ephemeral.sec))
	adm.asn.SetConn(conn)
	adm.doneCh = make(chan error, 1)
	return
}

func (adm *Adm) Dial(durl *URL) (net.Conn, error) {
	switch scheme := durl.Scheme; scheme {
	case "tcp":
		addr, err := net.ResolveTCPAddr(scheme, durl.Host)
		if err != nil {
			return nil, err
		}
		Diag.Println(adm.cmd.Cfg.Name, "dialing", scheme, addr)
		return net.DialTCP(scheme, nil, addr)
	case "unix":
		path := UrlPathSearch(durl.Path)
		addr, err := net.ResolveUnixAddr(scheme, path)
		if err != nil {
			return nil, err
		}
		Diag.Println(adm.cmd.Cfg.Name, "dialing", scheme, addr)
		return net.DialUnix(scheme, nil, addr)
	case "ws":
		turl := durl.String()
		Diag.Println(adm.cmd.Cfg.Name, "dialing", turl)
		nc, err := net.Dial("tcp", durl.Host)
		if err != nil {
			Diag.Println(adm.cmd.Cfg.Name, err)
			return nil, err
		}
		Diag.Println(adm.cmd.Cfg.Name, "connected to", turl)
		origin := "http://localhost" // FIXME
		wscfg, err := websocket.NewConfig(turl, origin)
		if err != nil {
			Diag.Println(adm.cmd.Cfg.Name, err)
			nc.Close()
			return nil, err
		}
		ws, err := websocket.NewClient(wscfg, nc)
		if err != nil {
			Diag.Println(adm.cmd.Cfg.Name, err)
		}
		return ws, err
	default:
		return nil, &Error{
			Name:   scheme,
			Reason: "unsupported URL scheme",
		}
	}
}

func (adm *Adm) DN() string {
	return adm.cmd.Cfg.Dir
}

func (adm *Adm) File(pdu *PDU) {
	blob, err := NewBlobFrom(pdu)
	if err != nil {
		adm.asn.Diag("NewBlob", err)
		return
	}
	sum, fn, err := adm.asn.Repos.File(blob, pdu)
	if err != nil {
		adm.asn.Diag("File", err)
	}
	links, err := adm.asn.Repos.MkLinks(blob, sum, fn)
	for i := range links {
		if links[i] != nil {
			adm.asn.Diag("saved", links[i].FN)
			links[i].Free()
			links[i] = nil
		}
	}
	links = nil
	blob.Free()
	pdu.Free()
}

// handler processes pdu RxQ until EOF or kill signal
func (adm *Adm) handler() {
	var (
		err error
		pdu *PDU
		v   Version
		id  Id
	)
	defer func() {
		adm.asn.Diag("handler", err)
		adm.doneCh <- err
	}()
	adm.asn.Diag("handler...")
	for err == nil {
		select {
		case pdu = <-adm.asn.RxQ:
			if pdu == nil {
				err = io.EOF
				return
			}
		case <-adm.cmd.Sig:
			adm.asn.SetStateClosed()
			err = io.EOF
			return
		}
		adm.asn.Diagf("handle %p\n", pdu)
		if err = pdu.Open(); err != nil {
			return
		}
		v.ReadFrom(pdu)
		if v < adm.asn.Version() {
			adm.asn.SetVersion(v)
		}
		id.ReadFrom(pdu)
		id.Internal(v)
		adm.asn.Diag("handle", id)
		switch id {
		case AckReqId:
			err = adm.asn.Acker.Rx(pdu)
		case BlobId:
			adm.File(pdu)
		default:
			adm.asn.Diag(id)
			err = ErrUnsupported
		}
		pdu.Free()
	}
}

func (adm *Adm) IsAdmin(key *PubEncr) bool {
	return *key == *adm.cmd.Cfg.Keys.Admin.Pub.Encr
}

func (adm *Adm) IsService(key *PubEncr) bool {
	return *key == *adm.cmd.Cfg.Keys.Server.Pub.Encr
}

func (adm *Adm) script() error {
	scanner := bufio.NewScanner(adm.cmd.In)
	for scanner.Scan() {
		if err := adm.cmdLine(scanner.Text()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (adm *Adm) Exec(args ...string) (err error) {
	var pdu *PDU
	for _, arg := range args {
		if arg == "-" {
			f, terr := adm.asn.Repos.Tmp.NewFile()
			if terr != nil {
				err = terr
				return
			}
			pdu = NewPDUFile(f)
			f = nil
			break
		}
	}
	if pdu == nil {
		pdu = NewPDUBuf()
	}
	v := adm.asn.Version()
	v.WriteTo(pdu)
	ExecReqId.Version(v).WriteTo(pdu)
	req := NewRequesterString("exec")
	req.WriteTo(pdu)
	pdu.Write([]byte(strings.Join(args, "\x00")))
	for _, arg := range args {
		if arg == "-" {
			pdu.Write([]byte{0, 0}[:])
			pdu.ReadFrom(adm.cmd.In)
			break
		}
	}
	adm.asn.Diag(ExecReqId, strings.Join(args, " "))
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req Requester, ack *PDU) error {
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		if err == nil {
			adm.asn.Diag("ack")
			ack.WriteTo(adm.cmd.Out)
		} else {
			adm.asn.Diag("nack", err)
		}
		ackCh <- err
		return nil
	})
	adm.asn.Tx(pdu)
	err = <-ackCh
	close(ackCh)
	return
}

func (adm *Adm) Login() (err error) {
	login := NewPDUBuf()
	key := adm.cmd.Cfg.Keys.Admin.Pub.Encr
	sig := adm.cmd.Cfg.Keys.Admin.Sec.Auth.Sign(key[:])
	v := adm.asn.Version()
	v.WriteTo(login)
	LoginReqId.Version(v).WriteTo(login)
	req := NewRequesterString("login")
	req.WriteTo(login)
	login.Write(key[:])
	login.Write(sig[:])
	adm.asn.Diag(LoginReqId, key.String()[:8]+"...",
		sig.String()[:8]+"...")
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req Requester, ack *PDU) error {
		adm.asn.Diag("rx ack of", req)
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		if err == nil {
			adm.asn.Diag("login rekey")
			adm.rekey(ack)
		} else {
			adm.asn.Diag("login", err)
		}
		ackCh <- err
		return nil
	})
	adm.asn.Tx(login)
	err = <-ackCh
	close(ackCh)
	return
}

func (adm *Adm) Pause() (err error) {
	pause := NewPDUBuf()
	v := adm.asn.Version()
	v.WriteTo(pause)
	PauseReqId.Version(v).WriteTo(pause)
	req := NewRequesterString("pause")
	req.WriteTo(pause)
	adm.asn.Diag(PauseReqId)
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req Requester, ack *PDU) error {
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		if err == nil {
			adm.asn.SetStateSuspended()
		}
		ackCh <- err
		return nil
	})
	adm.asn.Tx(pause)
	err = <-ackCh
	close(ackCh)
	return
}

func (adm *Adm) rekey(pdu *PDU) {
	var peer PubEncr
	var nonce Nonce
	pdu.Read(peer[:])
	pdu.Read(nonce[:])
	adm.asn.Diag("new key:", peer)
	adm.asn.Diag("new nonce:", nonce)
	adm.asn.SetBox(NewBox(2, &nonce, &peer,
		adm.ephemeral.pub, adm.ephemeral.sec))
	adm.asn.SetStateEstablished()
}

func (adm *Adm) Resume() (err error) {
	resume := NewPDUBuf()
	v := adm.asn.Version()
	v.WriteTo(resume)
	ResumeReqId.Version(v).WriteTo(resume)
	req := NewRequesterString("resume")
	req.WriteTo(resume)
	adm.asn.Diag(ResumeReqId)
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req Requester, ack *PDU) error {
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		if err == nil {
			adm.rekey(ack)
		}
		ackCh <- err
		return nil
	})
	adm.asn.Tx(resume)
	err = <-ackCh
	close(ackCh)
	return
}

func (adm *Adm) Quit() (err error) {
	quit := NewPDUBuf()
	v := adm.asn.Version()
	v.WriteTo(quit)
	QuitReqId.Version(v).WriteTo(quit)
	req := NewRequesterString("quit")
	req.WriteTo(quit)
	adm.asn.Diag(QuitReqId)
	adm.asn.SetStateQuitting()
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req Requester, ack *PDU) error {
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		ackCh <- err
		return nil
	})
	adm.asn.Tx(quit)
	err = <-ackCh
	close(ackCh)
	return
}
