// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/apptimistco/asn/debug"
	"gopkg.in/yaml.v1"
)

const (
	UsageApprove = `approve BLOB...`
	UsageAuth    = `auth [-u USER] AUTH`
	UsageBlob    = `blob <USER|[USER/]NAME> - CONTENT`
	UsageCat     = `cat BLOB...`
	UsageClone   = `clone [NAME][@TIME]`
	UsageEcho    = `echo [STRING]...`
	UsageFetch   = `fetch BLOB...`
	UsageFilter  = `filter FILTER [ARGS... --] [BLOB...]`
	UsageGC      = `gc [-v|--verbose] [-n|--dry-run] [@TIME]`
	UsageIam     = `iam NAME`
	UsageLS      = `ls [BLOB...]`
	UsageMark    = `mark [-u USER] [LATITUDE LONGITUDE | 7?PLACE]`
	UsageNewUser = `newuser [-b] <"actual"|"bridge"|"forum"|"place">`
	UsageObjDump = `objdump BLOB...`
	UsageRM      = `rm BLOB...`
	UsageTrace   = `trace [COMMAND [ARG]]`
	UsageUsers   = `users`
	UsageVouch   = `vouch USER SIG`
	UsageWho     = `who`

	UsageCommands = `Commands:

  ` + UsageApprove + `
	Before acknowledgment, the server forwards the matching blobs
	to its owner or subscriber.
  ` + UsageAuth + `
	Record user's ED255519 authentication key.
  ` + UsageBlob + `
	Creates named blob.
  ` + UsageCat + `
	Returns the contents of the named blob.
  ` + UsageClone + `
	Replicate or update an object repository.
  ` + UsageEcho + `
	Returns space separated ARGS in the Ack data.
  ` + UsageFilter + `
	Returns STDOUT of FILTER program run with list of blobs as STDIN.
  ` + UsageFetch + `
	Before acknowledgement the server sends all matching blobs.
  ` + UsageGC + `
	Before acknowledgement the server purges older or all blobs
	flagged for deletion.
  ` + UsageIam + `
        Show NAME instead of LOGIN key in list of Who.
	Used by servers in indirect clone request.
  ` + UsageLS + `
	Returns list of matching blobs.
  ` + UsageMark + `
	Record user's location.
  ` + UsageNewUser + `
	Creates a new user and return keys in acknowledgment.
  ` + UsageObjDump + `
	Returns the decoded header of the named blob
  ` + UsageRM + `
	Flag blobs for removal by garbage collector.
  ` + UsageTrace + `
	Return and flush the PDU trace or manipulate its filter.
  ` + UsageUsers + `
	List all users.
  ` + UsageVouch + `
	Vouch for or deny USER's identity.
  ` + UsageWho + `
	List logged in user names, if set, or login key.

Where BLOB may be any of the following:

  -
  '$'<'*' | SUM>[@TIME]
  ['~'['*' | '.' | '(' USERGLOB ')' | USER]][GLOB][@TIME]
`
)

var (
	ErrUsageApprove = errors.New("usage: " + UsageApprove)
	ErrUsageAuth    = errors.New("usage: " + UsageAuth)
	ErrUsageBlob    = errors.New("usage: " + UsageBlob)
	ErrUsageCat     = errors.New("usage: " + UsageCat)
	ErrUsageClone   = errors.New("usage: " + UsageClone)
	ErrUsageEcho    = errors.New("usage: " + UsageEcho)
	ErrUsageFetch   = errors.New("usage: " + UsageFetch)
	ErrUsageFilter  = errors.New("usage: " + UsageFilter)
	ErrUsageGC      = errors.New("usage: " + UsageGC)
	ErrUsageIam     = errors.New("usage: " + UsageIam)
	ErrUsageLS      = errors.New("usage: " + UsageLS)
	ErrUsageMark    = errors.New("usage: " + UsageMark)
	ErrUsageNewUser = errors.New("usage: " + UsageNewUser)
	ErrUsageObjDump = errors.New("usage: " + UsageObjDump)
	ErrUsageRM      = errors.New("usage: " + UsageRM)
	ErrUsageTrace   = errors.New("usage: " + UsageTrace)
	ErrUsageUsers   = errors.New("usage: " + UsageUsers)
	ErrUsageVouch   = errors.New("usage: " + UsageVouch)
	ErrUsageWho     = errors.New("usage: " + UsageWho)
	ErrFIXME        = errors.New("FIXME")
	ErrCantExec     = errors.New("asnsrv can't exec this command")
)

func (ses *Ses) RxExec(pdu *PDU) error {
	var (
		req  Req
		cmd  [256]byte
		args []string
	)
	req.ReadFrom(pdu)
	n, err := pdu.Read(cmd[:])
	if err != nil {
		return err
	}
	const demarcation = "\x00\x00"
	dem := bytes.Index(cmd[:n], []byte(demarcation))
	if dem < 0 && n == len(cmd) {
		err := errors.New("command too long")
		ses.Diag(err)
		ses.asn.Ack(req, err)
		return nil
	}
	if dem > 0 {
		args = strings.Split(string(cmd[:dem+1]), "\x00")
		pdu.Rseek(int64((dem-n)+len(demarcation)), os.SEEK_CUR)
	} else {
		args = strings.Split(string(cmd[:n]), "\x00")
	}
	pdu.Clone()
	ses.Lock()
	go ses.GoExec(req, pdu, args...)
	return nil
}

func (ses *Ses) GoExec(req Req, pdu *PDU, args ...string) {
	ses.asn.Ack(req, ses.Exec(req, pdu, args...))
	pdu.Free()
	ses.Unlock()
}

func (ses *Ses) Exec(req Req, in ReadWriteToer, args ...string) interface{} {
	ses.asn.Trace(debug.Id(ExecReqId), "rx", req, "exec", args)
	switch args[0] {
	case "exec-help", "help":
		return UsageCommands
	case "approve":
		return ses.ExecApprove(in, args[1:]...)
	case "auth":
		return ses.ExecAuth(args[1:]...)
	case "blob":
		return ses.ExecBlob(in, args[1:]...)
	case "cat":
		return ses.ExecCat(req, in, args[1:]...)
	case "clone":
		return ses.ExecClone(args[1:]...)
	case "echo":
		return strings.Join(args[1:], " ") + "\n"
	case "fetch":
		return ses.ExecFetch(in, args[1:]...)
	case "filter":
		return ses.ExecFilter(req, in, args[1:]...)
	case "gc":
		return ses.ExecGC(req, args[1:]...)
	case "iam":
		return ses.ExecIam(args[1:]...)
	case "ls":
		return ses.ExecLS(req, in, args[1:]...)
	case "mark":
		return ses.ExecMark(args[1:]...)
	case "newuser":
		return ses.ExecNewUser(args[1:]...)
	case "objdump":
		return ses.ExecObjDump(in, args[1:]...)
	case "rm":
		return ses.ExecRM(in, args[1:]...)
	case "trace":
		return ses.ExecTrace(args[1:]...)
	case "users":
		return ses.ExecUsers(args[1:]...)
	case "vouch":
		return ses.ExecVouch(args[1:]...)
	case "who":
		return ses.ExecWho(req, args[1:]...)
	default:
		return errors.New("unknown exec command: " + args[0])
	}
}

func (ses *Ses) ExecApprove(r io.Reader, args ...string) interface{} {
	if len(args) < 1 {
		return ErrUsageApprove
	}
	owner := ses.user
	sums := make(Sums, 0)
	defer func() { sums = nil }()
	err := ses.Blobber(func(fn string) error {
		// Permission to remove is checked in repos.ProcSums()
		f, err := os.Open(fn)
		if err != nil {
			return err
		}
		defer f.Close()
		sums = append(sums, *NewSumOf(f))
		return nil
	}, r, args...)
	if err != nil {
		return err
	}
	sum, err := ses.Store(owner, ses.user, AsnApprovals+"/", sums)
	if err != nil {
		return err
	}
	return sum
}

func (ses *Ses) ExecAuth(args ...string) interface{} {
	owner := ses.user
	if len(args) > 2 && args[0] == "-u" {
		owner = ses.asn.repos.users.UserString(args[1])
		if owner == nil {
			return ErrNOENT
		}
		args = args[2:]
	}
	if len(args) != 1 {
		return ErrUsageAuth
	}
	if len(args[0]) != (PubAuthSz * 2) {
		return os.ErrInvalid
	}
	authPub, err := NewPubAuthString(args[0])
	if err != nil {
		return err
	}
	if len(authPub) != PubAuthSz {
		return os.ErrInvalid
	}
	sum, err := ses.Store(owner, ses.user, AsnAuth, authPub)
	if err != nil {
		return err
	}
	return sum
}

func (ses *Ses) ExecBlob(in ReadWriteToer, args ...string) interface{} {
	owner := ses.user
	if len(args) < 2 {
		return ErrUsageBlob
	}
	name := args[0]
	if args[0][0] == '~' {
		slash := strings.Index(args[0][:], "/")
		if slash < 0 {
			slash = len(name)
			name = ""
		} else {
			name = args[0][slash+1:]
		}
		owner = ses.asn.repos.users.UserString(args[0][1:slash])
		if owner == nil {
			return ErrNOENT
		}
	}
	var sum *Sum
	svc := ses.cfg.Keys
	err := ses.asn.repos.Permission(owner, ses.user, svc, name)
	if err != nil {
		return err
	}
	if args[1] == "-" {
		ses.asn.Diagf("%T\n", in)
		sum, err = ses.Store(owner, ses.user, name, in)
	} else {
		sum, err = ses.Store(owner, ses.user, name,
			bytes.NewBufferString(strings.Join(args[1:], " ")))
	}
	if err != nil {
		return err
	}
	return sum
}

func (ses *Ses) ExecCat(req Req, r io.Reader, args ...string) interface{} {
	if len(args) == 0 {
		return ErrUsageCat
	}
	ack, err := ses.asn.NewAckSuccessPDUFile(req)
	if err != nil {
		return err
	}
	err = ses.Blobber(func(fn string) error {
		if strings.HasSuffix(fn, filepath.FromSlash(AsnMark)) {
			user, _ := ses.asn.repos.ParsePath(fn)
			if user == nil {
				return os.ErrNotExist
			}
			_, err := user.cache.Mark().WriteTo(ack)
			return err
		}
		f, err := os.Open(fn)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err = BlobSeek(f); err != nil {
			return err
		}
		ack.ReadFrom(f)
		return nil
	}, r, args...)
	if err != nil {
		ack.Free()
		ack = nil
		return err
	}
	return ack
}

func (ses *Ses) ExecClone(args ...string) interface{} {
	if ses.asnsrv {
		return ErrCantExec
	}
	var (
		err   error
		after time.Time

		dir, subdir []os.FileInfo
	)
	const fnlen = (SumSz - 1) * 2
	nargs := len(args)
	if nargs > 1 {
		return ErrUsageClone
	} else if nargs == 1 {
		var name string
		after, name = ses.StripTime(args[0])
		if name != "" {
			return ses.execCloneRemote(after, name)
		}
	}
	if dir, err = ioutil.ReadDir(ses.cfg.Dir); err != nil {
		return err
	}
	defer func() { dir = nil }()
	for _, fi := range dir {
		if fi.IsDir() && len(fi.Name()) == 2 {
			subdn := filepath.Join(ses.cfg.Dir, fi.Name())
			if subdir, err = ioutil.ReadDir(subdn); err != nil {
				return err
			}
			for _, fi := range subdir {
				fn := filepath.Join(subdn, fi.Name())
				if !fi.IsDir() && len(fi.Name()) == fnlen {
					bt := BlobTime(fn)
					if after.IsZero() || bt.After(after) {
						ses.asn.Tx(NewPDUFN(fn))
					}
				}
			}
			subdir = nil
		}
	}
	return nil
}

func (ses *Ses) execCloneRemote(after time.Time, name string) interface{} {
	var remote *Ses
	ses.ForEachLogin(func(x *Ses) {
		if x.name == name {
			remote = x
		}
	})
	if remote == nil {
		return errors.New("no remote session for " + name)
	}
	ls := NewPDUBuf()
	v := ses.asn.Version()
	v.WriteTo(ls)
	ExecReqId.Version(v).WriteTo(ls)
	req := NextReq()
	req.WriteTo(ls)
	if after.IsZero() {
		fmt.Fprint(ls, "ls\x00~*")
	} else {
		fmt.Fprintf(ls, "ls\x00~*@%d", after.UnixNano())
	}
	ses.asn.acker.Map(req, remote.execCloneLsAck)
	remote.asn.Tx(ls)
	return nil
}

func (ses *Ses) execCloneLsAck(req Req, err error, ack *PDU) error {
	ses.asn.acker.UnMap(req)
	if err != nil {
		return err
	}
	fetch := NewPDUFile(ses.asn.repos.tmp.New())
	v := ses.asn.Version()
	v.WriteTo(fetch)
	ExecReqId.Version(v).WriteTo(fetch)
	req = NextReq()
	req.WriteTo(fetch)
	fmt.Fprintf(fetch, "fetch\x00-\x00")
	scanner := bufio.NewScanner(ack)
	for scanner.Scan() {
		fmt.Fprintln(fetch, scanner.Text())
	}
	scanner = nil
	ses.asn.acker.Map(req, ses.execCloneFetchAck)
	ses.asn.Tx(fetch)
	return nil
}

func (ses *Ses) execCloneFetchAck(req Req, err error, ack *PDU) error {
	ses.asn.acker.UnMap(req)
	return err
}

func (ses *Ses) ExecFetch(r io.Reader, args ...string) interface{} {
	var err error
	if len(args) < 1 {
		return ErrUsageFetch
	}
	if ses.asnsrv {
		return ErrCantExec
	}
	err = ses.Blobber(func(fn string) error {
		if strings.HasSuffix(fn, filepath.FromSlash(AsnMark)) {
			user, _ := ses.asn.repos.ParsePath(fn)
			if user == nil {
				ses.asn.Diag("no user for", fn)
				return os.ErrNotExist
			}
			pdu := NewPDUBuf()
			NewFH(&ses.user.key,
				ses.cfg.Keys.Server.Pub.Encr,
				AsnMark).WriteTo(pdu)
			user.cache.Mark().WriteTo(pdu)
			ses.asn.Fixme("sent cached", fn)
			ses.asn.Tx(pdu)
			return nil
		}
		ses.asn.Tx(NewPDUFN(fn))
		return nil
	}, r, args...)
	return err
}

func (ses *Ses) ExecFilter(req Req, r io.Reader, args ...string) interface{} {
	if len(args) < 1 {
		return ErrUsageFilter
	}
	ack, err := ses.asn.NewAckSuccessPDUFile(req)
	if err != nil {
		return err
	}
	filterArgs := []string{}
	blobArgs := args[1:]
	for i, arg := range args[1:] {
		if arg == "--" {
			filterArgs = args[1:i]
			blobArgs = args[i+1:]
		}
	}
	cmd := exec.Command(args[0], filterArgs...)
	cmdStdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmdStdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmdStderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	var errbuf []byte
	blobberErr := make(chan error, 1)
	outDone := make(chan bool, 1)
	errDone := make(chan bool, 1)
	go func() {
		defer cmdStdin.Close()
		ses.asn.Diag("blobArgs:", strings.Join(blobArgs, " "))
		blobberErr <- ses.Blobber(func(fn string) error {
			fmt.Fprintln(cmdStdin, fn)
			return nil
		}, r, blobArgs...)

	}()
	go func() {
		ack.ReadFrom(cmdStdout)
		outDone <- true
	}()
	go func() {
		errbuf, _ = ioutil.ReadAll(cmdStderr)
		errDone <- true
	}()
	<-outDone
	<-errDone
	if err = cmd.Wait(); err != nil {
		ack.Free()
		return errors.New(string(errbuf))
	}
	if err = <-blobberErr; err != nil {
		ack.Free()
		return err
	}
	return ack
}

func (ses *Ses) ExecGC(req Req, args ...string) interface{} {
	var (
		err     error
		after   time.Time
		verbose bool
		dryrun  bool
		ack     *PDU
	)
	for _, arg := range args {
		if arg == "-v" || arg == "--verbose" {
			verbose = true
		} else if arg == "-n" || arg == "--dry-run" {
			dryrun = true
		} else if strings.HasPrefix(arg, "@") {
			after, _ = ses.StripTime(arg)
		} else {
			return ErrUsageGC
		}
	}
	if dryrun || verbose {
		ack, err = ses.asn.NewAckSuccessPDUFile(req)
		if err != nil {
			return err
		}
	}
	err = ses.asn.repos.Filter(after, func(fn string) error {
		var st syscall.Stat_t
		if strings.HasSuffix(fn, filepath.FromSlash(AsnMark)) {
			return nil
		}
		if err := syscall.Stat(fn, &st); err != nil {
			return err
		}
		if st.Nlink == 1 {
			if verbose {
				fmt.Fprintf(ack, "removed `%s'\n", fn)
			}
			if dryrun {
				fmt.Fprintf(ack, "Would removed `%s'\n", fn)
			} else {
				syscall.Unlink(fn)
			}
		}
		return nil
	})
	if err != nil {
		ack.Free()
		ack = nil
		return err
	}
	return ack
}

func (ses *Ses) ExecIam(args ...string) interface{} {
	if len(args) != 1 {
		return ErrUsageIam
	}
	ses.name = args[0]
	return nil
}

func (ses *Ses) ExecLS(req Req,
	r io.Reader, args ...string) interface{} {
	ack, err := ses.asn.NewAckSuccessPDUFile(req)
	if err != nil {
		return err
	}
	slogin := ses.Keys.Client.Login.FullString()
	err = ses.Blobber(func(fn string) error {
		if ref := ses.asn.repos.FN2Ref(slogin, fn); ref != "" {
			fmt.Fprintln(ack, ref)
		}
		return nil
	}, r, args...)
	if err != nil {
		ack.Free()
		ack = nil
		return err
	}
	return ack
}

// ExecMark without args (or just -u USER) sets the login or given
// user sets mark to { 0.0, 0.0 } (in the Gulf of Guinea)
func (ses *Ses) ExecMark(args ...string) interface{} {
	var err error
	defer func() {
		if err != nil {
			ses.asn.Diag(debug.Depth(2), err)
		}
	}()
	user := ses.user
	if len(args) >= 2 && args[0] == "-u" {
		user = ses.asn.repos.users.UserString(args[1])
		if user == nil {
			err = ErrNOENT
			return err
		}
		args = args[2:]
	}
	switch len(args) {
	default:
		if err = os.ErrInvalid; err != nil {
			return err
		}
	case 0:
		if err = user.cache.Mark().Set(MarkLoc{}); err != nil {
			return err
		}
	case 1:
		if err = user.cache.Mark().Set(args[0]); err != nil {
			return err
		}
	case 2:
		var loc *MarkLoc
		if loc, err = NewMarkLoc(args...); err != nil {
			return err
		} else if err = user.cache.Mark().Set(loc); err != nil {
			return err
		}
	}
	user.cache[AsnMark].Set(ses.asn.time.out)
	var sum *Sum
	b := &bytes.Buffer{}
	b.Write(user.key[:MarkeySz])
	b.Write(user.cache.Mark().Bytes())
	sum, err = ses.Store(user, ses.user, AsnMark, b)
	if err != nil {
		return err
	}
	return sum
}

func (ses *Ses) ExecNewUser(args ...string) interface{} {
	if len(args) < 1 {
		return ErrUsageNewUser
	}
	isBinary := args[0] == "-b"
	if isBinary {
		args = args[1:]
	}
	if len(args) != 1 {
		return ErrUsageNewUser
	}
	owner := ses.user
	k, err := NewRandomUserKeys()
	if err != nil {
		return err
	}
	defer func() {
		k.Free()
	}()
	author := ses.user
	owner, err = ses.asn.repos.NewUser(k.Pub.Encr)
	if err != nil {
		return err
	}
	if author == nil {
		author = owner
	}
	_, err = ses.Store(owner, ses.user, AsnAuth, k.Pub.Auth)
	if err != nil {
		return err
	}
	_, err = ses.Store(owner, ses.user, AsnAuthor, &author.key)
	if err != nil {
		return err
	}
	_, err = ses.Store(owner, ses.user, AsnUser,
		bytes.NewBufferString(args[0]))
	if err != nil {
		return err
	}
	// copy author also?
	owner.cache.Auth().Set(k.Pub.Auth)
	if isBinary {
		// Ack keys for new user in binary.
		out := append(k.Sec.Encr[:], k.Sec.Auth.Bytes()...)
		out = append(out, k.Pub.Encr.Bytes()...)
		out = append(out, k.Pub.Auth.Bytes()...)
		return out
	}
	out, err := yaml.Marshal(k)
	if err != nil {
		return err
	}
	return out
}

func (ses *Ses) ExecObjDump(r io.Reader, args ...string) interface{} {
	out := &bytes.Buffer{}
	if len(args) < 1 {
		return ErrUsageObjDump
	}
	if err := ses.Blobber(func(fn string) (err error) {
		defer func() {
			if err != nil {
				ses.asn.Diag(debug.Depth(2), err)
			}
		}()
		f, err := os.Open(fn)
		if err != nil {
			return
		}
		defer f.Close()
		sum := NewSumOf(f)
		f.Seek(BlobMagicOff, os.SEEK_SET)
		blob, err := NewBlobFrom(f)
		if err != nil {
			return
		}
		pos, _ := f.Seek(0, os.SEEK_CUR)
		fi, _ := f.Stat()
		fmt.Fprintln(out, "sum:", sum)
		fmt.Fprintln(out, blob)
		switch blob.Name {
		case AsnAuth:
			var auth PubAuth
			f.Read(auth[:])
			fmt.Fprintln(out, "auth:", auth)
		case AsnAuthor:
			var author PubEncr
			f.Read(author[:])
			fmt.Fprintln(out, "author:", author)
		case AsnMark:
			var mark Mark
			mark.ReadFrom(f)
			fmt.Fprintln(out, &mark)
		case AsnUser:
			fmt.Fprintf(out, "user: ")
			io.Copy(out, f)
			fmt.Fprintln(out)
		default:
			fmt.Fprintln(out, "size:", fi.Size())
			fmt.Fprintln(out, "len:", fi.Size()-pos)
		}
		return
	}, r, args...); err != nil {
		ses.asn.Diag(err)
		out = nil
		return err
	}
	return out
}

func (ses *Ses) ExecRM(r io.Reader, args ...string) interface{} {
	buf := &bytes.Buffer{}
	owner := ses.user
	if len(args) < 1 {
		return ErrUsageRM
	}
	err := ses.Blobber(func(fn string) error {
		fmt.Fprintln(buf, ses.asn.repos.DePrefix(fn))
		return nil
	}, r, args...)
	if err != nil {
		return err
	}
	sum, err := ses.Store(owner, ses.user, AsnRemovals, buf)
	if err != nil {
		return err
	}
	return sum
}

func (ses *Ses) ExecTrace(args ...string) interface{} {
	cmd := "flush"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "flush":
		return debug.Trace
	case "filter", "unfilter", "resize":
		ses.asn.Fixme(cmd)
		return ErrFIXME
	default:
		return ErrUsageTrace
	}
}

func (ses *Ses) ExecUsers(args ...string) interface{} {
	if len(args) != 0 {
		return ErrUsageUsers
	}
	return ses.asn.repos.users.LS()
}

func (ses *Ses) ExecVouch(args ...string) interface{} {
	if len(args) != 2 {
		return ErrUsageVouch
	}
	owner := ses.asn.repos.users.UserString(args[0])
	if owner == nil {
		return ErrNOENT
	}
	sig, err := NewSignatureString(args[1])
	if err != nil {
		return err
	}
	sum, err := ses.Store(owner, ses.user, AsnVouchers, sig)
	if err != nil {
		return err
	}
	return sum
}

func (ses *Ses) ExecWho(req Req, args ...string) interface{} {
	if len(args) != 0 {
		return ErrUsageWho
	}
	ack, err := ses.asn.NewAckSuccessPDUFile(req)
	if err != nil {
		return err
	}
	ses.ForEachLogin(func(x *Ses) {
		if x.name != "" {
			fmt.Fprintln(ack, x.name)
		} else {
			fmt.Fprintln(ack, &x.Keys.Client.Login)
		}
	})
	return ack
}

func (ses *Ses) Blobber(filter func(fn string) error, r io.Reader,
	args ...string) (err error) {
	var this time.Time
	var umatch, glob string
	var mustExist bool
	var scanner *bufio.Scanner
	repos := ses.asn.repos
	filterIfNewer := func(fn string) error {
		if this.IsZero() {
			return filter(fn)
		} else if fh, err := ReadFileHeader(fn); err != nil {
			return err
		} else if fh.Blob.Time.After(this) {
			return filter(fn)
		}
		return nil
	}
	walker := func(fn string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			return filterIfNewer(fn)
		}
		return err
	}
	uf := func(u *User) error {
		if u == nil {
			return ErrNOENT
		}
		if umatch != "" {
			uglob := repos.Join(u.Join(umatch))
			matches, err := filepath.Glob(uglob)
			if err != nil {
				return err
			}
			if len(matches) == 0 {
				return nil
			}
			matches = nil
		}
		matches, err := filepath.Glob(repos.Join(u.Join(glob)))
		defer func() { matches = nil }()
		if err != nil {
			return err
		}
		if len(matches) == 0 && mustExist {
			return os.ErrNotExist
		}
		for _, match := range matches {
			if err = filepath.Walk(match, walker); err != nil {
				return err
			}
		}
		return err
	}
	if len(args) == 0 {
		args = []string{""}
	}
	for err == nil {
		var arg string
		umatch, glob, mustExist = "", "", false
		if scanner != nil {
			if !scanner.Scan() {
				scanner = nil
				continue
			}
			arg = scanner.Text()
		} else if len(args) == 0 {
			break
		} else {
			arg = args[0]
			args = args[1:]
		}
		this, arg = ses.StripTime(arg)
		fi, staterr := os.Stat(arg)
		if arg == "asn" && !fi.IsDir() {
			fi = nil
		}
		slash := strings.Index(arg, "/")
		closeParen := strings.Index(arg, ")")
		switch {
		default:
			glob, mustExist = arg, true
			err = uf(ses.user)
		case staterr == nil && fi != nil:
			err = filterIfNewer(arg)
		case arg == "-":
			scanner = bufio.NewScanner(r)
		case arg == "", arg == "~", arg == "*":
			glob = "*"
			err = uf(ses.user)
		case arg[0:2] == "~/":
			glob, mustExist = arg[2:], true
			err = uf(ses.user)
		case arg == "$*":
			err = repos.Filter(this, filter)
		case arg[0] == '$':
			match, err := repos.Search(arg[1:])
			if err == nil {
				if match == "" {
					err = ErrNOENT
				} else {
					err = filepath.Walk(match, walker)
				}
			}
		case arg == "~*":
			glob = "*"
			err = repos.users.ForEachUser(uf)
		case arg[0:3] == "~*/":
			glob = arg[3:]
			err = repos.users.ForEachUser(uf)
		case arg == "~.":
			glob = "*"
			err = repos.users.ForEachLoggedInUser(uf)
		case arg[0:3] == "~./":
			glob = arg[3:]
			err = repos.users.ForEachLoggedInUser(uf)
		case arg[0:2] == "~(" && closeParen > 0:
			umatch, glob = arg[2:closeParen], arg[closeParen+1:]
			err = repos.users.ForEachLoggedInUser(uf)
		case arg[0] == '~' && slash < 0:
			glob, mustExist = "*", true
			err = uf(repos.users.UserString(arg[1:]))
		case arg[0] == '~' && slash > 0:
			glob, mustExist = arg[slash+1:], true
			err = uf(repos.users.UserString(arg[1:slash]))
		}
	}
	return
}

func (ses *Ses) Store(owner, author *User, name string, wt WriteToer) (*Sum,
	error) {
	blob := NewBlobWith(&owner.key, &author.key, name, ses.asn.time.out)
	defer blob.Free()
	return ses.asn.repos.Store(ses, Latest, blob, wt)
}

// StripTime removes '@TIME' argument suffixes
func (ses *Ses) StripTime(arg string) (t time.Time, argWoTime string) {
	argWoTime = arg
	if at := strings.Index(arg, "@"); at >= 0 {
		var nano int64
		argWoTime = arg[:at]
		if arg[at+1] == '+' || arg[at+1] == '-' {
			d, err := time.ParseDuration(arg[at+2:])
			if err != nil {
				ses.asn.Diag("invalid duration:", err)
				return
			}
			if arg[at+1] == '-' {
				d = -d
			}
			t = time.Now().Add(d)
			return
		}
		n, err := fmt.Sscan(arg[at+1:], &nano)
		if n == 1 && err == nil {
			isec := int64(time.Second)
			t = time.Unix(nano/isec, nano%isec)
			return
		}
		for _, layout := range []string{
			time.ANSIC,
			time.RubyDate,
			time.UnixDate,
			time.RFC822Z,
			time.RFC822,
			time.RFC850,
			time.RFC1123Z,
			time.RFC1123,
			time.RFC3339Nano,
			time.RFC3339,
		} {
			pt, err := time.Parse(layout, arg[at+1:])
			if err == nil {
				t = pt
				return
			}
		}
	}
	return
}
