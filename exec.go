// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
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
  ['~'['*' | '.' | USER]][GLOB][@TIME]
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
		req  Requester
		cmd  [256]byte
		args []string
	)
	const demarcation = "\x00\x00"
	req.ReadFrom(pdu)
	n, err := pdu.Read(cmd[:])
	if err != nil {
		return err
	}
	if i := bytes.Index(cmd[:n], []byte(demarcation)); i > 0 {
		args = strings.Split(string(cmd[:i+1]), "\x00")
		pdu.Rseek(int64((i-n)+len(demarcation)), os.SEEK_CUR)
	} else {
		args = strings.Split(string(cmd[:n]), "\x00")
	}
	ses.ASN.Diagf("exec pdu %p: %v\n", pdu, args)
	go ses.GoExec(req, pdu, args...)
	return nil
}

func (ses *Ses) GoExec(req Requester, pdu *PDU, args ...string) {
	ses.ASN.Ack(req, ses.Exec(req, pdu, args...))
	pdu.Free()
}

func (ses *Ses) Exec(req Requester, r io.Reader,
	args ...string) interface{} {
	switch args[0] {
	case "exec-help", "help":
		return UsageCommands
	case "approve":
		return ses.ExecApprove(r, args[1:]...)
	case "auth":
		return ses.ExecAuth(args[1:]...)
	case "blob":
		return ses.ExecBlob(r, args[1:]...)
	case "cat":
		return ses.ExecCat(req, r, args[1:]...)
	case "clone":
		return ses.ExecClone(args[1:]...)
	case "echo":
		return strings.Join(args[1:], " ") + "\n"
	case "fetch":
		return ses.ExecFetch(r, args[1:]...)
	case "filter":
		return ses.ExecFilter(req, r, args[1:]...)
	case "gc":
		return ses.ExecGC(req, args[1:]...)
	case "iam":
		return ses.ExecIam(args[1:]...)
	case "ls":
		return ses.ExecLS(req, r, args[1:]...)
	case "mark":
		return ses.ExecMark(args[1:]...)
	case "newuser":
		return ses.ExecNewUser(args[1:]...)
	case "objdump":
		return ses.ExecObjDump(r, args[1:]...)
	case "rm":
		return ses.ExecRM(r, args[1:]...)
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
	author := ses.srv.repos.Users.Search(&ses.Keys.Client.Login)
	owner := author
	defer func() {
		author = nil
		owner = nil
	}()
	sums := make(Sums, 0)
	defer func() { sums = nil }()
	err := ses.Blobber(func(fn string) error {
		// Permission to remove is checked in blob.Proc()
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
	return ses.NewBlob(owner, author, "asn/approvals/", sums)
}

func (ses *Ses) ExecAuth(args ...string) interface{} {
	author := ses.srv.repos.Users.Search(&ses.Keys.Client.Login)
	owner := author
	defer func() {
		author = nil
		owner = nil
	}()
	if len(args) > 2 && args[0] == "-u" {
		owner = ses.srv.repos.Users.Search(args[1])
		if owner == nil {
			return ErrNOENT
		}
		args = args[2:]
	}
	if len(args) != 1 {
		return ErrUsageAuth
	}
	if len(args[0]) != (AuthPubSz * 2) {
		return os.ErrInvalid
	}
	authPub, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}
	if len(authPub) != AuthPubSz {
		return os.ErrInvalid
	}
	return ses.NewBlob(owner, author, "asn/auth", authPub)
}

func (ses *Ses) ExecBlob(r io.Reader, args ...string) interface{} {
	author := ses.srv.repos.Users.Search(&ses.Keys.Client.Login)
	owner := author
	defer func() {
		author = nil
		owner = nil
	}()
	if len(args) < 2 {
		return ErrUsageBlob
	}
	name := args[0]
	if args[0][0] == '~' {
		slash := strings.Index(args[0][1:], "/")
		if slash < 0 {
			slash = len(name)
			name = ""
		} else {
			name = args[0][slash+1:]
		}
		owner = ses.srv.repos.Users.Search(args[0][1:slash])
		if owner == nil {
			return ErrNOENT
		}
	}
	if args[1] == "-" {
		Diag.Printf("%T\n", r)
		return ses.NewBlob(owner, author, name, r)
	} else {
		return ses.NewBlob(owner, author, name,
			strings.Join(args[1:], " "))
	}
}

func (ses *Ses) ExecCat(req Requester,
	r io.Reader, args ...string) interface{} {
	if len(args) == 0 {
		return ErrUsageCat
	}
	ack, err := ses.ASN.NewAckSuccessPDUFile(req)
	if err != nil {
		return err
	}
	err = ses.Blobber(func(fn string) error {
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
		after, name = StripTime(args[0])
		if name != "" {
			return ses.execCloneRemote(after, name)
		}
	}
	if dir, err = ioutil.ReadDir(ses.srv.cmd.Cfg.Dir); err != nil {
		return err
	}
	defer func() { dir = nil }()
	for _, fi := range dir {
		if fi.IsDir() && len(fi.Name()) == 2 {
			subdn := filepath.Join(ses.srv.cmd.Cfg.Dir, fi.Name())
			if subdir, err = ioutil.ReadDir(subdn); err != nil {
				return err
			}
			for _, fi := range subdir {
				fn := filepath.Join(subdn, fi.Name())
				if !fi.IsDir() && len(fi.Name()) == fnlen {
					bt := BlobTime(fn)
					if after.IsZero() || bt.After(after) {
						ses.ASN.Tx(NewPDUFN(fn))
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
	ses.srv.ForEachSession(func(x *Ses) {
		if x.name == name {
			remote = x
		}
	})
	if remote == nil {
		return errors.New("no remote session for " + name)
	}
	ls := NewPDUBuf()
	v := ses.ASN.Version()
	v.WriteTo(ls)
	ExecReqId.Version(v).WriteTo(ls)
	req := NextRequester()
	req.WriteTo(ls)
	if after.IsZero() {
		fmt.Fprint(ls, "ls\x00~*")
	} else {
		fmt.Fprintf(ls, "ls\x00~*@%d", after.UnixNano())
	}
	ses.ASN.Acker.Map(req, remote.execCloneLsAck)
	remote.ASN.Tx(ls)
	return nil
}

func (ses *Ses) execCloneLsAck(req Requester, ack *PDU) (err error) {
	ses.ASN.Acker.UnMap(req)
	if err = ses.ASN.ParseAckError(ack); err != nil {
		return
	}
	tmp, err := ses.ASN.Repos.Tmp.NewFile()
	if err != nil {
		return
	}
	fetch := NewPDUFile(tmp)
	v := ses.ASN.Version()
	v.WriteTo(fetch)
	ExecReqId.Version(v).WriteTo(fetch)
	req = NextRequester()
	req.WriteTo(fetch)
	fmt.Fprintf(fetch, "fetch\x00-\x00")
	scanner := bufio.NewScanner(ack)
	for scanner.Scan() {
		fmt.Fprintln(fetch, scanner.Text())
	}
	scanner = nil
	ses.ASN.Acker.Map(req, ses.execCloneFetchAck)
	ses.ASN.Tx(fetch)
	return nil
}

func (ses *Ses) execCloneFetchAck(req Requester, ack *PDU) error {
	ses.ASN.Acker.UnMap(req)
	return ses.ASN.ParseAckError(ack)
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
		ses.ASN.Tx(NewPDUFN(fn))
		return nil
	}, r, args...)
	return err
}

func (ses *Ses) ExecFilter(req Requester,
	r io.Reader, args ...string) interface{} {
	if len(args) < 1 {
		return ErrUsageFilter
	}
	ack, err := ses.ASN.NewAckSuccessPDUFile(req)
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
		Diag.Println("blobArgs:", strings.Join(blobArgs, " "))
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

func (ses *Ses) ExecGC(req Requester, args ...string) interface{} {
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
			after, _ = StripTime(arg)
		} else {
			return ErrUsageGC
		}
	}
	if dryrun || verbose {
		ack, err = ses.ASN.NewAckSuccessPDUFile(req)
		if err != nil {
			return err
		}
	}
	err = ses.srv.repos.Filter(after, func(fn string) error {
		var st syscall.Stat_t
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

func (ses *Ses) ExecLS(req Requester,
	r io.Reader, args ...string) interface{} {
	ack, err := ses.ASN.NewAckSuccessPDUFile(req)
	if err != nil {
		return err
	}
	slogin := ses.Keys.Client.Login.String()
	err = ses.Blobber(func(fn string) error {
		if ref := ses.srv.repos.FN2Ref(slogin, fn); ref != "" {
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

func (ses *Ses) ExecMark(args ...string) interface{} {
	author := ses.srv.repos.Users.Search(&ses.Keys.Client.Login)
	owner := author
	defer func() {
		author = nil
		owner = nil
	}()
	var m Mark
	if len(args) > 2 && args[0] == "-u" {
		owner = ses.srv.repos.Users.Search(args[1])
		if owner == nil {
			return ErrNOENT
		}
		args = args[2:]
	}
	if nargs := len(args); nargs == 1 {
		if len(args[0]) < 6 || args[0][0] != '7' {
			return ErrUsageMark
		}
		place := ses.srv.repos.Users.Search(args[0][2:])
		if place == nil {
			return ErrNOENT
		}
		kplace, err := NewEncrPubString(place.String)
		if err != nil {
			return err
		}
		defer func() { kplace = nil }()
		err = m.SetPlace(owner.Key, kplace, args[0][:2])
		if err != nil {
			return err
		}
	} else if nargs == 2 {
		if err := m.SetLL(owner.Key, args...); err != nil {
			return err
		}
	} else {
		syscall.Unlink(ses.srv.repos.Expand(owner.String, "asn/mark"))
		syscall.Unlink(ses.srv.repos.Expand(owner.String,
			"asn/mark-server"))
		owner.ASN.MarkServer = ""
		return nil
	}
	v := ses.NewBlob(owner, author, "asn/mark", m)
	if err, _ := v.(error); err != nil {
		return err
	}
	if owner.ASN.User != "actual" || owner.ASN.User != "" {
		ses.NewBlob(owner, author, "asn/mark-server",
			ses.srv.cmd.Cfg.Name)
	}
	owner.ASN.MarkServer = ses.srv.cmd.Cfg.Name
	return v
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
	author := ses.srv.repos.Users.Search(&ses.Keys.Client.Login)
	owner := author
	defer func() {
		author = nil
		owner = nil
	}()
	q, err := NewQuad()
	if err != nil {
		return err
	}
	defer func() {
		q.Clean()
		q = nil
	}()
	owner, err = ses.srv.repos.NewUser(q.Pub.Encr.String())
	if err != nil {
		return err
	}
	if author == nil {
		author = owner
	}
	v := ses.NewBlob(owner, author, "asn/auth", []byte(q.Pub.Auth[:]))
	if err, _ := v.(error); err != nil {
		return err
	}
	v = ses.NewBlob(owner, author, "asn/author", []byte(author.Key[:]))
	if err, _ := v.(error); err != nil {
		return err
	}
	v = ses.NewBlob(owner, author, "asn/user", args[0])
	if err, _ := v.(error); err != nil {
		return err
	}
	// copy author also?
	copy(owner.ASN.Auth[:], q.Pub.Auth[:])
	if isBinary {
		// Ack 2 secret keys for new user in binary.
		return append(q.Sec.Encr[:], q.Sec.Auth[:]...)
	}
	out, err := yaml.Marshal(q)
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
	err := ses.Blobber(func(fn string) error {
		f, err := os.Open(fn)
		if err != nil {
			return err
		}
		defer f.Close()
		sum := NewSumOf(f)
		f.Seek(BlobOff, os.SEEK_SET)
		blob, err := NewBlobFrom(f)
		if err != nil {
			return err
		}
		pos, _ := f.Seek(0, os.SEEK_CUR)
		fi, _ := f.Stat()
		fmt.Fprintln(out, "name:", blob.Name)
		fmt.Fprintln(out, "sum:", sum.String())
		fmt.Fprintln(out, "owner:", blob.Owner.String())
		fmt.Fprintln(out, "author:", blob.Author.String())
		fmt.Fprintln(out, "time:", blob.RFC822Z())
		fmt.Fprintln(out, "unix nano:", blob.Time.UnixNano())
		fmt.Fprintln(out, "size:", fi.Size())
		fmt.Fprintln(out, "len:", fi.Size()-pos)
		switch blob.Name {
		case "asn/auth":
			var auth AuthPub
			f.Read(auth[:])
			fmt.Fprintln(out, "asn/auth:", auth.String())
		case "asn/author":
			var author EncrPub
			f.Read(author[:])
			fmt.Fprintln(out, "asn/author:", author.String())
		case MarkFN:
			var m Mark
			m.ReadFrom(f)
			fmt.Fprintln(out, "key:", m.Key.String())
			if m.IsPlace() {
				fmt.Fprintln(out, "place:", m.Place().String())
				if eta := m.ETA(); eta != 0 {
					fmt.Fprintln(out, "eta:", eta)
				}
			} else {
				ll := m.LL()
				fmt.Fprintf(out, "lat: %0.6f\n", ll.Lat)
				fmt.Fprintf(out, "lon: %0.6f\n", ll.Lon)
			}
		case "asn/user":
			fmt.Fprint(out, "asn/user: ")
			io.Copy(out, f)
			fmt.Fprintln(out)
		}
		return nil
	}, r, args...)
	if err != nil {
		out = nil
		return err
	}
	b := out.Bytes()
	out = nil
	return b
}

func (ses *Ses) ExecRM(r io.Reader, args ...string) interface{} {
	buf := &bytes.Buffer{}
	author := ses.srv.repos.Users.Search(&ses.Keys.Client.Login)
	owner := author
	defer func() {
		buf = nil
		author = nil
		owner = nil
	}()
	if len(args) < 1 {
		return ErrUsageRM
	}
	err := ses.Blobber(func(fn string) error {
		fmt.Fprintln(buf, ses.srv.repos.DePrefix(fn))
		return nil
	}, r, args...)
	if err != nil {
		return err
	}
	return ses.NewBlob(owner, author, "asn/removals/", buf)
}

func (ses *Ses) ExecTrace(args ...string) interface{} {
	cmd := "flush"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "flush":
		return TraceFlush
	case "filter", "unfilter", "resize":
		return ErrFIXME
	default:
		return ErrUsageTrace
	}
}

func (ses *Ses) ExecUsers(args ...string) interface{} {
	if len(args) != 0 {
		return ErrUsageUsers
	}
	return ses.srv.repos.Users.LS()
}

func (ses *Ses) ExecVouch(args ...string) interface{} {
	if len(args) != 2 {
		return ErrUsageVouch
	}
	author := ses.srv.repos.Users.Search(&ses.Keys.Client.Login)
	owner := ses.srv.repos.Users.Search(args[0])
	if owner == nil {
		return ErrNOENT
	}
	defer func() {
		author = nil
		owner = nil
	}()
	sig, err := hex.DecodeString(args[1])
	if err != nil {
		return err
	}
	if len(sig) != AuthSigSz {
		return os.ErrInvalid
	}
	return ses.NewBlob(owner, author, "asn/vouchers/", sig)
}

func (ses *Ses) ExecWho(req Requester, args ...string) interface{} {
	if len(args) != 0 {
		return ErrUsageWho
	}
	ack, err := ses.ASN.NewAckSuccessPDUFile(req)
	if err != nil {
		return err
	}
	ses.srv.ForEachSession(func(x *Ses) {
		if x.name != "" {
			fmt.Fprintln(ack, x.name)
		} else {
			fmt.Fprintln(ack, x.Keys.Client.Login.String()[:16])
		}
	})
	return ack
}

func (ses *Ses) Blobber(f func(fn string) error, r io.Reader,
	args ...string) (err error) {
	repos := ses.srv.repos
	name := ses.srv.cmd.Cfg.Name
	login := repos.Users.Search(&ses.Keys.Client.Login)
	var (
		after     time.Time
		glob      string
		mustExist bool
	)
	uf := func(u *ReposUser) error {
		if u == nil {
			return ErrNOENT
		}
		xn := repos.Expand(u.String, glob)
		matches, err := filepath.Glob(xn)
		if err != nil {
			return err
		}
		if len(matches) == 0 && mustExist {
			return os.ErrNotExist
		}
		for _, match := range matches {
			if err = BlobFilter(match, after, f); err != nil {
				return err
			}
		}
		return nil
	}
	if len(args) == 0 {
		args = []string{""}
	}
	for _, arg := range args {
		after, arg = StripTime(arg)
		_, staterr := os.Stat(arg)
		slash := strings.Index(arg, "/")
		switch {
		default:
			glob, mustExist = arg, true
			err = uf(login)
		case arg == "", arg == "~", arg == "*":
			glob, mustExist = "*", false
			err = uf(login)
		case arg[0:2] == "~/":
			glob, mustExist = arg[2:], true
			err = uf(login)
		case arg == "-":
			err = ses.blobberRecurse(f, r)
		case arg == "$*":
			err = repos.Filter(after, f)
		case arg[0] == '$':
			match, err := repos.Search(arg[1:])
			if err == nil {
				if match == "" {
					err = ErrNOENT
				} else {
					err = BlobFilter(match, after, f)
				}
			}
		case arg == "~*":
			glob, mustExist = "*", false
			err = repos.Users.ForEachUser(uf)
		case arg == "~.":
			glob, mustExist = "*", false
			err = repos.Users.ForEachUserOn(name, uf)
		case arg[0:3] == "~*/":
			glob, mustExist = arg[3:], false
			err = repos.Users.ForEachUser(uf)
		case arg[0:3] == "~./":
			glob, mustExist = arg[3:], false
			err = repos.Users.ForEachUserOn(name, uf)
		case arg[0] == '~' && slash < 0:
			glob, mustExist = "*", true
			err = uf(repos.Users.Search(arg[1:]))
		case arg[0] == '~' && slash > 0:
			glob, mustExist = arg[slash+1:], true
			err = uf(repos.Users.Search(arg[1:slash]))
		case staterr == nil:
			err = BlobFilter(arg, after, f)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// blobberRecurse reruns Blobber with reference of each input line.
func (ses *Ses) blobberRecurse(f func(fn string) error, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		xarg := scanner.Text()
		if xarg != "-" { // only one level recursion
			err := ses.Blobber(f, nil, xarg)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (ses *Ses) NewBlob(owner, author *ReposUser, name string,
	v interface{}) interface{} {
	blob := NewBlob(owner.Key, author.Key, name)
	defer func() {
		blob.Free()
		blob = nil
	}()
	sum, fn, err := ses.srv.repos.File(blob, v)
	if err != nil {
		Diag.Println(err)
		return err
	}
	links, err := ses.srv.repos.MkLinks(blob, sum, fn)
	if err != nil {
		Diag.Println(err)
		return err
	}
	ses.removals(links)
	ses.dist(links)
	links = nil
	return sum
}

// StripTime removes '@TIME' argument suffixes
func StripTime(arg string) (t time.Time, argWoTime string) {
	argWoTime = arg
	if at := strings.Index(arg, "@"); at >= 0 {
		var nano int64
		argWoTime = arg[:at]
		d, err := time.ParseDuration(arg[at+1:])
		if err == nil {
			if d > 0 {
				d = -d
			}
			t = time.Now().Add(d)
			Diag.Println(t.Format(time.RFC3339))
			return
		}
		n, err := fmt.Sscan(arg[at+1:], &nano)
		if n == 1 && err == nil {
			isec := int64(time.Second)
			t = time.Unix(nano/isec, nano%isec)
			Diag.Println(t.Format(time.RFC3339))
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
				Diag.Println(t.Format(time.RFC3339))
				return
			}
		}
	}
	return
}
