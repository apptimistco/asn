// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/apptimistco/asn"
	"gopkg.in/yaml.v1"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	BlobArg = `<FILE|SHA|USER[@EPOCH]|[USER]@EPOCH|[USER/]NAME[@EPOCH]>`

	UsageApprove = `approve SUM...`
	UsageAuth    = `auth [-u USER] AUTH`
	UsageBlob    = `blob <USER|[USER/]NAME> - CONTENT`
	UsageCat     = `cat ` + BlobArg + `...`
	UsageClone   = `clone [URL|MIRROR][@EPOCH]`
	UsageEcho    = `echo [STRING]...`
	UsageFetch   = `fetch ` + BlobArg + `...`
	UsageGC      = `gc [-v] [@EPOCH]`
	UsageLS      = `ls ` + BlobArg + `...`
	UsageMark    = `mark [-u USER] <LATITUDE LONGITUDE>|<7?PLACE>`
	UsageNewUser = `newuser <"actual"|"bridge"|"forum"|"place">`
	UsageObjDump = `objdump ` + BlobArg + `...`
	UsageRM      = `rm ` + BlobArg + `...`
	UsageScan    = `scan LATITUDE LONGITUDE RANGE`
	UsageTrace   = `trace [COMMAND [ARG]]`
	UsageVouch   = `vouch USER SIG`

	HelpExec = `ASN exec commands:
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
    ` + UsageFetch + `
	Before acknowledgement the server sends all matching blobs.
    ` + UsageGC + `
	Before acknowledgement the server purges older or all blobs
	flagged for deletion.
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
    ` + UsageScan + `
	Requests matching MARK blobs.
    ` + UsageTrace + `
	Return and flush the PDU trace or manipulate its filter.
    ` + UsageVouch + `
	Vouch for or deny USER's identity.
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
	ErrUsageGC      = errors.New("usage: " + UsageGC)
	ErrUsageLS      = errors.New("usage: " + UsageLS)
	ErrUsageMark    = errors.New("usage: " + UsageMark)
	ErrUsageNewUser = errors.New("usage: " + UsageNewUser)
	ErrUsageObjDump = errors.New("usage: " + UsageObjDump)
	ErrUsageRM      = errors.New("usage: " + UsageRM)
	ErrUsageScan    = errors.New("usage: " + UsageScan)
	ErrUsageTrace   = errors.New("usage: " + UsageTrace)
	ErrUsageVouch   = errors.New("usage: " + UsageVouch)
	ErrFIXME        = errors.New("FIXME")
	ErrCantExec     = errors.New("asnsrv can't exec this command")
)

func (ses *Ses) RxExec(pdu *asn.PDU) error {
	var req asn.Requester
	var cmd [256]byte
	const sep = "-\x00"
	req.ReadFrom(pdu)
	n, err := pdu.Read(cmd[:])
	if err != nil {
		return err
	}
	sepi := bytes.Index(cmd[:n], []byte(sep))
	if sepi > 0 {
		n = sepi
	}
	args := strings.Split(string(cmd[:n]), "\x00")
	ses.ASN.Println("exec", strings.Join(args, " "))
	if sepi > 0 {
		pdu.Rewind()
		pdu.Read(cmd[:sepi+len(sep)])
	}
	go ses.GoExec(pdu, req, args...)
	return nil
}

func (ses *Ses) GoExec(pdu *asn.PDU, req asn.Requester,
	args ...string) {
	ses.ASN.Ack(req, ses.Exec(pdu, args...))
}

func (ses *Ses) Exec(r io.Reader, args ...string) interface{} {
	switch args[0] {
	case "exec-help", "help":
		return HelpExec
	case "approve":
		return ses.ExecApprove(args[1:]...)
	case "auth":
		return ses.ExecAuth(args[1:]...)
	case "blob":
		return ses.ExecBlob(r, args[1:]...)
	case "cat":
		return ses.ExecCat(args[1:]...)
	case "clone":
		return ses.ExecClone(args[1:]...)
	case "echo":
		return strings.Join(args[1:], " ") + "\n"
	case "fetch":
		return ses.ExecFetch(args[1:]...)
	case "gc":
		return ses.ExecGC(args[1:]...)
	case "ls":
		return ses.ExecLS(args[1:]...)
	case "mark":
		return ses.ExecMark(args[1:]...)
	case "newuser":
		return ses.ExecNewUser(args[1:]...)
	case "objdump":
		return ses.ExecObjDump(args[1:]...)
	case "rm":
		return ses.ExecRM(args[1:]...)
	case "scan":
		return ses.ExecScan(args[1:]...)
	case "trace":
		return ses.ExecTrace(args[1:]...)
	case "vouch":
		return ses.ExecVouch(args[1:]...)
	default:
		return asn.ErrUnknown
	}
}

func (ses *Ses) ExecApprove(args ...string) interface{} {
	return ses.Summer(ErrUsageApprove, "asn/approvals/", args...)
}

func (ses *Ses) ExecAuth(args ...string) interface{} {
	var err error
	owner := ses.Keys.Client.Login
	if len(args) > 2 && args[0] == "-u" {
		if owner, err = asn.UniqueUser(ses, args[1]); err != nil {
			return err
		}
		args = args[2:]
	}
	if len(args) != 1 {
		return ErrUsageAuth
	}
	if err = os.ErrInvalid; len(args[0]) != (asn.AuthPubSz * 2) {
		return err
	}
	pub, err := hex.DecodeString(args[0])
	if err != nil {
		return err
	}
	if err = os.ErrInvalid; len(pub) != asn.AuthPubSz {
		return err
	}
	blob := asn.NewBlob(&owner, &ses.Keys.Client.Login, "asn/auth")
	defer blob.Free()
	fn, sum, err := blob.File(ses, pub)
	if err != nil {
		return err
	}
	blob.Proc(ses, sum, fn, func(_ string, _ ...*asn.EncrPub) {
		// FIXME
	})
	return sum
}

func (ses *Ses) ExecBlob(r io.Reader, args ...string) interface{} {
	var err error
	if len(args) != 1 {
		return ErrUsageBlob
	}
	owner := ses.Keys.Client.Login
	name := args[0]
	slash := strings.Index(args[0], "/")
	if asn.IsHex(args[0]) || (slash > 0 && asn.IsHex(name[:slash])) {
		if slash < 0 {
			slash = len(name)
			name = ""
		} else {
			name = name[slash+1:]
		}
		owner, err = asn.UniqueUser(ses, args[0][:slash])
		if err != nil {
			return err
		}
	}
	blob := asn.NewBlob(&owner, &ses.Keys.Client.Login, name)
	defer blob.Free()
	fn, sum, err := blob.File(ses, r)
	if err != nil {
		return err
	}
	blob.Proc(ses, sum, fn, func(_ string, _ ...*asn.EncrPub) {
		// FIXME
	})
	return sum
}

func (ses *Ses) ExecCat(args ...string) interface{} {
	var files []*os.File
	if len(args) == 0 {
		return ErrUsageCat
	}
	err := ses.Blobber(func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err = asn.SeekBlobContent(f); err != nil {
			f.Close()
			return err
		}
		files = append(files, f)
		return nil
	}, args...)
	if err != nil {
		for _, f := range files {
			f.Close()
		}
		return err
	}
	return files
}

func (ses *Ses) ExecClone(args ...string) interface{} {
	var (
		err   error
		epoch time.Time
		arg   string
		pdu   *asn.PDU

		dir, subdir []os.FileInfo
	)
	const fnlen = (asn.SumSz - 1) * 2
	nargs := len(args)
	if nargs > 1 {
		return ErrUsageClone
	} else if nargs == 1 {
		epoch, arg = StripEpoch(args[0])
	}
	if ses.asnsrv {
		return ErrCantExec
	}
	if len(arg) > 0 {
		// remote clone
		return ErrFIXME
	}
	if dir, err = ioutil.ReadDir(ses.srv.Config.Dir); err != nil {
		return err
	}
	for _, fi := range dir {
		if fi.IsDir() && len(fi.Name()) == 2 {
			subdn := filepath.Join(ses.srv.Config.Dir, fi.Name())
			if subdir, err = ioutil.ReadDir(subdn); err != nil {
				return err
			}
			for _, fi := range subdir {
				fn := filepath.Join(subdn, fi.Name())
				if !fi.IsDir() && len(fi.Name()) == fnlen {
					bt := asn.BlobTime(fn)
					if epoch.IsZero() || bt.After(epoch) {
						pdu, err = asn.OpenPDU(fn)
						if err != nil {
							return err
						}
						ses.ASN.Tx(pdu)
					}
				}
			}
		}
	}
	return nil
}

func (ses *Ses) ExecFetch(args ...string) interface{} {
	var err error
	if len(args) < 1 {
		return ErrUsageFetch
	}
	if ses.asnsrv {
		return ErrCantExec
	}
	err = ses.Blobber(func(path string) error {
		pdu, err := asn.OpenPDU(path)
		if err == nil {
			ses.ASN.Tx(pdu)
		}
		return err
	}, args...)
	return err
}

func (ses *Ses) ExecGC(args ...string) interface{} {
	var (
		err     error
		epoch   time.Time
		verbose bool
		out     []byte
	)
	for _, arg := range args {
		if arg == "-v" || arg == "--v" {
			verbose = true
		} else if strings.HasPrefix(arg, "@") {
			epoch, _ = StripEpoch(arg)
		} else {
			return ErrUsageGC
		}
	}
	walker := func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			f, err := os.Open(path)
			if err == nil {
				var id asn.Id
				id.ReadFrom(f)
				if id.IsDeleted() &&
					(epoch.IsZero() ||
						asn.BlobTime(f).After(epoch)) {
					if verbose {
						out = append(out,
							[]byte(path)...)
						out = append(out, '\n')
					}
					syscall.Unlink(path)
				}
				f.Close()
			}
		}
		return err
	}
	err = filepath.Walk(ses.srv.Config.Dir, walker)
	if err != nil {
		return err
	}
	return out
}

func (ses *Ses) ExecLS(args ...string) interface{} {
	var out []byte
	err := ses.Blobber(func(path string) error {
		suser, path := asn.StripUserString(ses, path)
		if suser != "" && suser != ses.Keys.Client.Login.String() {
			out = append(out, []byte(suser[:16])...)
			out = append(out, os.PathSeparator)
		}
		out = append(out, []byte(path)...)
		out = append(out, '\n')
		return nil
	}, args...)
	if err != nil {
		out = nil
		return err
	}
	return out
}

func (ses *Ses) ExecMark(args ...string) interface{} {
	var (
		err error
		m   asn.Mark
		sum *asn.Sum
	)
	user := ses.Keys.Client.Login
	if len(args) > 2 && args[0] == "-u" {
		user, err = asn.UniqueUser(ses, args[1])
		if err != nil {
			return err
		}
		args = args[2:]
	}
	if nargs := len(args); nargs == 1 {
		if len(args[0]) < 6 || args[0][0] != '7' {
			return ErrUsageMark
		}
		place, err := asn.UniqueUser(ses, args[0][2:])
		if err != nil {
			return err
		}
		if err = m.SetPlace(&user, &place, args[0][:2]); err != nil {
			return err
		}
	} else if nargs == 2 {
		if err = m.SetLL(&user, args...); err != nil {
			return err
		}
	} else {
		return ErrUsageMark
	}
	blob := asn.NewBlob(&user, &ses.Keys.Client.Login, "asn/mark")
	defer blob.Free()
	fn, sum, err := blob.File(ses, m)
	if err != nil {
		return err
	}
	blob.Proc(ses, sum, fn, func(_ string, _ ...*asn.EncrPub) {
		// FIXME
	})
	return sum
}

func (ses *Ses) ExecNewUser(args ...string) interface{} {
	if len(args) != 1 {
		return ErrUsageNewUser
	}
	q, err := asn.NewQuad()
	if err != nil {
		return err
	}
	defer func() {
		q.Clean()
		q = nil
	}()
	out, err := yaml.Marshal(q)
	if err != nil {
		return err
	}
	blob := asn.NewBlob(q.Pub.Encr, &ses.Keys.Client.Login, "asn/auth")
	defer blob.Free()
	fn, sum, err := blob.File(ses, []byte(q.Pub.Auth[:]))
	if err != nil {
		return err
	}
	blob.Proc(ses, sum, fn, func(_ string, _ ...*asn.EncrPub) {
		// FIXME
	})
	blob = asn.NewBlob(q.Pub.Encr, &ses.Keys.Client.Login, "asn/author")
	defer blob.Free()
	fn, sum, err = blob.File(ses, []byte(ses.Keys.Client.Login[:]))
	if err != nil {
		return err
	}
	blob.Proc(ses, sum, fn, func(_ string, _ ...*asn.EncrPub) {
		// FIXME
	})
	blob = asn.NewBlob(q.Pub.Encr, &ses.Keys.Client.Login, "asn/user")
	defer blob.Free()
	fn, sum, err = blob.File(ses, args[0])
	if err != nil {
		return err
	}
	blob.Proc(ses, sum, fn, func(_ string, _ ...*asn.EncrPub) {
		// FIXME
	})
	return out
}

func (ses *Ses) ExecObjDump(args ...string) interface{} {
	out := &bytes.Buffer{}
	if len(args) < 1 {
		return ErrUsageObjDump
	}
	err := ses.Blobber(func(path string) error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sum := asn.NewSumOf(f)
		f.Seek(asn.BlobOff, os.SEEK_SET)
		blob, err := asn.NewBlobFrom(f)
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
		fmt.Fprintln(out, "epoch:", blob.Time.UnixNano())
		fmt.Fprintln(out, "size:", fi.Size())
		fmt.Fprintln(out, "len:", fi.Size()-pos)
		switch blob.Name {
		case "asn/auth":
			var auth asn.AuthPub
			f.Read(auth[:])
			fmt.Fprintln(out, "asn/auth:", auth.String())
		case "asn/author":
			var author asn.EncrPub
			f.Read(author[:])
			fmt.Fprintln(out, "asn/author:", author.String())
		case asn.MarkFN:
			var m asn.Mark
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
	}, args...)
	if err != nil {
		out = nil
		return err
	}
	b := out.Bytes()
	out = nil
	return b
}

func (ses *Ses) ExecRM(args ...string) interface{} {
	return ses.Summer(ErrUsageRM, "asn/removals/", args...)
}

func (ses *Ses) ExecScan(args ...string) interface{} {
	var f float64
	if len(args) != 3 {
		return ErrUsageScan
	}
	if _, err := fmt.Sscanf(args[0], "%f", &f); err != nil {
		return err
	}
	ses.Lat = int32(f * 1000000)
	if _, err := fmt.Sscanf(args[1], "%f", &f); err != nil {
		return err
	}
	ses.Lon = int32(f * 1000000)
	if _, err := fmt.Sscanf(args[2], "%d", &ses.Range); err != nil {
		return err
	}
	// FIXME send current locations
	return nil
}

func (ses *Ses) ExecTrace(args ...string) interface{} {
	cmd := "flush"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "flush":
		return asn.TraceFlush
	case "filter", "unfilter", "resize":
		return ErrFIXME
	default:
		return ErrUsageTrace
	}
}

func (ses *Ses) ExecVouch(args ...string) interface{} {
	if len(args) != 2 {
		return ErrUsageVouch
	}
	user, err := asn.UniqueUser(ses, args[0])
	if err != nil {
		return err
	}
	sig, err := hex.DecodeString(args[1])
	if err != nil {
		return err
	}
	if err = os.ErrInvalid; len(sig) != asn.AuthSigSz {
		return err
	}
	blob := asn.NewBlob(&user, &ses.Keys.Client.Login, "asn/vouchers/")
	defer blob.Free()
	fn, sum, err := blob.File(ses, sig)
	if err != nil {
		return err
	}
	blob.Proc(ses, sum, fn, func(_ string, _ ...*asn.EncrPub) {
		// FIXME
	})
	return sum
}

func BlobFilter(fn string, epoch time.Time,
	f func(fn string) error) (err error) {
	fi, err := os.Stat(fn)
	if err != nil {
		return
	}
	if fi.IsDir() {
		filepath.Walk(fn,
			func(wn string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() &&
					(epoch.IsZero() ||
						asn.BlobTime(wn).After(epoch)) {
					err = f(wn)
				}
				return err
			})
	} else if epoch.IsZero() || asn.BlobTime(fn).After(epoch) {
		err = f(fn)
	}
	return
}

func (ses *Ses) Blobber(f func(path string) error, args ...string) error {
	var (
		epoch time.Time
		users *[]*asn.EncrPub
	)
	defaultUsers := []*asn.EncrPub{&ses.Keys.Client.Login}
	defer func() {
		defaultUsers[0] = nil
	}()
	if len(args) == 0 {
		args = []string{""}
	}
argLoop:
	for _, arg := range args {
		users = &defaultUsers
		(*users)[0] = &ses.Keys.Client.Login
		epoch, arg = StripEpoch(arg)
		if _, err := os.Stat(arg); err == nil { // DIR or FILE
			BlobFilter(arg, epoch, f)
			continue argLoop
		} else if asn.IsHex(arg) { // USER or SHA
			fn, err := asn.UniqueENT(ses, arg)
			if err != nil {
				return err
			}
			if asn.IsUserENT(fn) { // USER
				suser := asn.TopDN(arg) + fn
				(*users)[0], err = asn.NewEncrPubString(suser)
				if err != nil {
					return err
				}
				arg = ""
			} else { // SHA
				BlobFilter(arg, epoch, f)
				continue argLoop
			}
		} else if slash := strings.Index(arg, "/"); slash > 0 &&
			asn.IsHex(arg[:slash]) { // USER/NAME
			s := ses.srv.Config.Keys.Server.Pub.Encr.String()
			if strings.HasPrefix(s, arg[:slash]) {
				users = &ses.srv.Users
			} else {
				fn, err := asn.UniqueENT(ses, arg[:slash])
				if err != nil {
					return err
				}
				if !asn.IsUserENT(fn) {
					return asn.ErrNOENT
				}
				suser := asn.TopDN(arg) + fn
				(*users)[0], err = asn.NewEncrPubString(suser)
				if err != nil {
					return err
				}
			}
			arg = arg[slash+1:]
		}
		if arg == "" {
			arg = "*"
		}
		for _, user := range *users {
			xn := asn.UserPN(ses, user, arg)
			if matches, err := filepath.Glob(xn); err != nil {
				return err
			} else if len(matches) > 0 {
				for _, match := range matches {
					BlobFilter(match, epoch, f)
				}
			} else if len(*users) == 1 {
				return os.ErrNotExist
			}
		}
	}
	return nil
}

func (ses *Ses) Summer(errusage error, name string, args ...string) interface{} {
	if len(args) < 1 {
		return errusage
	}
	sums := make(asn.Sums, 0)
	defer func() { sums = nil }()
	err := ses.Blobber(func(path string) error {
		// Permission to remove is checked in blob.Proc()
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sums = append(sums, *asn.NewSumOf(f))
		return nil
	}, args...)
	if err != nil {
		return err
	}
	blob := asn.NewBlob(&ses.Keys.Client.Login, &ses.Keys.Client.Login,
		"asn/removals/")
	defer blob.Free()
	fn, sum, err := blob.File(ses, sums)
	if err != nil {
		return err
	}
	blob.Proc(ses, sum, fn, func(_ string, _ ...*asn.EncrPub) {
		// FIXME
	})
	return sum
}

// StripEpoch removes '@NANO' argument suffixes
func StripEpoch(arg string) (t time.Time, argWoTime string) {
	argWoTime = arg
	if at := strings.Index(arg, "@"); at >= 0 {
		var nano int64
		isec := int64(time.Second)
		fmt.Sscanf(arg[at+1:], "%d", &nano)
		t = time.Unix(nano/isec, nano%isec)
		argWoTime = arg[:at]
	}
	return
}
