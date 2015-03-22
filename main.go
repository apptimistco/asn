// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/file"
)

const (
	Usage = `Usage:	asn [FLAGS] [COMMAND [ARGS...]]

`
	ExampleUsage = `
Examples:

  $ asn -config example-sf &
  $ asn -config example-adm echo hello world
  $ asn -config example-adm -server 1 echo hello world
  $ asn -config example-adm -server sf echo hello world
  $ asn -config example-adm -server sf			# CLI
  $ asn -config example-adm -server sf - <<-EOF
	echo hello world
  EOF

`
	ExampleConfigs = `
Server CONFIG Format:
  name: STRING
  dir: PATH
  lat: FLOAT
  lon: FLOAT
  listen:
  - unix:///PATH.sock
  - tcp://:PORT
  - ws://[HOST][:PORT]/PATH.ws
  keys:
    admin:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    server:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      sec:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    nonce: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

Admin CONFIG Format:
  name: STRING
  dir: PATH
  lat: FLOAT
  lon: FLOAT
  keys:
    admin:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      sec:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    server:
      pub:
        encr: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        auth: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    nonce: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  server:
  - name: local
    url: unix:///PATH.sock
  - name: sf
    url: ws://HOST[:PORT]/PATH.ws
    lat: 37.774929
    lon: -122.419415
  - name: la
    url: ws://HOST[:PORT]/PATH.ws
    lat: 34.052234
    lon: -118.243684
`
	ConfigExt = ".yaml"
	LogExt    = ".log"
	ReposExt  = ".asn"

	DefaultConfigFN = AsnStr + ConfigExt
	DefaultReposDN  = ReposExt
)

var (
	Exit = os.Exit
	FS   *flag.FlagSet
	FN   struct {
		config string
		diag   string
		log    string
	}
	Show struct {
		help    bool
		config  bool
		ids     bool
		errors  bool
		newkeys bool
		sums    bool
	}
	NL    = []byte{'\n'}
	Time0 = time.Time{}
	Debug = debug.Debug(AsnStr)
)

func init() {
	FS = flag.NewFlagSet(AsnStr, flag.ContinueOnError)
	FS.Usage = ShowHelp
	FS.BoolVar(&Show.help, "show-help", false,
		`Print this and exit.`)
	FS.BoolVar(&Show.config, "show-config", false,
		`Print configuration with redacted keys and exit.`)
	FS.BoolVar(&Show.ids, "show-ids", false,
		`Print ASN protocol identifiers and exit.`)
	FS.BoolVar(&Show.errors, "show-errors", false,
		`Print ASN protocol error codes and exit.`)
	FS.BoolVar(&Show.newkeys, "new-keys", false,
		"Print new keys and exit.")
	FS.BoolVar(&Show.sums, "show-sums", false,
		"Print sums of *.go files and exit.")
	FS.StringVar(&FN.config, "config", DefaultConfigFN,
		`Load configuration from named file or builtin string.
	Without this flag asn searches './' and '/etc' for 'asn.yaml'.`)
	FS.StringVar(&FN.log, "log", "",
		`This redirects all log output to the named file instead of
	syslog or 'NAME.log' with the prefix of the config flag.`)
}

func IsBlob(fi os.FileInfo) bool {
	fn := fi.Name()
	return !fi.IsDir() && len(fn) == 2*(SumSz-1) && IsHex(fn)
}

func IsBridge(fn string) bool {
	return filepath.Base(filepath.Dir(fn)) == "bridge"
}

func IsHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' ||
			'a' <= c && c <= 'f' ||
			'A' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

func IsINT(sig os.Signal) bool  { return sig == syscall.SIGINT }
func IsTERM(sig os.Signal) bool { return sig == syscall.SIGTERM }
func IsUSR1(sig os.Signal) bool { return sig == syscall.SIGUSR1 }

func IsTopDir(fi os.FileInfo) bool {
	fn := fi.Name()
	return fi.IsDir() && len(fn) == ReposTopSz && IsHex(fn)
}

func IsUser(fn string) bool {
	return IsHex(fn) && len(fn) == 2*(PubEncrSz-1)
}

func main() {
	syscall.Umask(0007)
	cmd := Command{
		Stdin:  file.File{os.Stdin},
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	pid := os.Getpid()
	FS.BoolVar(&cmd.Flag.Admin, "admin", false,
		`Run COMMAND or CLI in admin mode.
	This is the default action if the configuration doesn't have
	any listerners.`)
	FS.BoolVar(&cmd.Flag.NoLogin, "nologin", false,
		`run COMMAND w/o login`)
	FS.StringVar(&cmd.Flag.Server, "server", "0",
		`Connect to the configured server with the matching name,
	URL or at the given index.`)
	err := FS.Parse(os.Args[1:])
	prefix := strings.TrimSuffix(FN.config, ConfigExt)
	cmd.Debug.Set(prefix)
	logfn := ""
	if FN.log != "" {
		logfn = FN.log
	} else if FN.config != DefaultConfigFN {
		logfn = prefix + LogExt
	}
	if logfn != "" {
		var f *os.File
		if f, err = os.Create(logfn); err != nil {
			return
		}
		defer f.Close()
		if err = f.Chmod(0664); err != nil {
			return
		}
		debug.Redirect(f)
		cmd.Log("start", pid)
	}
	defer func() {
		cmd.Log("end", pid)
		if err != nil {
			cmd.Diag(debug.Depth(2), err)
			io.WriteString(cmd.Stderr, err.Error())
			cmd.Stderr.Write(NL)
			Exit(1)
		}
	}()
	switch {
	case err == flag.ErrHelp:
		return
	case err != nil:
		return
	case Show.help:
		showHelp(cmd.Stdout)
		return
	case Show.errors:
		cmd.ShowErrors()
		return
	case Show.ids:
		cmd.ShowIds()
		return
	case Show.newkeys:
		cmd.ShowNewKeys()
		return
	case Show.sums:
		cmd.ShowSums()
		return
	}
	if err = cmd.Cfg.Parse(FN.config); err != nil {
		return
	}
	if Show.config {
		cmd.ShowConfig()
		return
	}
	cmd.Sig = make(Sig, 1)
	cmd.Done = make(Done, 1)
	signal.Notify(cmd.Sig,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGUSR1)
	if cmd.Flag.Admin || len(cmd.Cfg.Listen) == 0 {
		go cmd.Admin(FS.Args()...)
	} else {
		go cmd.Server(FS.Args()...)
	}
	if err = cmd.Wait(); err == io.EOF {
		err = nil
	}
	FlushPDU()
}

func MkdirAll(dn string) error {
	return os.MkdirAll(dn, os.FileMode(0770))
}

func showHelp(out io.Writer) {
	io.WriteString(out, Usage)
	io.WriteString(out, "Flags:\n\n")
	FS.PrintDefaults()
	io.WriteString(out, ExampleUsage)
	io.WriteString(out, UsageCommands)
	io.WriteString(out, ExampleConfigs)
}

func ShowHelp() {
	showHelp(os.Stderr)
}

// UrlPathSearch looks for the given file in this order.
//	path		return
//	/foo.bar	foo.bar
//	/foo/bar	foo/bar if foo/ exists; otherwise
//			/foo/bar
func UrlPathSearch(path string) string {
	dir := filepath.Dir(path)
	if dir == "/" {
		return filepath.Base(path)
	} else {
		if f, err := os.Open(dir[1:]); err == nil {
			f.Close()
			return path[1:]
		}
	}
	return path
}

type Command struct {
	debug.Debug
	Stdin  ReadCloseWriteToer
	Stdout io.WriteCloser
	Stderr io.WriteCloser
	Sig    Sig
	Done   Done
	Cfg    Config
	Flag   struct {
		Admin   bool
		NoLogin bool
		Server  string
	}
}

func (cmd *Command) ShowConfig() {
	c := cmd.Cfg
	c.Keys = nil
	io.WriteString(cmd.Stdout, c.String())
}

func (cmd *Command) ShowIds() {
	fmt.Fprintf(cmd.Stdout, "%25s%s\n", "", "Version")
	fmt.Fprintf(cmd.Stdout, "%25s", "")
	for v := Version(0); v <= Latest; v++ {
		fmt.Fprintf(cmd.Stdout, "%4d", v)
	}
	cmd.Stdout.Write(NL)
	for id := RawId + 1; id < Nids; id++ {
		fmt.Fprintf(cmd.Stdout, "%8d.", id)
		if s := id.String(); len(s) > 0 {
			fmt.Fprintf(cmd.Stdout, "%16s", s+"Id")
			for v := Version(0); v <= Latest; v++ {
				fmt.Fprintf(cmd.Stdout, "%4d", id.Version(v))
			}
		}
		cmd.Stdout.Write(NL)
	}
}

func (cmd *Command) ShowErrors() {
	fmt.Fprintf(cmd.Stdout, "%25s%s\n", "", "Version")
	fmt.Fprintf(cmd.Stdout, "%25s", "")
	for v := Version(0); v <= Latest; v++ {
		fmt.Fprintf(cmd.Stdout, "%4d", v)
	}
	cmd.Stdout.Write(NL)
	for ecode, s := range ErrStrings {
		fmt.Fprintf(cmd.Stdout, "%8d.", ecode)
		fmt.Fprintf(cmd.Stdout, "%16s", s)
		for v := Version(0); v <= Latest; v++ {
			fmt.Fprintf(cmd.Stdout, "%4d", Err(ecode).Version(v))
		}
		cmd.Stdout.Write(NL)
	}
}

func (cmd *Command) ShowNewKeys() {
	if k, err := NewRandomServiceKeys(); err != nil {
		io.WriteString(os.Stderr, err.Error())
	} else {
		io.WriteString(cmd.Stdout, k.String())
	}
}

func (cmd *Command) ShowSums() {
	b := &bytes.Buffer{}
	dot, err := os.Open(".")
	if err != nil {
		io.WriteString(os.Stderr, err.Error())
		return
	}
	dir, _ := dot.Readdir(0)
	dot.Close()
	var in, out Sums
	for _, fi := range dir {
		if strings.HasSuffix(fi.Name(), ".go") {
			if f, err := os.Open(fi.Name()); err != nil {
				io.WriteString(os.Stderr, err.Error())
			} else {
				sum := NewSumOf(f)
				out = append(out, *sum)
				fmt.Fprintf(cmd.Stdout, "%s:\t%s\n",
					fi.Name(), sum.FullString())
				sum = nil
			}
		}
	}
	out.WriteTo(b)
	in.ReadFrom(b)
	if len(out) != len(in) {
		fmt.Fprintf(os.Stderr, "Mismatched lengths %d vs. %d\n",
			len(in), len(out))
	} else {
		for i := range in {
			if in[i] != out[i] {
				fmt.Fprintf(os.Stderr,
					"mismatch @ %d : %s vs. %s\n",
					i, in[i].String()[:8],
					out[i].String()[:8])
			}
		}
	}
}

func (cmd *Command) Wait() error { return cmd.Done.Wait() }

type Done chan error

func (done Done) Wait() error { return <-done }

type Sig chan os.Signal

func (sig Sig) INT()  { sig <- syscall.SIGINT }
func (sig Sig) TERM() { sig <- syscall.SIGTERM }
func (sig Sig) USR1() { sig <- syscall.SIGUSR1 }
