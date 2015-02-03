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
	"strings"
	"syscall"
)

const (
	Usage = `Usage:	asn [FLAGS] [COMMAND [ARGS...]]

`
	ExampleUsage = `
Examples:

  $ asn -config example-sf.yaml &
  $ asn -config example-adm.yaml echo hello world
  $ asn -config example-adm.yaml -server 1 echo hello world
  $ asn -config example-adm.yaml -server sf echo hello world
  $ asn -config example-adm.yaml -server sf			# CLI
  $ asn -config example-adm.yaml -server sf - <<-EOF
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
	DiagExt   = ".diag"
	LogExt    = ".log"
	ReposExt  = ".asn"

	DefaultName     = "asn"
	DefaultConfigFN = DefaultName + ConfigExt
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
	NL = []byte{'\n'}
)

type Done chan error
type Sig chan os.Signal

type Command struct {
	In   io.ReadCloser
	Out  io.WriteCloser
	Sig  Sig
	Done Done
	Cfg  Config
	Flag struct {
		Admin   bool
		Nologin bool
		Server  string
	}
}

func init() {
	FS = flag.NewFlagSet("asn", flag.ContinueOnError)
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
	FS.StringVar(&FN.diag, "diag", "",
		`If built with the 'diag' tag, this redirects output
	to the named file instead of syslog or 'NAME.diag' with the
	prefix of the config flag.`)
	FS.StringVar(&FN.log, "log", "",
		`If built *without* the 'nolog' tag, this redirects
	output to the named file instead of syslog or 'NAME.log' with
	the prefix of the config flag.`)
}

func main() {
	syscall.Umask(0007)
	cmd := Command{
		In:  os.Stdin,
		Out: os.Stdout,
	}
	FS.BoolVar(&cmd.Flag.Admin, "admin", false,
		`Run COMMAND or CLI in admin mode.
	This is the default action if the configuration doesn't have
	any listerners.`)
	FS.BoolVar(&cmd.Flag.Nologin, "nologin", false,
		`run COMMAND w/o login`)
	FS.StringVar(&cmd.Flag.Server, "server", "0",
		`Connect to the configured server with the matching name,
	URL or at the given index.`)
	err := FS.Parse(os.Args[1:])
	prefix := strings.TrimSuffix(FN.config, ConfigExt)
	diagfn := ""
	if FN.diag != "" {
		diagfn = FN.diag
	} else if FN.config != DefaultConfigFN {
		diagfn = prefix + DiagExt
	}
	logfn := ""
	if FN.log != "" {
		logfn = FN.log
	} else if FN.config != DefaultConfigFN {
		logfn = prefix + LogExt
	}
	switch {
	case err == flag.ErrHelp:
		return
	case err != nil:
		io.WriteString(os.Stderr, err.Error())
		os.Stderr.Write(NL)
		Exit(1)
		return
	case Show.help:
		ShowHelp()
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
	if diagfn != "" {
		if err = Diag.Create(diagfn); err != nil {
			goto egress
		}
	}
	if logfn != "" {
		if err = Log.Create(logfn); err != nil {
			goto egress
		}
	}
	if err = cmd.Cfg.Parse(FN.config); err != nil {
		goto egress
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
	err = cmd.Wait()
	FlushASN()
	FlushPDU()
	Log.Close()
	Diag.Close()
egress:
	if err != nil {
		os.Stderr.WriteString(err.Error())
		os.Stderr.WriteString("\n")
		Exit(1)
	}
}

func ShowHelp() {
	io.WriteString(os.Stderr, Usage)
	io.WriteString(os.Stderr, "Flags:\n\n")
	FS.PrintDefaults()
	io.WriteString(os.Stderr, ExampleUsage)
	io.WriteString(os.Stderr, UsageCommands)
	io.WriteString(os.Stderr, ExampleConfigs)
}

func (cmd *Command) ShowConfig() {
	c := cmd.Cfg
	c.Keys = nil
	io.WriteString(cmd.Out, c.String())
}

func (cmd *Command) ShowIds() {
	fmt.Fprintf(cmd.Out, "%25s%s\n", "", "Version")
	fmt.Fprintf(cmd.Out, "%25s", "")
	for v := Version(0); v <= Latest; v++ {
		fmt.Fprintf(cmd.Out, "%4d", v)
	}
	cmd.Out.Write(NL)
	for id := RawId + 1; id < Nids; id++ {
		fmt.Fprintf(cmd.Out, "%8d.", id)
		if s := id.String(); len(s) > 0 {
			fmt.Fprintf(cmd.Out, "%16s", s+"Id")
			for v := Version(0); v <= Latest; v++ {
				fmt.Fprintf(cmd.Out, "%4d", id.Version(v))
			}
		}
		cmd.Out.Write(NL)
	}
}

func (cmd *Command) ShowErrors() {
	fmt.Fprintf(cmd.Out, "%25s%s\n", "", "Version")
	fmt.Fprintf(cmd.Out, "%25s", "")
	for v := Version(0); v <= Latest; v++ {
		fmt.Fprintf(cmd.Out, "%4d", v)
	}
	cmd.Out.Write(NL)
	for ecode, s := range ErrStrings {
		fmt.Fprintf(cmd.Out, "%8d.", ecode)
		fmt.Fprintf(cmd.Out, "%16s", s)
		for v := Version(0); v <= Latest; v++ {
			fmt.Fprintf(cmd.Out, "%4d", Err(ecode).Version(v))
		}
		cmd.Out.Write(NL)
	}
}

func (cmd *Command) ShowNewKeys() {
	if k, err := NewRandomServiceKeys(); err != nil {
		io.WriteString(os.Stderr, err.Error())
	} else {
		io.WriteString(cmd.Out, k.String())
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
				fmt.Fprintf(cmd.Out, "%s:\t%s\n",
					fi.Name(), sum.String())
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

func (done Done) Wait() error { return <-done }

func (sig Sig) INT()  { sig <- syscall.SIGINT }
func (sig Sig) TERM() { sig <- syscall.SIGTERM }
func (sig Sig) USR1() { sig <- syscall.SIGUSR1 }

func IsINT(sig os.Signal) bool  { return sig == syscall.SIGINT }
func IsTERM(sig os.Signal) bool { return sig == syscall.SIGTERM }
func IsUSR1(sig os.Signal) bool { return sig == syscall.SIGUSR1 }
