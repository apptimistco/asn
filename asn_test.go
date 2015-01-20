// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"testing"
)

type Buffer struct{ bytes.Buffer }
type AsnTest struct {
	mode Mode
	fn   string
	base []byte
	in   Buffer
	out  Buffer
	cmd  Command
}

type AsnTestMap map[string]*AsnTest

var (
	atf struct {
		clean bool
		trace string
	}
	atm = AsnTestMap{
		"admin": &AsnTest{
			mode: AdminMode,
			fn:   "test-adm.yaml",
			base: []byte(`
name: test-adm
dir: test-adm.asn
lat: 37.7833
lon: -122.4167
server:
- name: sf
  url: unix:///test-sf.sock
  lat: 181
  lon: 0
- name: la
  url: unix:///test-la.sock
  lat: 34.0500
  lon: -118.2500
- name: sf.ws
  url: ws://localhost:6080/asn/test-sf.ws
  lat: 37.7833
  lon: -122.4167
`)},
		"sf": &AsnTest{
			mode: ServerMode,
			fn:   "test-sf.yaml",
			base: []byte(`
name: test-sf
dir: test-sf.asn
lat: 37.7833
lon: -122.4167
listen:
- unix:///test-sf.sock
- ws://localhost:6080/asn/test-sf.ws
`)},
		"la": &AsnTest{
			mode: ServerMode,
			fn:   "test-la.yaml",
			base: []byte(`
name: test-la
dir: test-la.asn
lat: 34.0500
lon: -118.2500
listen:
- unix:///test-la.sock
`)},
	}
)

func init() {
	flag.BoolVar(&atf.clean, "clean", false,
		"clean repos before test")
	if testing.Verbose() {
		atf.trace = "trace flush\n"
	}
	for _, x := range atm {
		x.cmd.In = &x.in
		x.cmd.Out = &x.out
		x.cmd.Sig = make(Sig, 1)
		x.cmd.Done = make(Done, 1)
		signal.Notify(x.cmd.Sig, syscall.SIGINT, syscall.SIGTERM)
	}
}

func AsnTestConfig(t *testing.T) {
	for _, err := range []error{
		Diag.Create("test.diag"),
		Log.Create("test.log"),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, x := range atm {
		if atf.clean {
			Diag.Println("rm", x.fn)
			os.Remove(x.fn)
			Diag.Println("rm -r", x.cmd.Cfg.Dir)
			os.RemoveAll(x.cmd.Cfg.Dir)
		}
		if f, err := os.Open(x.fn); err == nil {
			if b, err := ioutil.ReadAll(f); err == nil {
				if err = x.cmd.Cfg.Parse(b); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Fatal(err)
			}
		} else {
			k, err := NewKeys()
			if err != nil {
				t.Fatal(err)
			}
			for _, x := range atm {
				if err = x.cmd.Cfg.Parse(x.base); err != nil {
					t.Fatal(err)
				}
				x.cmd.Cfg.Keys = k
				err = ioutil.WriteFile(x.fn, x.cmd.Cfg.Bytes(),
					os.FileMode(0660))
				if err != nil {
					t.Fatal(err)
				}
			}
			break
		}
	}
}

func TestAsn(t *testing.T) {
	AsnTestConfig(t)
	Log.Println("pid:", os.Getpid())
	admin := atm["admin"]
	sf := atm["sf"]
	err := atm.CheckConfigs()
	if err != nil {
		t.Fatal(err)
	}
	err = sf.Test("SF help", "", "Commands:", "help")
	if err != nil {
		t.Fatal(err)
	}
	sf.out.Reset()
	atm.StartServers()
	defer func() {
		if err := atm.StopServers(); err != nil {
			t.Error(err)
		}
	}()
	admin.cmd.Flag.Nologin = true
	err = admin.Test("no-login echo", "", "hello world",
		"echo", "hello", "world")
	if err != nil {
		t.Fatal(err)
	}
	admin.cmd.Flag.Nologin = false
	err = admin.Test("echo", "", "hello world",
		"echo", "hello", "world")
	if err != nil {
		t.Fatal(err)
	}
	admin.cmd.Flag.Server = "sf.ws"
	err = admin.Test("WS echo", "", "hello world",
		"echo", "hello", "world")
	if err != nil {
		t.Fatal(err)
	}
	admin.cmd.Flag.Server = "la"
	err = admin.Test("LA echo", "", "hello world",
		"echo", "hello", "world")
	if err != nil {
		t.Fatal(err)
	}
	admin.cmd.Flag.Server = ""
	err = admin.Test("script echo", `
echo hello world
`, "hello world", "-")
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Test("trace", `
trace flush
`, "test-sf:unnamed connected.*", "-")
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Test("suspend", `
pause
resume
echo Awaken!
`, "Awaken!", "-")
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Test("hello blob", `
blob asn/hello hello world
`, "[0-9a-f]*", "-")
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Test("hello again", `
blob asn/hello hello its me
`, "[0-9a-f]*", "-")
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Test("cat asn/hello", `
cat asn/hello
`, "hello its me", "-")
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Test("auth-blob", `
auth-blob
`, "[0-9a-f]*", "-")
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Test("message blob", `
blob asn/messages hello world
blob asn/messages/ its me
`, "[0-9a-f]*", "-")
	if err != nil {
		t.Fatal(err)
	}
}

func (b *Buffer) Close() error { return nil }

// Test runs the receiver Admin or Server with given input and args then
// compares the output to the given patter.
func (x *AsnTest) Test(desc, in, pat string, args ...string) (err error) {
	if testing.Verbose() {
		fmt.Print(desc, "...")
	}
	x.out.Reset()
	x.in.Reset()
	io.WriteString(&x.in, in)
	if x.mode.Admin() {
		go x.cmd.Admin(args...)
	} else {
		go x.cmd.Server(args...)
	}
	if err = x.cmd.Wait(); err == nil {
		var t bool
		got := x.out.String()
		t, err = regexp.MatchReader(pat, &x.out)
		if err == nil && !t {
			Diag.Print("expected: ", pat, "\ngot:\n",
				got, "\n")
			err = &Error{desc, "mis-matched output"}
		}
	}
	if testing.Verbose() {
		if err != nil {
			fmt.Println("FAILED")
		} else {
			fmt.Println("PASS")
		}
	}
	return

}

func (m AsnTestMap) CheckConfigs() error {
	for k, x := range m {
		if err := x.cmd.Cfg.Check(x.mode); err != nil {
			return &Error{k, err.Error()}
		}
	}
	return nil
}

func (m AsnTestMap) StartServers() {
	for k, x := range m {
		if x.mode.Server() {
			Diag.Println("starting", k, "...")
			go x.cmd.Server()
		}
	}
}

func (m AsnTestMap) StopServers() (err error) {
	for k, x := range m {
		if x.mode.Server() {
			Diag.Println("stopping ", k, " ...")
			x.cmd.Sig <- os.Interrupt
			if xerr := x.cmd.Wait(); xerr != nil {
				Diag.Println(k, "stopped with", xerr)
				if err == nil {
					err = xerr
				}
			}
		}
	}
	return
}
