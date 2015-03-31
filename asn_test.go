// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/apptimistco/asn/debug"
)

type AsnTest struct {
	mode Mode
	fn   string
	in   Buffer
	out  Buffer
	cmd  Command
}

type AsnTestMap map[string]*AsnTest

var (
	atf struct {
		debug.Debug
		clean bool
		trace string
	}
	atm = AsnTestMap{
		"admin": &AsnTest{
			mode: AdminMode,
			fn:   "test-adm",
		},
		"sf": &AsnTest{
			mode: ServerMode,
			fn:   "test-sf",
		},
		"la": &AsnTest{
			mode: ServerMode,
			fn:   "test-la",
		},
	}
)

func init() {
	flag.BoolVar(&atf.clean, "clean", false,
		"clean repos before test")
	if testing.Verbose() {
		atf.trace = "trace flush\n"
	}
	for _, x := range atm {
		x.cmd.Stdin = &x.in
		x.cmd.Stdout = &x.out
		x.cmd.Stderr = NopCloserWriter(os.Stderr)
		x.cmd.Done = make(Done, 1)
	}
}

func TestAsn(t *testing.T) {
	atf.Debug.Set("asn_test")
	f, err := debug.Create("test.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	debug.Redirect(f)
	atf.Log("pid:", os.Getpid())
	for _, x := range atm {
		if atf.clean {
			repos := x.fn + ReposExt
			atf.Log("rm -r", repos)
			os.RemoveAll(repos)
		}
		if err := x.cmd.Cfg.Parse(x.fn); err != nil {
			t.Fatal(err)
		}
	}
	admin := atm["admin"]
	sf := atm["sf"]
	if err = atm.CheckConfigs(); err != nil {
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
	admin.cmd.Flag.NoLogin = true
	err = admin.Test("no-login echo", "", "hello world",
		"echo", "hello", "world")
	if err != nil {
		t.Fatal(err)
	}
	admin.cmd.Flag.NoLogin = false
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
`, `.*`, "-")
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
	// admin.cmd.Flag.Server = "sf.ws"
	err = admin.Test("message", `
blob asn/messages hello world
`, "[0-9a-f]*", "-")
	if err != nil {
		t.Fatal(err)
	}
	err = admin.Test("another message", `
blob asn/messages/ its me
`, "[0-9a-f]*", "-")
	if err != nil {
		t.Fatal(err)
	}
}

// Test runs the receiver Admin or Server with given input and args then
// compares the output to the given patter.
func (x *AsnTest) Test(desc, in, pat string, args ...string) (err error) {
	if testing.Verbose() {
		fmt.Print(desc, "...")
		atf.Log(desc, "...")
	}
	x.out.Reset()
	x.in.Reset()
	io.WriteString(&x.in, in)
	sleep := func() {}
	if x.mode.Admin() {
		go x.cmd.Admin(args...)
		sleep = func() { time.Sleep(100 * time.Millisecond) }
	} else {
		go x.cmd.Server(args...)
	}
	err = x.cmd.Wait()
	sleep()
	if err == nil {
		var t bool
		got := x.out.String()
		t, err = regexp.MatchReader(pat, &x.out)
		if err == nil && !t {
			atf.Diag("expected: ", pat, "\ngot:\n", got, "\n")
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
			atf.Log("starting", k, "...")
			go x.cmd.Server()
		}
	}
}

func (m AsnTestMap) StopServers() (err error) {
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		return
	}
	proc.Signal(os.Interrupt)
	for k, x := range m {
		if x.mode.Server() {
			if xerr := x.cmd.Wait(); xerr != nil {
				atf.Diag(k, "stopped with", xerr)
				if err == nil {
					err = xerr
				}
			}
		}
	}
	return
}
