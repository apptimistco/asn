// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"flag"
	"github.com/apptimistco/asn/adm"
	"github.com/apptimistco/asn/srv"
	"os"
	"sync"
	"testing"
)

var (
	Stdin  = os.Stdin
	Stdout = os.Stdout
	Clean  = flag.Bool("clean", false, "clean repos before test")
	Once   sync.Once
)

func srvTestSetup() {
	procflags()
	WriteConfigs()
}

func procflags() {
	if *Clean {
		srv.CleanRepos = true
	}
}

func asnsrv(t *testing.T, args ...string) {
	err := srv.Main(append([]string{"asnsrv"}, args...)...)
	if err != nil {
		t.Error("srv", err)
	}
}

func asnadm(t *testing.T, args ...string) {
	err := adm.Main(append([]string{"asnadm"}, args...)...)
	if err != nil {
		t.Error("adm", err)
	}
}

func TestArgs(t *testing.T) {
	Once.Do(srvTestSetup)
	t.Log("CleanRepos:", srv.CleanRepos)
}

func TestNoLoginEcho(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	for i, s := range []string{"unix", "ws"} {
		var adm adm.Adm
		if err := adm.Config(AdmConfigFN); err != nil {
			t.Error(s, err)
		} else if err = adm.Connect(i); err != nil {
			t.Error(s, err)
		} else if err = adm.Exec("echo", "hello"); err != nil {
			t.Error(s, err)
		}
		adm.Close()
	}
	srv.KillAll(os.Interrupt)
}

func TestLoginEcho(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	asnadm(t, AdmConfigFN, "echo", "hello", "world")
	srv.KillAll(os.Interrupt)
}

func TestLoginTrace(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	asnadm(t, AdmConfigFN, "trace", "flush")
	srv.KillAll(os.Interrupt)
}

func TestSuspend(t *testing.T) {
	var adm adm.Adm
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	if err := adm.Config(AdmConfigFN); err != nil {
		t.Error(err)
	} else if err = adm.Connect(0); err != nil {
		t.Error(err)
	} else if err = adm.Login(); err != nil {
		t.Error(err)
	} else if err = adm.Exec("echo", "hello", "world"); err != nil {
		t.Error(err)
	} else if err = adm.Pause(); err != nil {
		t.Error(err)
	} else if err = adm.Resume(); err != nil {
		t.Error(err)
	} else if err = adm.Exec("echo", "Awaken!"); err != nil {
		t.Error(err)
	} else if testing.Verbose() {
		adm.Exec("trace")
	}
	adm.Quit()
	adm.Close()
	srv.KillAll(os.Interrupt)
}

func TestHelloBlob(t *testing.T) {
	var adm adm.Adm
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Config(AdmConfigFN)
	adm.Connect(0)
	adm.Login()
	adm.Blob("asn/hello", "hello world\n")
	adm.Quit()
	adm.Close()
	srv.KillAll(os.Interrupt)
}

func TestHelloAgainBlob(t *testing.T) {
	var adm adm.Adm
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Config(AdmConfigFN)
	adm.Connect(0)
	adm.Login()
	adm.Blob("asn/hello", "hello world\n")
	adm.Blob("asn/hello", "hello it's me\n")
	adm.Quit()
	adm.Close()
	srv.KillAll(os.Interrupt)
}

func TestAuthBlob(t *testing.T) {
	var adm adm.Adm
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Config(AdmConfigFN)
	adm.Connect(0)
	adm.Login()
	adm.AuthBlob()
	adm.Quit()
	adm.Close()
	srv.KillAll(os.Interrupt)
}

func TestMessageBlobs(t *testing.T) {
	var adm adm.Adm
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Config(AdmConfigFN)
	adm.Connect(0)
	adm.Login()
	adm.Blob("", "hello world\n")
	adm.Blob("", "hello it's me\n")
	adm.Quit()
	adm.Close()
	srv.KillAll(os.Interrupt)
}
