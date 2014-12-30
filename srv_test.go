// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/apptimistco/asn/internal/adm"
	"github.com/apptimistco/asn/internal/srv"
)

var (
	Clean    = flag.Bool("clean", false, "clean repos before test")
	Once     sync.Once
	MayTrace = ""
)

func srvTestSetup() {
	procflags()
	WriteConfigs()
	if testing.Verbose() {
		MayTrace = "trace flush\n"
	} else {
		adm.Stdout = ioutil.Discard
	}
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
	asnadm(t, "-nologin", AdmConfigFN, "echo", "hello", "world")
	srv.KillAll(os.Interrupt)
}

func TestLoginEcho(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	asnadm(t, AdmConfigFN, "echo", "hello", "world")
	srv.KillAll(os.Interrupt)
}

func TestTrace(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	asnadm(t, AdmConfigFN, "trace", "flush")
	srv.KillAll(os.Interrupt)
}

func TestSuspend(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Stdin = strings.NewReader(`
echo hello world
pause
resume
echo Awaken!
` + MayTrace)
	asnadm(t, AdmConfigFN, "-")
	srv.KillAll(os.Interrupt)
}

func TestHelloBlob(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Stdin = strings.NewReader(`
blob asn/hello hello world
` + MayTrace)
	asnadm(t, AdmConfigFN, "-")
	srv.KillAll(os.Interrupt)
}

func TestHelloAgainBlob(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Stdin = strings.NewReader(`
blob asn/hello hello world
blob asn/hello its me
` + MayTrace)
	asnadm(t, AdmConfigFN, "-")
	srv.KillAll(os.Interrupt)
}

func TestAuthBlob(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Stdin = strings.NewReader(`
auth-blob
` + MayTrace)
	asnadm(t, AdmConfigFN, "-")
	srv.KillAll(os.Interrupt)
}

func TestMessageBlobs(t *testing.T) {
	Once.Do(srvTestSetup)
	go asnsrv(t, SrvConfigFN)
	adm.Stdin = strings.NewReader(`
blob asn/messages/ hello world
blob asn/messages/ its me
` + MayTrace)
	asnadm(t, AdmConfigFN, "-")
	srv.KillAll(os.Interrupt)
}
