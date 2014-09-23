// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"github.com/apptimistco/asn/adm"
	"github.com/apptimistco/asn/srv"
	"os"
	"testing"
)

func TestEcho(t *testing.T) {
	admConfigString, srvConfigString := Configs()
	go func() {
		if err := srv.Main("asnsrv", srvConfigString); err != nil {
			t.Fatal("srv", err)
		}
	}()
	for i, s := range []string{"unix", "ws"} {
		var adm adm.Adm
		if err := adm.Config(admConfigString); err != nil {
			t.Error(s, err)
			break
		}
		if err := adm.Connect(i); err != nil {
			t.Error(s, err)
			break
		}
		if err := adm.Exec("echo", "hello", "world"); err != nil {
			t.Error(s, err)
			break
		}
		adm.Close()
	}
	srv.KillAll(os.Interrupt)
}

func TestLogin(t *testing.T) {
	admConfigString, srvConfigString := Configs()
	go func() {
		if err := srv.Main("asnsrv", srvConfigString); err != nil {
			t.Error("srv", err)
		}
	}()
	var adm adm.Adm
	defer func() {
		adm.Close()
		srv.KillAll(os.Interrupt)
	}()
	adm.Config(admConfigString)
	adm.Connect(0)
	if err := adm.Login(); err != nil {
		t.Error(err)
	} else {
		adm.Exec("echo", "hello", "world")
		adm.Quit()
	}
}

func TestTrace(t *testing.T) {
	admConfigString, srvConfigString := Configs()
	go func() {
		if err := srv.Main("asnsrv", srvConfigString); err != nil {
			t.Error("srv", err)
		}
	}()
	var adm adm.Adm
	defer func() {
		adm.Close()
		srv.KillAll(os.Interrupt)
	}()
	adm.Config(admConfigString)
	adm.Connect(0)
	adm.Login()
	if err := adm.Exec("trace"); err != nil {
		t.Error(err)
	}
	adm.Quit()
}

func TestSuspend(t *testing.T) {
	admConfigString, srvConfigString := Configs()
	go func() {
		if err := srv.Main("asnsrv", srvConfigString); err != nil {
			t.Error("srv", err)
		}
	}()
	var adm adm.Adm
	defer func() {
		adm.Close()
		srv.KillAll(os.Interrupt)
	}()
	adm.Config(admConfigString)
	adm.Connect(0)
	adm.Login()
	adm.Exec("echo", "hello", "world")
	if err := adm.Pause(); err != nil {
		t.Error(err)
		return
	}
	if err := adm.Resume(); err != nil {
		t.Error(err)
		return
	}
	if err := adm.Exec("echo", "Awake!", "Be", "ready."); err != nil {
		t.Error(err)
		return
	}
	if testing.Verbose() {
		adm.Exec("trace")
	}
	adm.Quit()
}
