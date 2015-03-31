// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !nocli

package main

import (
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/apptimistco/asn/debug"
	"github.com/rocky/go-gnureadline"
)

func (adm *Adm) CLI() (err error) {
	var prompt, line string
	adm.rxq = make(chan *PDU, 16)
	home := os.Getenv("HOME")
	history := filepath.Join(home, ".asnadm_history")
	defer gnureadline.WriteHistory(history)
	rc := filepath.Join(home, ".asnadmrc")
	if s := adm.asn.Debug.String(); s == "" {
		prompt = "asnadm: "
	} else {
		prompt = s + "# "
	}
	if _, err = os.Stat(rc); err == nil {
		if err = gnureadline.ReadInitFile(rc); err != nil {
			return err
		}
	}
	if _, err = os.Stat(history); err == nil {
		gnureadline.ReadHistory(history)
	} else {
		err = nil
	}
	gnureadline.StifleHistory(32)
	defer gnureadline.Rl_reset_terminal("")
	done := make(Done, 1)
	defer close(done)
	signal.Notify(adm.cmd.Sig, syscall.SIGWINCH)
	go func() {
		for err == nil {
			line = ""
			line, err = gnureadline.Readline(prompt, true)
			if err == nil {
				err = adm.cmdLine(line)
			}
		}
		done <- nil
	}()
	for {
		select {
		case <-done:
			return
		case pdu := <-adm.rxq:
			if line == "" {
				println()
				adm.ObjDump(pdu)
				gnureadline.Rl_resize_terminal()
			} else {
				adm.ObjDump(pdu)
			}
		case sig := <-adm.cmd.Sig:
			switch sig {
			case syscall.SIGWINCH:
				gnureadline.Rl_resize_terminal()
			case syscall.SIGINT:
				adm.Log("sigint")
				debug.Trace.WriteTo(debug.Log)
				fallthrough
			case syscall.SIGTERM:
				err = io.EOF
				<-done
				return
			case syscall.SIGUSR1:
				debug.Trace.WriteTo(debug.Log)
			}
		}
	}
}
