// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !nocli

package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/tgrennan/go-gnureadline"
)

func (adm *Adm) CLI() (err error) {
	var prompt, line string
	home := os.Getenv("HOME")
	term := os.Getenv("TERM")
	history := filepath.Join(home, ".asnadm_history")
	rc := filepath.Join(home, ".asnadmrc")
	if adm.asn.Name.Session == "" {
		prompt = "asnadm: "
	} else {
		prompt = adm.asn.Name.Session + ": "
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
	gnureadline.StifleHistory(16)
	winch := make(chan os.Signal, 1)
	done := make(Done, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for {
			switch <-winch {
			case syscall.SIGWINCH:
				gnureadline.Rl_resize_terminal()
			case syscall.SIGTERM:
				signal.Stop(winch)
				gnureadline.Rl_reset_terminal(term)
				done <- nil
				runtime.Goexit()
			}
		}
	}()
	for err == nil {
		if line, err = gnureadline.Readline(prompt, true); err == nil {
			err = adm.cmdLine(line)
		}
	}
	winch <- syscall.SIGTERM
	<-done
	return
}
