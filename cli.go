// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !nocli

package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/rocky/go-gnureadline"
)

func (adm *Adm) CLI() (err error) {
	var prompt, line string
	var inrl bool
	adm.rxq = make(chan *PDU, 16)
	home := os.Getenv("HOME")
	term := os.Getenv("TERM")
	history := filepath.Join(home, ".asnadm_history")
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
	gnureadline.StifleHistory(16)
	winch := make(chan os.Signal, 1)
	done := make(Done, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case pdu := <-adm.rxq:
				if inrl {
					println()
					adm.ObjDump(pdu)
					gnureadline.Rl_resize_terminal()
				} else {
					adm.ObjDump(pdu)
				}
			case sig := <-winch:
				if sig == syscall.SIGWINCH {
					gnureadline.Rl_resize_terminal()
				} else if sig == syscall.SIGTERM {
					signal.Stop(winch)
					gnureadline.Rl_reset_terminal(term)
					done <- nil
					runtime.Goexit()
				}
			}
		}
	}()
	for err == nil {
		inrl = true
		line, err = gnureadline.Readline(prompt, true)
		inrl = false
		if err == nil {
			err = adm.cmdLine(line)
			if err != nil && err != io.EOF {
				fmt.Println(err)
				err = nil
			}
		}
	}
	winch <- syscall.SIGTERM
	<-done
	return
}
