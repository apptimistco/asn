// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package adm

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/tgrennan/go-gnureadline"
)

func (adm *Adm) cli() error {
	var prompt string
	home := os.Getenv("HOME")
	term := os.Getenv("TERM")
	history := filepath.Join(home, ".asnadm_history")
	rc := filepath.Join(home, ".asnadmrc")
	if adm.asn.Name.Session == "" {
		prompt = "asnadm: "
	} else {
		prompt = adm.asn.Name.Session + ": "
	}
	if _, err := os.Stat(history); err == nil {
		gnureadline.ReadHistory(history)
	}
	if _, err := os.Stat(rc); err == nil {
		gnureadline.ReadInitFile(rc)
	}
	gnureadline.StifleHistory(16)
	winch := make(chan os.Signal, 1)
	winchStop := make(chan bool, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for {
			select {
			case <-winch:
				gnureadline.Rl_resize_terminal()
			case <-winchStop:
				return
			}
		}
	}()
	defer func() {
		winchStop <- true
		gnureadline.Rl_reset_terminal(term)
	}()
	for {
		line, err := gnureadline.Readline(prompt, true)
		if err != nil {
			return err
		}
		err = adm.cmdLine(line)
		if err != nil {
			return err
		}
	}
}
