// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"unsafe"
)

type Logger struct {
	*log.Logger
	f *os.File
}

type NoLogger struct{}

func (l *Logger) ASN(asn *ASN, v ...interface{}) {
	l.Output(3, asn.Name.Session+" "+fmt.Sprintln(v...))
}

func (l *Logger) ASNf(asn *ASN, format string, v ...interface{}) {
	Diag.Output(3, asn.Name.Session+" "+fmt.Sprintf(format, v...))
}

func (l *Logger) Close() (err error) {
	if l.f != nil {
		err = l.f.Close()
		l.f = nil
	}
	return
}

func (l *Logger) Create(fn string) (err error) {
	l.Close()
	if fn == os.DevNull {
		*l = Logger{log.New(ioutil.Discard, "", 0), nil}
		return
	}
	f, err := os.Create(fn)
	if err != nil {
		return
	}
	if err = f.Chmod(0664); err != nil {
		f.Close()
		return
	}
	*l = Logger{log.New(f, "", l.Flag()), f}
	return
}

func (l *Logger) Flag() int {
	if l.IsDiag() {
		return log.Lshortfile
	}
	return 0
}

func (l *Logger) Init() {
	t, _ := syslog.NewLogger(l.Priority(), l.Flag())
	*l = Logger{t, nil}
}

func (l *Logger) IsLog() bool {
	return unsafe.Pointer(l) == unsafe.Pointer(Log)
}

func (l *Logger) IsDiag() bool {
	return unsafe.Pointer(l) == unsafe.Pointer(Diag)
}

func (l *Logger) Priority() syslog.Priority {
	if l.IsLog() {
		return syslog.LOG_INFO | syslog.LOG_USER
	} else if l.IsDiag() {
		return syslog.LOG_DEBUG | syslog.LOG_USER
	}
	return syslog.LOG_NOTICE | syslog.LOG_USER
}

func (l *Logger) Write(b []byte) (int, error) {
	l.Output(2, string(b))
	return len(b), nil
}

func (n *NoLogger) ASN(_ *ASN, _ ...interface{}) {
}
func (n *NoLogger) ASNf(_ *ASN, _ string, _ ...interface{}) {}
func (n *NoLogger) Close() error {
	return nil
}
func (n *NoLogger) Create(_ string) error {
	return nil
}
func (n *NoLogger) Init(_ syslog.Priority) {}
func (n *NoLogger) Output(_ int, _ string) error {
	return nil
}
func (n *NoLogger) Print(_ ...interface{}) {
}
func (n *NoLogger) Printf(_ string, _ ...interface{}) {}
func (n *NoLogger) Println(_ ...interface{}) {
}
func (n *NoLogger) Write(b []byte) (int, error) {
	return len(b), nil
}

func (asn *ASN) Diag(v ...interface{}) {
	Diag.ASN(asn, v...)
}

func (asn *ASN) Diagf(format string, v ...interface{}) {
	Diag.ASNf(asn, format, v...)
}

func (asn *ASN) Log(v ...interface{}) {
	Log.ASN(asn, v...)
}

func (asn *ASN) Logf(format string, v ...interface{}) {
	Log.ASNf(asn, format, v...)
}
