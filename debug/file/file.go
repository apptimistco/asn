// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package file provides a wrapper to os.File that, when built with both "diag"
and "file" tags (e.g. go build -tags "diag file"), enables a Diag method. This
wrapper also includes a Dup method.

Usage ("./foo.go"):

	package main

	import (
		"github.com/apptimistco/asn/debug"
		"github.com/apptimistco/asn/debug/file"
	)

	func main() {
		if false {
			debug.Diag.Redirect("foo.log")
		}
		foo, err := file.Create("foo.txt")	// line: X
		if err {
			panic(err)
		}
		defer foo.Close()
		io.WriteString(foo, "this is foo\n")
	}						// line: Y

build and run,

	$ go build -tags "diag file" .
	$ ./foo

would syslog this at level DEBUG,

	foo.go:X: file "foo.txt" create
	foo.go:Y: file "foo.txt" closed

with the Redirect(), this is printed to the named file instead of syslog.
*/
package file

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/accumulator"
)

var FileDiag *debug.Logger

type File struct {
	*os.File
}

func Create(fn string) (f *File, err error) {
	p, err := os.Create(fn)
	if err != nil {
		return
	}
	f = &File{p}
	runtime.SetFinalizer(f.File, (*os.File).Close)
	f.Diag(debug.Depth(2), "created")
	return
}

func Open(fn string) (f *File, err error) {
	p, err := os.Open(fn)
	if err != nil {
		return
	}
	f = &File{p}
	runtime.SetFinalizer(f.File, (*os.File).Close)
	f.Diag(debug.Depth(2), "opened")
	return
}

func (f File) Close() error {
	if f.File == nil {
		return os.ErrInvalid
	}
	fn := f.Name()
	err := f.File.Close()
	if err == nil {
		runtime.SetFinalizer(f.File, nil)
		f.File = nil
		if FileDiag != nil {
			FileDiag.Output(2, fmt.Sprintf("file %q closed\n", fn))
		}
	} else if FileDiag != nil {
		FileDiag.Output(2, fmt.Sprintf("file %q close %v\n", err))
	}
	return err
}

func (f *File) Diag(v ...interface{}) {
	if FileDiag == nil {
		return
	}
	depth, v := debug.FilterDepth(v...)
	FileDiag.Output(depth, fmt.Sprintf("file %q %s", f.Name(),
		fmt.Sprintln(v...)))
}

func (f *File) Dup() (dup *File, err error) {
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return
	}
	dup = &File{os.NewFile(uintptr(fd), f.Name())}
	_, err = dup.Seek(0, os.SEEK_SET)
	f.Diag(debug.Depth(2), "duped")
	return
}

func (f File) WriteTo(w io.Writer) (n int64, err error) {
	var (
		b [4096]byte
		a accumulator.Int64
	)
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
		n = int64(a)
		if err == io.EOF {
			err = nil
		}
	}()
	for {
		var i int
		if i, err = f.Read(b[:]); err != nil {
			return
		}
		a.Accumulate(w.Write(b[:i]))
	}
	return
}
