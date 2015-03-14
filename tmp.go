// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/file"
	"github.com/apptimistco/asn/debug/mutex"
)

const (
	tmpStr = "tmp"
	tmpPre = tmpStr + "_"
)

type Tmp struct {
	mutex.Mutex
	dn string
	i  int
}

func IsTmp(fn string) bool {
	return strings.HasPrefix(filepath.Base(fn), tmpPre)
}

// flush hanging files
func (tmp *Tmp) flush() {
	if dir, err := ioutil.ReadDir(tmp.dn); err == nil {
		for _, fi := range dir {
			syscall.Unlink(fi.Name())
		}
		dir = nil
	}
}

func (tmp *Tmp) Free(f *file.File) {
	if f != nil {
		fn := f.Name()
		f.Close()
		syscall.Unlink(fn)
		tmp.Diag(debug.Depth(2), fn, "removed")
	}
}

func (tmp *Tmp) New() *file.File {
	tmp.Lock()
	defer tmp.Unlock()
	f, err := file.Create(filepath.Join(tmp.dn,
		fmt.Sprintf("%s%012d", tmpPre, tmp.i)))
	tmp.i += 1
	if err != nil {
		panic(err)
	}
	tmp.Diag(debug.Depth(2), f.Name(), "removed")
	return f
}

func (tmp *Tmp) Reset() {
	if tmp.dn == "" {
		return
	}
	tmp.flush()
	tmp.Mutex.Reset()
	tmp.dn = ""
	tmp.i = 0
}

func (tmp *Tmp) Set(v interface{}) (err error) {
	switch t := v.(type) {
	case int:
		tmp.i = t
	case string:
		if !strings.HasSuffix(t, tmpStr) {
			tmp.dn = filepath.Join(t, tmpStr)
		} else {
			tmp.dn = t
		}
		tmp.Mutex.Set(tmp.dn)
		if err = MkdirAll(tmp.dn); err != nil {
			return
		}
		tmp.flush()
	default:
		err = os.ErrInvalid
	}
	return
}
