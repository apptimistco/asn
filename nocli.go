// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build nocli

package main

import "errors"

func (adm *Adm) CLI() error {
	return errors.New("cli feature not installed")
}
