// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package accumulator provides an integer wrapper with a pointer receiver
method to sum results of Read, ReadFrom, Write and WriteTo signatures.

Usage:

	var a accumulator.Int64
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
		n = int64(a)
	}()

	a.Accumulate(w.Write(b1))
	a.Accumulate(w.Write(b2))
	a.Accumulate(w.Write(b3))
	a.Accumulate(w.Write(b1))
	a.Accumulate64(w.ReadFrom(r))
	...
	fmt.Println("wrote:", a)
*/
package accumulator

import "strconv"

type Int64 int64

// Accumulate Read and Write results with panic on error.
func (a *Int64) Accumulate(i int, err error) {
	if err != nil {
		panic(err)
	}
	*a += Int64(i)
}

// Accumulate64 ReadFrom and WriteTo results with panic on error.
func (a *Int64) Accumulate64(i int64, err error) {
	if err != nil {
		panic(err)
	}
	*a += Int64(i)
}

func (a *Int64) String() string {
	return strconv.FormatInt(int64(*a), 10)
}
