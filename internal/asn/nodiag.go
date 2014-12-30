// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !diag

package asn

var Diag nodiag

type nodiag bool

func (nd *nodiag) Output(_ int, _ string) error      { return nil }
func (nd *nodiag) Print(_ ...interface{})            {}
func (nd *nodiag) Printf(_ string, _ ...interface{}) {}
func (nd *nodiag) Println(_ ...interface{})          {}
func (asn *ASN) Diag(_ ...interface{})               {}
func (asn *ASN) Diagf(_ string, _ ...interface{})    {}
