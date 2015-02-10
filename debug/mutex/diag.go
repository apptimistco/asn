// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build mutex

package mutex

import "github.com/apptimistco/asn/debug"

func (m *Mutex) Lock() {
	m.Mutex.Lock()
	m.Diag(debug.Depth(2), "lock")
}

func (m *Mutex) Unlock() {
	m.Diag(debug.Depth(2), "unlock")
	m.Mutex.Unlock()
}
