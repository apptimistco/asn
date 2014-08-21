// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package repos

import (
	"crypto/rand"
	"crypto/sha512"
	"github.com/apptimistco/asn/pdu/reflection"
	"github.com/apptimistco/encr"
	"testing"
)

func Test(t *testing.T) {
	objget := NewObjGetReq()
	for i := 0; i < 10; i++ {
		var id ObjId
		n, err := rand.Reader.Read(id[:])
		if err != nil {
			t.Fatal(err)
		}
		if n != sha512.Size {
			t.Fatal(n, "!=", sha512.Size)
		}
		objget.Append(id)
	}
	pass := reflection.Check(objget)

	objput := NewObjPutReq()
	for i := 0; i < 10; i++ {
		var rec ObjRec
		n, err := rand.Reader.Read(rec.Id[:])
		if err != nil {
			t.Fatal(err)
		}
		if n != sha512.Size {
			t.Fatal(n, "!=", sha512.Size)
		}
		rec.Len = uint32(i)
		objput.Append(rec)
	}
	pass = pass && reflection.Check(objput)

	key, _, _ := encr.NewRandomKeys()

	pass = pass && reflection.Check(NewRefGetReq(key, 0, 0))

	refput := NewRefPutReq(key)
	for i := 0; i < 10; i++ {
		var id ObjId
		n, err := rand.Reader.Read(id[:])
		if err != nil {
			t.Fatal(err)
		}
		if n != sha512.Size {
			t.Fatal(n, "!=", sha512.Size)
		}
		refput.Append(id)
	}
	pass = pass && reflection.Check(refput)

	if !pass {
		t.Fail()
	}
}
