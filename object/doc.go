// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package `object` provides methods to read and write ASN repository object
files.  We identify each object by the SHA-512 sum of its content. There are
four object types: blob (opaque data), ASN tree, User Tree, and Pack. The last,
pack isn't stored in the repos; instead it's used to bundle several blob or
tree objects.

Objects are read in four steps as outlined here:

	var m object.Magic
	if m.ReadFrom(r); m.IsMagic() {
		var c object.Code
		var h object.Header
		c.ReadFrom(r)
		h.ReadFrom(r)
		switch {
		case c.IsBlob():
			r.Read(blob)
		case c.IsASN() || c.IsUser():
			var t object.Tree
			t.ReadFrom(r)
			...
		case c.IsPack():
			var p object.Pack
			p.ReadFrom(r)
		}
	}

Similarly, objects are written in these four steps:

	object.MagicString.WriteTo(w)
	c.WriteTo(w)
	(&object.Header{Owner: *KEY, Author: *KEY}).WriteTo(w)
	switch {
	case c.IsBlob():
		w.Write(blob[:])
	case c.IsASN() || c.IsUser():
		t.WriteTo(w)
	case c.IsPack():
		p.WriteTo(w)
	}

So, each object begins with a magic string to distinguish it as an ASN file; a
code denoting the type of object; some random data to assure that all blobs are
unique; both owner and author keys; and a time stamp of origin.

	Object = Magic + Code + Random + Owner + Author + Time + ...
	Magic = [7]uint8("asnobj\0")
	Code = uint8		(1 - Blob, 2 - Asn, 3 - User, 4 - Pack)
	Random = [24]uint8	(random data; e.g session Key[:24])
	Owner = [32]uint8	(public encryption key)
	Author = [32]uint8	(public encryption key)
	Time = uint64		(BigEndian Unix epoch nanoseconds)

After the time stamp, the remaining data is object specific.

The Code MSB, if set, marks the object for removal.

Blob data, with the exception of ASN control files, are opaque to the server.
It may be fetched and read by anyone so the App is generally responsible for
security, compression, content identification and interpretation. Once written,
blobs may not be modified other than through truncation by the owner or admin
with a null length write. This results in the object file truncated after the
time stamp.

Both ASN and User tree data reference blobs with free-format or hierarchical
names. Tree data begins with a count of the one or more succeeding blob
reference records, each containing the 64 byte, SHA-512 sum of the referenced
blob with a UTF-8 encoded Name string and its length.

	TreeData = Count + []Blob
	Count = uint32
	Blob = Sum + Len + Name
	Sum = [64]uint8
	Len = uint8
	Name = []uint8

Tree objects may be fetched and read by anyone but are never modified. However,
after updating the respective ASN or User tree reference, the service removes
the previous tree object along with any orphaned blobs.

Pack data begins with a count of the one or more concatenated objects.

	PackData = Count + []ObjLV
	Count = uint32
	ObjLV = Len + Object
	Len = uint32
	Object = []uint8
*/
package object
