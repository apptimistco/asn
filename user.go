// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"path/filepath"
)

func userDN(keystr string) string {
	return filepath.Join(keystr[:ReposTopSz], keystr[ReposTopSz:])
}

type User struct {
	cache  Cache
	dn     string
	key    PubEncr
	keystr string
	logins int
}

func newUser(key *PubEncr, keystr string) (u *User) {
	u = &User{
		cache: Cache{
			AsnAuth:        &CacheEntry{Time0, &PubAuth{}},
			AsnAuthor:      &CacheEntry{Time0, &PubEncr{}},
			AsnEditors:     &CacheEntry{Time0, &PubEncrList{}},
			AsnID:          &CacheEntry{Time0, &CacheBuffer{}},
			AsnInvites:     &CacheEntry{Time0, &PubEncrList{}},
			AsnMark:        &CacheEntry{Time0, &Mark{}},
			AsnModerators:  &CacheEntry{Time0, &PubEncrList{}},
			AsnSubscribers: &CacheEntry{Time0, &PubEncrList{}},
		},
		dn:     userDN(keystr),
		key:    *key,
		keystr: keystr,
	}
	u.cache.Mark().Key.Set(key)
	return
}

func NewUserKey(key *PubEncr) *User {
	return newUser(key, key.FullString())
}

func NewUserString(keystr string) *User {
	key, err := NewPubEncrString(keystr)
	if err != nil {
		panic(err)
	}
	return newUser(key, key.FullString())
}

func (u *User) Bytes() []byte {
	return u.key.Bytes()
}

func (u *User) DN() string {
	if u.dn == "" {
		u.dn = userDN(u.FullString())
	}
	return u.dn
}

func (u *User) MayApproveFor(o *User) bool {
	if u == nil {
		return true
	}
	return u.OnList(o.cache.Moderators())
}

func (u *User) MayEdit(o *User) bool {
	if u == nil || o == nil {
		return false
	}
	if u == o {
		return true
	}
	if o.cache.Author().Has(u.key) {
		return true
	}
	return u.OnList(o.cache.Editors())
}

func (u *User) OnList(l *PubEncrList) bool {
	if l == nil {
		return false
	}
	for _, x := range *l {
		if bytes.Equal(u.key.Bytes(), x.Bytes()) {
			return true
		}
	}
	return false
}

func (u *User) Join(elements ...string) string {
	if u.dn == "" {
		u.dn = userDN(u.FullString())
	}
	path := u.dn
	for _, x := range elements {
		path = filepath.Join(path, filepath.FromSlash(x))
	}
	return path
}

func (u *User) Reset() {
	u.cache.Reset()
	u.dn = ""
	var emptyKey PubEncr
	copy(u.key.Bytes(), emptyKey.Bytes())
	u.keystr = ""
	u.logins = 0
}

func (u *User) Set(v interface{}) (err error) {
	switch t := v.(type) {
	case int:
		u.logins = t
	case string:
		var k *PubEncr
		u.keystr = t
		if k, err = NewPubEncrString(t); err == nil {
			u.key = *k
			u.dn = userDN(u.keystr)
		}
	case *PubEncr:
		u.key = *t
		u.keystr = t.FullString()
		u.dn = userDN(u.keystr)
	default:
		err = os.ErrInvalid
	}
	return
}

func (u *User) FullString() string {
	if u.keystr == "" {
		u.keystr = u.key.FullString()
	}
	return u.keystr
}

func (u *User) ShortString() string {
	return u.FullString()[:8]
}

func (u *User) String() string {
	return u.ShortString() + "..."
}
