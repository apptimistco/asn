// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
	"sort"

	"github.com/apptimistco/asn/debug/mutex"
)

type Users struct {
	mutex.Mutex
	l []*User
}

func (users *Users) ForEachUser(f func(*User) error) error {
	users.Lock()
	defer users.Unlock()
	for _, u := range users.l {
		if err := f(u); err != nil {
			return err
		}
	}
	return nil
}

func (users *Users) ForEachLoggedInUser(f func(*User) error) error {
	return users.ForEachUser(func(u *User) error {
		if u.logins > 0 {
			return f(u)
		}
		return nil
	})
}

// LS repos user table
func (users *Users) LS() []byte {
	users.Lock()
	defer users.Unlock()
	n := len(users.l)
	out := make([]byte, 0, n*((PubEncrSz*2)+1))
	for _, user := range users.l {
		out = append(out, []byte(user.String())...)
		out = append(out, '\n')
	}
	return out
}

func (users *Users) NewUserString(keystr string) *User {
	users.Lock()
	defer users.Unlock()
	user := NewUserString(keystr)
	users.l = append(users.l, user)
	return user
}

func (users *Users) Reset() {
	users.Lock()
	defer users.Unlock()
	for i, u := range users.l {
		u.Reset()
		users.l[i] = nil
	}
	users.l = nil
}

func (users *Users) Set(v interface{}) error {
	switch t := v.(type) {
	case string:
		users.Mutex.Set(t + " users")
	default:
		return os.ErrInvalid
	}
	return nil
}

// Binary search for longest matching key.
func (users *Users) User(key *PubEncr) (user *User) {
	users.Lock()
	defer users.Unlock()
	n := len(users.l)
	i := sort.Search(n, func(i int) bool {
		return bytes.Compare(users.l[i].key.Bytes(), key.Bytes()) >= 0
	})
	if i < n && users.l[i].key == *key {
		user = users.l[i]
	}
	return
}

// Binary search for longest matching key-string.
func (users *Users) UserString(ks string) (user *User) {
	users.Lock()
	defer users.Unlock()
	n := len(users.l)
	kslen := len(ks)
	i := sort.Search(n, func(i int) bool {
		return users.l[i].FullString() >= ks
	})
	if i < n && len(users.l[i].FullString()) >= kslen &&
		users.l[i].FullString()[:kslen] == ks {
		user = users.l[i]
	}
	return
}
