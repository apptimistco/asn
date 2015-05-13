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

func (users *Users) insert(user *User) {
	users.Lock()
	defer users.Unlock()
	n := len(users.l)
	i := sort.Search(n, func(i int) bool {
		return users.l[i].String() >= user.String()
	})
	if i == n {
		users.l = append(users.l, user)
	} else {
		users.l = append(users.l[:i], append([]*User{user},
			(users.l[i:])...)...)
	}
}

func (users *Users) NewUserKey(key *PubEncr) *User {
	u := NewUserKey(key)
	users.insert(u)
	return u
}

func (users *Users) NewUserString(keystr string) *User {
	u := NewUserString(keystr)
	users.insert(u)
	return u
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

func (users *Users) RM(user *User) {
	users.Lock()
	defer users.Unlock()
	for i, u := range users.l {
		if u == user {
			u.Reset()
			if i+1 < len(users.l) {
				users.l = append(users.l[:i], users.l[i+1:]...)
			} else {
				users.l = users.l[:i]
			}
			return
		}
	}
}

func (users *Users) Set(v interface{}) error {
	switch t := v.(type) {
	case string:
		users.Mutex.Set(t + "{users}")
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
