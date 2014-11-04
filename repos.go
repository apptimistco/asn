// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	ReposPerm = os.FileMode(0770)
	TopDNSz   = 2
)

var (
	Join        = filepath.Join
	ErrAmbiguos = errors.New("Ambiguous USER or SHA")
	ErrNOENT    = errors.New("No such USER, SHA or FILE")
)

func BlobFN(repos Reposer, sum *Sum) string {
	s := sum.String()
	return filepath.Join(repos.DN(), s[:TopDNSz], s[TopDNSz:])
}

func MkReposDir(dn string) error {
	return os.MkdirAll(dn, ReposPerm)
}

func MkReposPath(fn string) error {
	return os.MkdirAll(filepath.Dir(fn), ReposPerm)
}

func Permission(repos Reposer, blob *Blob, login, ephemeral *EncrPub) error {
	if repos.IsAdmin(login) || repos.IsService(login) {
		return nil
	}
	if (blob.Name == "asn/mark" || blob.Name == "") &&
		(blob.Author == *login || blob.Author == *ephemeral) {
		return nil
	}
	if blob.Owner == *login || GetAsnAuthor(repos, &blob.Owner) == *login {
		return nil
	}
	if KeysHasKey(GetAsnEditors(repos, &blob.Owner), login) {
		return nil
	}
	return os.ErrPermission
}

func StripUserString(repos Reposer, path string) (user, remainder string) {
	prefix := repos.DN() + string(os.PathSeparator)
	if strings.HasPrefix(path, prefix) {
		path = strings.TrimPrefix(path, prefix)
	}
	remainder = path
	first := strings.IndexByte(path, os.PathSeparator)
	if first == TopDNSz {
		nxt := first + 1
		second := nxt + strings.IndexByte(path[nxt:], os.PathSeparator)
		if second > first {
			user = path[:first] + path[nxt:second]
			remainder = path[second+1:]
		}
	}
	return
}

func UniqueENT(repos Reposer, arg string) (fn string, err error) {
	dir, err := ioutil.ReadDir(PN(repos, TopDN(arg)))
	if os.IsNotExist(err) {
		err = ErrNOENT
		return
	} else if err != nil {
		return
	}
	match := SubDFN(arg)
	err = ErrNOENT
	for _, fi := range dir {
		if strings.HasPrefix(fi.Name(), match) {
			if err == nil {
				fn = ""
				err = ErrAmbiguos
				break
			} else {
				fn = fi.Name()
				err = nil
			}
		}
	}
	return
}

func UniqueUser(repos Reposer, arg string) (user EncrPub, err error) {
	fn, err := UniqueENT(repos, arg)
	if err != nil {
		return
	}
	b, _ := hex.DecodeString(TopDN(arg))
	user[0] = b[0]
	b, _ = hex.DecodeString(fn)
	copy(user[1:], b)
	b = nil
	return
}

func IsHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' ||
			'a' <= c && c <= 'f' ||
			'A' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

func IsBlobENT(fn string) bool {
	return IsHex(fn) && len(fn) == 2*(SumSz-1)
}

func IsUserENT(fn string) bool {
	return IsHex(fn) && len(fn) == 2*(EncrPubSz-1)
}

// SubDFN returns the argument's trailing sub directory or file (partial) name
func SubDFN(arg string) string {
	return arg[TopDNSz:]
}

// TopDN returns the argument's top directory name
func TopDN(arg string) string {
	return arg[:TopDNSz]
}

func PN(repos Reposer, args ...string) string {
	return filepath.Join(append([]string{repos.DN()}, args...)...)
}

func UserPN(repos Reposer, key *EncrPub, args ...string) string {
	s := key.String()
	return filepath.Join(append([]string{repos.DN(), TopDN(s), SubDFN(s)},
		args...)...)
}

func GetAsnAuth(repos Reposer, user *EncrPub) (auth AuthPub) {
	fn := UserPN(repos, user, "asn", "auth")
	if f, err := os.Open(fn); err == nil {
		defer f.Close()
		if _, err = SeekBlobContent(f); err == nil {
			f.Read(auth[:])
		}
		f.Close()
	}
	return
}

func GetAsnAuthor(repos Reposer, user *EncrPub) (author EncrPub) {
	fn := UserPN(repos, user, "asn", "author")
	if f, err := os.Open(fn); err == nil {
		defer f.Close()
		if _, err = SeekBlobContent(f); err == nil {
			f.Read(author[:])
		}
		f.Close()
	}
	return
}

func GetAsnEditors(repos Reposer, user *EncrPub) (keys []*EncrPub) {
	return GetKeysFromBlob(UserPN(repos, user, "asn", "editors"))
}

func GetAsnModerators(repos Reposer, user *EncrPub) (keys []*EncrPub) {
	return GetKeysFromBlob(UserPN(repos, user, "asn", "moderators"))
}

func GetAsnSubscribers(repos Reposer, user *EncrPub) (keys []*EncrPub) {
	return GetKeysFromBlob(UserPN(repos, user, "asn", "subscribers"))
}

func KeysHasKey(keys []*EncrPub, x *EncrPub) bool {
	for _, k := range keys {
		if *k == *x {
			return true
		}
	}
	return false
}

func CleanKeys(keys []*EncrPub) {
	for i := range keys {
		keys[i] = nil
	}
}

func GetKeysFromBlob(fn string) (keys []*EncrPub) {
	if f, err := os.Open(fn); err == nil {
		defer f.Close()
		var pos int64
		if pos, err = SeekBlobContent(f); err != nil {
			return
		}
		fi, _ := f.Stat()
		n := int(fi.Size()-pos) / EncrPubSz
		keys = make([]*EncrPub, n)
		for i := 0; i < n; i++ {
			f.Read(keys[i][:])
		}
	}
	return
}

func GetAsnUser(repos Reposer, owner *EncrPub) (user string) {
	fn := UserPN(repos, owner, "asn", "user")
	if f, err := os.Open(fn); err == nil {
		defer f.Close()
		if _, err = SeekBlobContent(f); err != nil {
			return
		}
		var b [256]byte
		if n, err := f.Read(b[:]); err == nil {
			user = string(b[:n])
		}
		f.Close()
	}
	return
}

func GetUsers(dn string) (users []*EncrPub, err error) {
	dir, err := ioutil.ReadDir(dn)
	if err != nil {
		return
	}
	users = []*EncrPub{}
	for _, fi := range dir {
		if fi.IsDir() && len(fi.Name()) == TopDNSz {
			subdn := filepath.Join(dn, fi.Name())
			subdir, suberr := ioutil.ReadDir(subdn)
			if err != nil {
				err = suberr
				return
			}
			for _, subfi := range subdir {
				if subfi.IsDir() && IsUserENT(subfi.Name()) {
					suser := fi.Name() + subfi.Name()
					user, uerr := NewEncrPubString(suser)
					if uerr != nil {
						err = uerr
						return
					}
					users = append(users, user)
					user = nil
				}
			}
		}
	}
	return
}
