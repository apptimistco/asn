// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
)

const (
	ReposPerm  = os.FileMode(0770)
	reposTopSz = 2
)

var (
	Join        = filepath.Join
	ErrAmbiguos = errors.New("Ambiguous USER or SHA")
	ErrNOENT    = errors.New("No such USER, SHA or FILE")
)

type ReposTmp struct {
	DN    string
	i     int
	mutex *sync.Mutex
}

func NewReposTmp(dn string) (tmp *ReposTmp, err error) {
	tmpDN := filepath.Join(dn, "tmp")
	x, err := ioutil.ReadDir(tmpDN)
	if err == nil {
		// flush hanging tmp files
		for _, fi := range x {
			syscall.Unlink(fi.Name())
		}
		x = nil
	} else if os.IsNotExist(err) {
		if err = os.MkdirAll(tmpDN, ReposPerm); err != nil {
			return
		}
	}
	tmp = &ReposTmp{
		DN:    tmpDN,
		i:     0,
		mutex: new(sync.Mutex),
	}
	return
}

func (tmp *ReposTmp) Free() {
	if tmp == nil {
		return
	}
	tmp.mutex = nil
	x, err := ioutil.ReadDir(tmp.DN)
	if err == nil {
		// flush hanging tmp files
		for _, fi := range x {
			syscall.Unlink(fi.Name())
		}
	}
	x = nil
}

func (tmp *ReposTmp) NewFile() (f *os.File, err error) {
	tmp.mutex.Lock()
	defer tmp.mutex.Unlock()
	f, err = os.Create(fmt.Sprintf("%s%cblob%012d", tmp.DN,
		os.PathSeparator, tmp.i))
	tmp.i += 1
	return
}

type ReposUser struct {
	Key    *EncrPub
	String string
	ASN    struct {
		Auth        AuthPub
		Author      EncrPub
		Editors     []EncrPub
		Moderators  []EncrPub
		Subscribers []EncrPub
		User        string
	}
}

func NewReposUser(reposDN, suser string) (user *ReposUser, err error) {
	key, err := NewEncrPubString(suser)
	if err != nil {
		return
	}
	user = &ReposUser{
		Key:    key,
		String: suser,
	}
	defer func() {
		if err != nil {
			user.Key = nil
			user.ASN.Editors = nil
			user.ASN.Moderators = nil
			user.ASN.Subscribers = nil
			user = nil
		}
	}()
	_, err = ReadBlobContent(user.ASN.Auth[:],
		filepath.Join(reposDN, user.Expand("asn/auth")))
	if err != nil && !os.IsNotExist(err) {
		return
	}
	_, err = ReadBlobContent(user.ASN.Author[:],
		filepath.Join(reposDN, user.Expand("asn/author")))
	if err != nil && !os.IsNotExist(err) {
		return
	}
	user.ASN.Editors, err = ReadBlobKeyList(filepath.Join(reposDN,
		user.Expand("asn/editors")))
	if err != nil && !os.IsNotExist(err) {
		return
	}
	user.ASN.Moderators, err = ReadBlobKeyList(filepath.Join(reposDN,
		user.Expand("asn/moderators")))
	if err != nil && !os.IsNotExist(err) {
		return
	}
	user.ASN.Subscribers, err = ReadBlobKeyList(filepath.Join(reposDN,
		user.Expand("asn/subscribers")))
	if err != nil && !os.IsNotExist(err) {
		return
	}
	var b [256]byte
	n, err := ReadBlobContent(b[:],
		filepath.Join(reposDN, user.Expand("asn/user")))
	if err != nil {
		if os.IsNotExist(err) {
			user.ASN.User = "actual"
			err = nil
		}
	} else {
		user.ASN.User = string(b[:n])
	}
	return
}

// Expand converts the stringified user key to repos file name.
func (user *ReposUser) Expand(elements ...string) string {
	path := filepath.Join(ReposTopDN(user.String),
		ReposSubDFN(user.String))
	for _, x := range elements {
		path = filepath.Join(path, filepath.FromSlash(x))
	}
	return path
}

func (user *ReposUser) Free() {
	if user != nil {
		return
	}
	user.Key = nil
	user.ASN.Editors = nil
	user.ASN.Moderators = nil
	user.ASN.Subscribers = nil
}

type ReposUsers struct {
	Entry []*ReposUser
	mutex *sync.Mutex
}

func NewReposUsers(dn string) (users *ReposUsers, err error) {
	users = &ReposUsers{mutex: new(sync.Mutex)}
	var topdir, subdir []os.FileInfo
	var user *ReposUser
	defer func() {
		if err != nil {
			users.Free()
			users = nil
		}
		topdir = nil
		subdir = nil
		user = nil
	}()
	if topdir, err = ioutil.ReadDir(dn); err != nil {
		return
	}
	for _, fi := range topdir {
		if fi.IsDir() && len(fi.Name()) == reposTopSz {
			subdn := filepath.Join(dn, fi.Name())
			if subdir, err = ioutil.ReadDir(subdn); err != nil {
				return
			}
			for _, subfi := range subdir {
				if subfi.IsDir() && IsUserENT(subfi.Name()) {
					user, err = NewReposUser(dn,
						fi.Name()+subfi.Name())
					if err != nil {
						return
					}
					users.Entry = append(users.Entry, user)
				}
			}
		}
	}
	return
}

// Free repos user table to GC
func (users *ReposUsers) Free() {
	if users == nil {
		return
	}
	for i, e := range users.Entry {
		e.Free()
		users.Entry[i] = nil
	}
	users.Entry = nil
	users.mutex = nil
}

// LS repos user table
func (users *ReposUsers) LS() []byte {
	users.mutex.Lock()
	defer users.mutex.Unlock()
	n := len(users.Entry)
	out := make([]byte, 0, n*((EncrPubSz*2)+1))
	for _, user := range users.Entry {
		out = append(out, []byte(user.String)...)
		out = append(out, '\n')
	}
	return out
}

// Binary search for longest matching user key or string.
func (users *ReposUsers) Search(v interface{}) (user *ReposUser) {
	users.mutex.Lock()
	defer users.mutex.Unlock()
	n := len(users.Entry)
	switch t := v.(type) {
	case string:
		lent := len(t)
		i := sort.Search(n, func(i int) bool {
			return users.Entry[i].String >= t
		})
		if i < n && len(users.Entry[i].String) >= lent &&
			users.Entry[i].String[:lent] == t {
			user = users.Entry[i]
		}
	case *EncrPub:
		i := sort.Search(n, func(i int) bool {
			return bytes.Compare(users.Entry[i].Key[:], t[:]) >= 0
		})
		if i < n && *users.Entry[i].Key == *t {
			user = users.Entry[i]
		}
	default:
		panic("not key or string")
	}
	return
}

type Repos struct {
	DN    string
	Tmp   *ReposTmp
	Users *ReposUsers
}

func NewRepos(dn string) (repos *Repos, err error) {
	tmp, err := NewReposTmp(dn)
	if err != nil {
		return
	}
	users, err := NewReposUsers(dn)
	if err != nil {
		tmp.Free()
		return
	}
	repos = &Repos{
		DN:    dn,
		Tmp:   tmp,
		Users: users,
	}
	return
}

// DePrefix strips leading repos directory from pathname
func (repos *Repos) DePrefix(pn string) string {
	return pn[len(repos.DN)+1:]
}

// Expand converts the stringified user key or blob sum to respective repos
// directory and file name.
func (repos *Repos) Expand(hex string, elements ...string) string {
	path := filepath.Join(repos.DN, ReposTopDN(hex), ReposSubDFN(hex))
	for _, x := range elements {
		path = filepath.Join(path, filepath.FromSlash(x))
	}
	return path
}

// File blob with v contents in repos returning list of file links, sum and any
// error.  The first link name (unless it's a user mark) is the blob sum that
// the calling server should distribute to its mirrors. The server should send
// links named "asn/mark" to all users session. Any other links should be sent
// to the assciated owner and subscriber sessions.
func (repos *Repos) File(blob *Blob, v interface{}) (links []string, sum *Sum,
	err error) {
	blobli := len(blob.Name) - 1
	f, err := repos.Tmp.NewFile()
	if err != nil {
		return
	}
	fn := f.Name()
	sum, _, err = blob.SummingWriteContentsTo(f, v)
	f.Close()
	if err != nil {
		return
	}
	linkit := func(dst string) {
		if lerr := ReposLink(fn, dst); lerr != nil {
			panic(lerr)
		}
		links = append(links, dst)
	}
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
		syscall.Unlink(fn)
	}()
	ssum := sum.String()
	sumfn := repos.Expand(ssum)
	blobfn := blob.FN(ssum)
	if _, xerr := os.Stat(sumfn); xerr == nil {
		// already exists
		return
	}
	linkit(sumfn)
	author := repos.Users.Search(&blob.Author)
	if author == nil {
		author, err = repos.NewUser(&blob.Author)
	}
	owner := repos.Users.Search(&blob.Owner)
	if owner == nil {
		owner, err = repos.NewUser(&blob.Owner)
	}
	switch {
	case blob.Name == "" || blob.Name == "asn/messages/" ||
		blob.Name == "asn/messages":
		linkit(repos.Expand(author.String, "asn/messages", blobfn))
		if len(owner.ASN.Moderators) > 0 {
			for _, k := range owner.ASN.Moderators {
				linkit(repos.Expand(k.String(), "asn/messages",
					blobfn))
			}
		} else {
			for _, k := range owner.ASN.Subscribers {
				if k != *author.Key {
					linkit(repos.Expand(k.String(),
						"asn/messages", blobfn))
				}
			}
			if owner != author {
				linkit(repos.Expand(owner.String,
					"asn/messages", blobfn))
			}
		}
	case blob.Name == "asn/bridge" || blob.Name == "asn/bridge/":
		for _, k := range owner.ASN.Subscribers {
			if k != *author.Key {
				linkit(repos.Expand(k.String(), "asn/bridge",
					blobfn))
			}
		}
		// don't mirror or archive bridge messages
		syscall.Unlink(sumfn)
		links[0] = ""
	case blob.Name[blobli] == '/':
		linkit(repos.Expand(owner.String, blob.Name[:blobli], blobfn))
	case blob.Name == "asn/mark":
		mark := repos.Expand(owner.String, "asn/mark")
		// always overwrite current mark
		syscall.Unlink(mark)
		linkit(mark)
		if owner.ASN.User == "actual" {
			links[0] = ""
		}
	case blob.Name == "asn/removals":
		// FIXME rethink removals
	case blob.Name == "asn/approvals":
		// FIXME
	default:
		dst := repos.Expand(owner.String, blob.Name)
		if _, xerr := os.Stat(dst); xerr == nil {
			if blob.Time.After(BlobTime(dst)) {
				syscall.Unlink(dst)
				linkit(dst)
			} else { // don't dist older blob
				links = links[:0]
			}
		} else {
			linkit(dst)
		}
	}
	return
}

// Free repos cache
func (repos *Repos) Free() {
	if repos == nil {
		return
	}
	repos.Tmp.Free()
	repos.Users.Free()
	repos.Tmp = nil
	repos.Users = nil
}

func (repos *Repos) NewUser(v interface{}) (user *ReposUser, err error) {
	user = new(ReposUser)
	repos.Users.mutex.Lock()
	defer func() {
		repos.Users.mutex.Unlock()
		if err != nil {
			user = nil
		}
	}()
	var i int
	n := len(repos.Users.Entry)
	switch t := v.(type) {
	case string:
		i = sort.Search(n, func(i int) bool {
			return repos.Users.Entry[i].String >= t
		})
		user.String = t
		user.Key, err = NewEncrPubString(user.String)
	case *EncrPub:
		i = sort.Search(n, func(i int) bool {
			return bytes.Compare(repos.Users.Entry[i].Key[:],
				t[:]) >= 0
		})
		user.Key = t
		user.String = user.Key.String()
	default:
		err = os.ErrInvalid
	}
	if err != nil {
		return
	}
	if i == n {
		repos.Users.Entry = append(repos.Users.Entry, user)
	} else {
		repos.Users.Entry = append(repos.Users.Entry[:i],
			append([]*ReposUser{user},
				(repos.Users.Entry[i:])...)...)
	}
	userdn := repos.Expand(repos.Users.Entry[i].String)
	if _, err = os.Stat(userdn); err != nil {
		err = os.MkdirAll(userdn, ReposPerm)
	}
	return
}

func (repos Repos) ParsePath(pn string) (userOrSHA, remainder string) {
	if strings.HasPrefix(pn, repos.DN) {
		pn = repos.DePrefix(pn)
	}
	if pn[reposTopSz] != os.PathSeparator {
		remainder = pn
		return
	}
	topDN := pn[:reposTopSz]
	pn = pn[reposTopSz+1:]
	slash := strings.IndexByte(pn, os.PathSeparator)
	if IsHex(pn) {
		userOrSHA = topDN + pn
	} else if slash > 0 && IsHex(pn[:slash]) {
		userOrSHA = topDN + pn[:slash]
		remainder = pn[slash+1:]
	} else {
		userOrSHA = "Invalid repos path"
		remainder = topDN + pn
	}
	return
}

func (repos *Repos) Permission(blob *Blob, user *ReposUser,
	admin, service, login, ephemeral *EncrPub) error {
	if *login == *admin || *login == *service {
		return nil
	}
	if (blob.Name == "asn/mark" || blob.Name == "") &&
		(blob.Author == *login || blob.Author == *ephemeral) {
		return nil
	}
	if *login == blob.Owner || *login == user.ASN.Author {
		return nil
	}
	if KeysHasKey(user.ASN.Editors, login) {
		return nil
	}
	return os.ErrPermission
}

// Search the repos for the unique longest matching blob file.
func (repos *Repos) Search(x string) (match string, err error) {
	topdn := ReposTopDN(x)
	subdfn := ReposSubDFN(x)
	lensubdfn := len(subdfn)
	topf, err := os.Open(filepath.Join(repos.DN, topdn))
	if err != nil {
		return
	}
	defer topf.Close()
	for {
		var names []string
		names, err = topf.Readdirnames(16)
		if len(names) > 0 {
			for _, name := range names {
				if len(name) >= lensubdfn &&
					name[:lensubdfn] == subdfn {
					if match != "" {
						match = ""
						err = ErrAmbiguos
						return
					}
					match = filepath.Join(topf.Name(),
						name)
				}
			}
		} else {
			if err == io.EOF {
				err = nil
			}
			return
		}
	}
}

// ReposLink creates directories if required then hard links dst with src
func ReposLink(src, dst string) (err error) {
	dn := filepath.Dir(dst)
	if _, err = os.Stat(dn); err != nil {
		if !os.IsNotExist(err) {
			return
		}
		if err = os.MkdirAll(dn, ReposPerm); err != nil {
			return
		}
	}
	err = syscall.Link(src, dst)
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

// ReposSplitDFN returns the argument split into top and sub-directory or file
// (partial) name elements.
func ReposSplitDFN(arg string) (top, sub string) {
	return arg[:reposTopSz], arg[reposTopSz:]
}

// ReposSubDFN returns the argument's trailing sub directory or file
// (partial) name.
func ReposSubDFN(arg string) string {
	return arg[reposTopSz:]
}

// ReposTopDN returns the argument's top directory name
func ReposTopDN(arg string) string {
	return arg[:reposTopSz]
}

func PN(repos Reposer, args ...string) string {
	return filepath.Join(append([]string{repos.DN()}, args...)...)
}

func KeysHasKey(keys []EncrPub, x *EncrPub) bool {
	for _, k := range keys {
		if k == *x {
			return true
		}
	}
	return false
}
