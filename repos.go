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
	"time"
)

const (
	ReposPerm      = os.FileMode(0770)
	reposPS        = string(os.PathSeparator)
	reposTopSz     = 2
	reposAsnDN     = "asn"
	reposBridgeDN  = "bridge"
	reposTmpDN     = "tmp"
	reposTmpPre    = "tmp_"
	reposTmpPat    = reposTmpDN + reposPS + reposTmpPre
	reposBridgePat = reposAsnDN + reposPS + reposBridgeDN + reposPS
)

var (
	ErrAmbiguos = errors.New("Ambiguous USER or SHA")
	ErrNOENT    = errors.New("No such USER, SHA or FILE")
)

type ReposTmp struct {
	DN    string
	i     int
	mutex *sync.Mutex
}

func (tmp *ReposTmp) free() {
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
	f, err = os.Create(fmt.Sprintf("%s%ctmp_%012d", tmp.DN,
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
		Editors     EncrPubList
		Moderators  EncrPubList
		Subscribers EncrPubList
		User        string
	}
}

// expand converts the stringified user key to repos file name.
func (user *ReposUser) expand(elements ...string) string {
	path := filepath.Join(user.TopDN(), user.SubDN())
	for _, x := range elements {
		path = filepath.Join(path, filepath.FromSlash(x))
	}
	return path
}

func (user *ReposUser) free() {
	if user != nil {
		return
	}
	user.Key = nil
	user.ASN.Editors = nil
	user.ASN.Moderators = nil
	user.ASN.Subscribers = nil
}

func (user *ReposUser) SubDN() string { return user.String[reposTopSz:] }
func (user *ReposUser) TopDN() string { return user.String[:reposTopSz] }

type ReposUsers struct {
	Entry []*ReposUser
	mutex *sync.Mutex
}

func (users *ReposUsers) add(user *ReposUser) {
	users.Entry = append(users.Entry, user)
}

func (users *ReposUsers) free() {
	if users == nil {
		return
	}
	for i, e := range users.Entry {
		e.free()
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
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
			repos.Free()
			repos = nil
		}
	}()
	repos = &Repos{
		DN: dn,
	}
	repos.newTmp()
	repos.newUsers()
	return
}

// DePrefix strips leading repos directory from pathname
func (repos *Repos) DePrefix(pn string) string {
	return pn[len(repos.DN)+1:]
}

// expand converts the stringified user key or blob sum to respective repos
// directory and file name.
func (repos *Repos) Expand(hex string, elements ...string) string {
	path := repos.join(reposTopDN(hex), reposSubDFN(hex))
	for _, x := range elements {
		path = filepath.Join(path, filepath.FromSlash(x))
	}
	return path
}

func (repos *Repos) load(user *ReposUser) {
	user.Key = newEncrPub(user.String)
	user.ASN.Auth.fromBlob(repos.join(user.expand("asn/auth")))
	user.ASN.Author.fromBlob(repos.join(user.expand("asn/author")))
	user.ASN.Editors.fromBlob(repos.join(user.expand("asn/editors")))
	user.ASN.Moderators.fromBlob(repos.join(user.expand("asn/moderators")))
	user.ASN.Subscribers.fromBlob(repos.join(user.expand("asn/subscribers")))
	user.ASN.User = blobGets(repos.join(user.expand("asn/user")))
	if user.ASN.User == "" {
		user.ASN.User = "actual"
	}
}

// File blob with v contents in repos returning file sum, name, and any error.
// Returns empty name if file already exists.
func (repos *Repos) File(blob *Blob, v interface{}) (sum *Sum, fn string,
	err error) {
	tf, err := repos.Tmp.NewFile()
	if err != nil {
		return
	}
	tfn := tf.Name()
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
		syscall.Unlink(tfn)
	}()
	sum, _, err = blob.SummingWriteContentsTo(tf, v)
	tf.Close()
	if err != nil {
		return
	}
	fn = repos.Expand(sum.String())
	if _, xerr := os.Stat(fn); xerr == nil {
		// already exists
		fn = ""
		return
	}
	reposLN(tfn, fn)
	return
}

// Filter all REPOS/SHA files after epoch
func (repos *Repos) Filter(epoch time.Time,
	f func(fn string) error) (err error) {
	var (
		topdir, subdir *os.File
		topfis, subfis []os.FileInfo
	)
	topdir, err = os.Open(repos.DN)
	if err != nil {
		return
	}
	defer func() {
		if err == io.EOF {
			err = nil
		}
		topdir.Close()
		subdir.Close()
		topdir = nil
		subdir = nil
		topfis = nil
		subfis = nil
	}()
topdirloop:
	for {
		topfis, err = topdir.Readdir(16)
		if err != nil {
			break topdirloop
		}
	topfiloop:
		for _, topfi := range topfis {
			if !reposIsTopDir(topfi) {
				continue topfiloop
			}
			subfn := repos.join(topfi.Name())
			if subdir, err = os.Open(subfn); err != nil {
				return
			}
		subdirloop:
			for {
				subfis, err = subdir.Readdir(16)
				if err == io.EOF {
					break subdirloop
				}
				if err != nil {
					return
				}
			subfiloop:
				for _, subfi := range subfis {
					if !reposIsBlob(subfi) {
						continue subfiloop
					}
					fn := repos.join(topfi.Name(),
						subfi.Name())
					if epoch.IsZero() ||
						BlobTime(fn).After(epoch) {
						if err = f(fn); err != nil {
							return
						}
					}
				}
			}
		}
		topfis, err = topdir.Readdir(16)
	}
	return
}

// MkLinks to given REPOS/SHA file.  The first link name (unless it's a user
// mark) is the blob sum that the calling server should distribute to its
// mirrors. The server should send links named "asn/mark" to all users session.
// Any other links should be sent to the associated owner and subscriber
// sessions.
func (repos *Repos) MkLinks(blob *Blob, sum *Sum, fn string) (links []*PDU,
	err error) {
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
	}()
	blobli := len(blob.Name) - 1
	switch {
	case blob.Name == "" || blob.Name == "asn/messages/" ||
		blob.Name == "asn/messages":
		links = repos.mkMessageLinks(blob, sum, fn)
	case blob.Name == "asn/bridge" || blob.Name == "asn/bridge/":
		links = repos.mkBridgeLinks(blob, sum, fn)
	case blob.Name == "asn/mark":
		links = repos.mkMarkLinks(blob, sum, fn)
	case blob.Name == "asn/removals":
		links = repos.mkRemovalLinks(blob, sum, fn)
	case blob.Name == "asn/approvals":
		links = repos.mkForwardLinks(blob, sum, fn)
	case blob.Name[blobli] == '/':
		links = repos.mkDerivedLinks(blob, sum, fn, blob.Name[:blobli])
	default:
		links = repos.mkNamedLinks(blob, sum, fn)
	}
	return
}

// mkBridgeLinks to all subscriber's "asn/bridge/EPOCH_SHA".
// Don't mirror or archive bridge messages by removing REPOS/SHA.
func (repos *Repos) mkBridgeLinks(blob *Blob, sum *Sum, sumFN string) []*PDU {
	owner := repos.searchOrNewUser(&blob.Owner)
	blobFN := blob.FN(sum.String())
	n := len(owner.ASN.Subscribers)
	if n == 0 {
		return nil
	}
	links := make([]*PDU, n+1)
	for i, k := range owner.ASN.Subscribers {
		user := repos.searchOrNewUser(k)
		fn := repos.join(user.expand("asn/bridge", blobFN))
		reposLN(sumFN, fn)
		links[i+1] = NewPDUFN(fn)
	}
	syscall.Unlink(sumFN)
	return links
}

func (repos *Repos) mkDerivedLinks(blob *Blob, sum *Sum,
	sumFN, dn string) []*PDU {
	owner := repos.searchOrNewUser(&blob.Owner)
	fn := repos.join(owner.expand(dn, blob.FN(sum.String())))
	reposLN(sumFN, fn)
	return []*PDU{
		0: NewPDUFN(sumFN),
		1: NewPDUFN(fn),
	}
}

func (repos *Repos) mkNamedLinks(blob *Blob, sum *Sum, sumFN string) []*PDU {
	owner := repos.searchOrNewUser(&blob.Owner)
	fn := repos.join(owner.expand(blob.Name))
	if _, xerr := os.Stat(fn); xerr == nil {
		if blob.Time.After(BlobTime(fn)) {
			syscall.Unlink(fn)
			reposLN(sumFN, fn)
			return []*PDU{
				0: NewPDUFN(sumFN),
				1: NewPDUFN(fn),
			}
		} else { // don't dist or link older blob
			return nil
		}
	}
	reposLN(sumFN, fn)
	return []*PDU{
		0: NewPDUFN(sumFN),
		1: NewPDUFN(fn),
	}
}

// forward the moderator approved messages
func (repos *Repos) mkForwardLinks(blob *Blob, sum *Sum, sumFN string) []*PDU {
	var sums Sums
	sums.fromBlob(sumFN)
	defer func() { sums = nil }()
	links := []*PDU{NewPDUFN(sumFN)}
	for _, xsum := range sums {
		xssum := xsum.String()
		xsumFN := repos.Expand(xssum)
		xsumf, err := os.Open(xsumFN)
		if err != nil {
			panic(err)
		}
		xblob, err := NewBlobFrom(xsumf)
		xsumf.Close()
		if err != nil {
			panic(err)
		}
		xowner := repos.Users.Search(&xblob.Owner)
		xblobfn := xblob.FN(xssum)
		for _, xmod := range xowner.ASN.Moderators {
			if blob.Author.Equal(&xmod) {
				for _, sub := range xowner.ASN.Subscribers {
					user := repos.Users.Search(&sub)
					fn := repos.join(user.expand(
						"asn/messages", xblobfn))
					reposLN(xsumFN, fn)
					links = append(links, NewPDUFN(fn))
				}
			}
		}
	}
	return links
}

// File mark blob by always overwriting current mark.
// Also, don't mirror "actual" user marks.
func (repos *Repos) mkMarkLinks(blob *Blob, sum *Sum, sumFN string) []*PDU {
	owner := repos.searchOrNewUser(&blob.Owner)
	fn := repos.join(owner.expand("asn/mark"))
	syscall.Unlink(fn)
	reposLN(sumFN, fn)
	if owner.ASN.User == "actual" {
		return []*PDU{
			0: nil,
			1: NewPDUFN(fn),
		}
	}
	return []*PDU{
		0: NewPDUFN(sumFN),
		1: NewPDUFN(fn),
	}
}

// if necessary, forward messages through moderators; otherwise, directly link
// as author, owner, and subscriber's "asn/messages/EPOCH_SHA"
func (repos *Repos) mkMessageLinks(blob *Blob, sum *Sum, sumFN string) []*PDU {
	author := repos.searchOrNewUser(&blob.Author)
	owner := repos.searchOrNewUser(&blob.Owner)
	blobFN := blob.FN(sum.String())
	authorFN := repos.join(author.expand("asn/messages", blobFN))
	ownerFN := repos.join(owner.expand("asn/messages", blobFN))
	reposLN(sumFN, authorFN)
	if n := len(owner.ASN.Moderators); n > 0 {
		links := make([]*PDU, n+2)
		links[0] = NewPDUFN(sumFN)
		links[1] = NewPDUFN(authorFN)
		for i, k := range owner.ASN.Moderators {
			user := repos.searchOrNewUser(k)
			fn := repos.join(user.expand("asn/messages", blobFN))
			reposLN(sumFN, fn)
			links[i+2] = NewPDUFN(fn)
		}
		return links
	} else if n = len(owner.ASN.Subscribers); n > 0 {
		var (
			o     int
			links []*PDU
		)
		if !owner.Key.Equal(author.Key) {
			o = 3
			links = make([]*PDU, n+o)
			links[0] = NewPDUFN(sumFN)
			links[1] = NewPDUFN(authorFN)
			links[2] = NewPDUFN(ownerFN)
		} else {
			links = make([]*PDU, n+o)
			links[0] = NewPDUFN(sumFN)
			links[1] = NewPDUFN(authorFN)
		}
		for i, k := range owner.ASN.Subscribers {
			if k != *author.Key {
				user := repos.searchOrNewUser(k)
				fn := repos.join(user.expand("asn/messages",
					blobFN))
				reposLN(sumFN, fn)
				links[i+o] = NewPDUFN(fn)
			}
		}
		return links
	} else if !owner.Key.Equal(author.Key) {
		reposLN(sumFN, ownerFN)
		return []*PDU{
			NewPDUFN(sumFN),
			NewPDUFN(authorFN),
			NewPDUFN(ownerFN),
		}
	}
	return []*PDU{
		NewPDUFN(sumFN),
		NewPDUFN(authorFN),
	}
}

// File remove blob and unlink it's referenced blobs
func (repos *Repos) mkRemovalLinks(blob *Blob, sum *Sum, sumFN string) []*PDU {
	// FIXME
	return nil
}

func (repos *Repos) Free() {
	if repos == nil {
		return
	}
	repos.Tmp.free()
	repos.Users.free()
	repos.Tmp = nil
	repos.Users = nil
}

func (repos *Repos) join(elements ...string) string {
	return repos.DN + reposPS + filepath.Join(elements...)
}

func (repos *Repos) newTmp() {
	tmpDN := repos.join("tmp")
	x, err := ioutil.ReadDir(tmpDN)
	if err == nil {
		// flush hanging tmp files
		for _, fi := range x {
			syscall.Unlink(fi.Name())
		}
		x = nil
	} else if os.IsNotExist(err) {
		if err = os.MkdirAll(tmpDN, ReposPerm); err != nil {
			panic(err)
		}
	}
	repos.Tmp = &ReposTmp{
		DN:    tmpDN,
		i:     0,
		mutex: new(sync.Mutex),
	}
}

// NewUser creates a cached user and repos directory
func (repos *Repos) NewUser(v interface{}) (user *ReposUser, err error) {
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
	}()
	user = repos.newUser(v)
	return
}

// newUser will panic on error so the calling function must recover.
func (repos *Repos) newUser(v interface{}) *ReposUser {
	user := new(ReposUser)
	repos.Users.mutex.Lock()
	defer repos.Users.mutex.Unlock()
	var i int
	n := len(repos.Users.Entry)
	switch t := v.(type) {
	case string:
		i = sort.Search(n, func(i int) bool {
			return repos.Users.Entry[i].String >= t
		})
		user.String = t
		user.Key = newEncrPub(user.String)
	case *EncrPub:
		i = sort.Search(n, func(i int) bool {
			return bytes.Compare(repos.Users.Entry[i].Key[:],
				t[:]) >= 0
		})
		user.Key = t
		user.String = user.Key.String()
	default:
		panic(os.ErrInvalid)
	}
	if i == n {
		repos.Users.Entry = append(repos.Users.Entry, user)
	} else {
		repos.Users.Entry = append(repos.Users.Entry[:i],
			append([]*ReposUser{user},
				(repos.Users.Entry[i:])...)...)
	}
	userdn := repos.Expand(repos.Users.Entry[i].String)
	if _, err := os.Stat(userdn); err != nil {
		if err = os.MkdirAll(userdn, ReposPerm); err != nil {
			user = nil
			panic(err)
		}
	}
	return user
}

func (repos *Repos) newUsers() {
	repos.Users = &ReposUsers{
		mutex: new(sync.Mutex),
	}
	var (
		topdir []os.FileInfo
		subdir []os.FileInfo
		err    error
	)
	defer func() {
		topdir = nil
		subdir = nil
	}()
	if topdir, err = ioutil.ReadDir(repos.DN); err != nil {
		panic(err)
	}
	for _, fi := range topdir {
		if fi.IsDir() && len(fi.Name()) == reposTopSz {
			subdn := repos.join(fi.Name())
			if subdir, err = ioutil.ReadDir(subdn); err != nil {
				panic(err)
			}
			for _, sub := range subdir {
				if sub.IsDir() && reposIsUser(sub.Name()) {
					user := &ReposUser{
						String: fi.Name() + sub.Name(),
					}
					repos.load(user)
					repos.Users.add(user)
					user = nil
				}
			}
		}
	}
	return
}

func (repos Repos) ParsePath(pn string) (usersum, remainder string) {
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
		usersum = topDN + pn
	} else if slash > 0 && IsHex(pn[:slash]) {
		usersum = topDN + pn[:slash]
		remainder = pn[slash+1:]
	} else {
		usersum = "Invalid repos path"
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
	if user.ASN.Editors.Has(login) {
		return nil
	}
	return os.ErrPermission
}

// Search the repos for the unique longest matching blob file.
func (repos *Repos) Search(x string) (match string, err error) {
	topdn := reposTopDN(x)
	subdfn := reposSubDFN(x)
	lensubdfn := len(subdfn)
	topf, err := os.Open(repos.join(topdn))
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
					match = repos.join(topdn, name)
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

func (repos *Repos) searchOrNewUser(v interface{}) *ReposUser {
	user := repos.Users.Search(v)
	if user == nil {
		user = repos.newUser(v)
	}
	return user
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

func reposIsTmpFN(fn string) bool {
	for _, pat := range []string{
		reposTmpPat,
		reposBridgePat,
	} {
		if i := strings.Index(fn, pat); i > 0 {
			return true
		}
	}
	return false
}

func reposIsTopDir(fi os.FileInfo) bool {
	fn := fi.Name()
	return fi.IsDir() && len(fn) == 2 && IsHex(fn)
}

func reposIsBlob(fi os.FileInfo) bool {
	fn := fi.Name()
	return !fi.IsDir() && len(fn) == 2*(SumSz-1) && IsHex(fn)
}

func reposIsUser(fn string) bool {
	return IsHex(fn) && len(fn) == 2*(EncrPubSz-1)
}

// reposLN creates directories if required then hard links dst with src.
// reposLN panic's on error so the calling function must recover.
func reposLN(src, dst string) {
	dn := filepath.Dir(dst)
	if _, err := os.Stat(dn); err != nil {
		if !os.IsNotExist(err) {
			panic(err)
		}
		if err := os.MkdirAll(dn, ReposPerm); err != nil {
			panic(err)
		}
	}
	if err := syscall.Link(src, dst); err != nil {
		panic(err)
	}
}

// reposSubDFN returns the argument's trailing sub directory or file
// (partial) name.
func reposSubDFN(arg string) string {
	return arg[reposTopSz:]
}

// reposTopDN returns the argument's top directory name
func reposTopDN(arg string) string {
	return arg[:reposTopSz]
}
