// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"github.com/apptimistco/asn"
)

type ses struct {
	asn *asn.ASN
}

var poolSes chan *ses

func init() { poolSes = make(chan *ses, 16) }

// del[ete] an ses
func delSes(p *ses) {
	if p == nil {
		return
	}
	if p.asn != nil {
		asn.Push(&p.asn)
	}
}

// flush the ses pool.
func flushSes() {
	for {
		select {
		case p := <-poolSes:
			delSes(p)
		default:
			return
		}
	}
}

func newSes() *ses {
	return &ses{asn: asn.Pull()}
}

// pull an ses from the pool or create a new one if necessary.
func pullSes() (p *ses) {
	select {
	case p = <-poolSes:
		p.asn = asn.Pull()
	default:
		p = newSes()
	}
	return
}

// push the double-indirect ses back to pool or release it to GC if full;
// then nil its reference.
func pushSes(pp **ses) {
	p := *pp
	if p == nil {
		return
	}
	select {
	case poolSes <- p:
		asn.Push(&p.asn)
	default:
		delSes(p)
	}
	*pp = nil
}
