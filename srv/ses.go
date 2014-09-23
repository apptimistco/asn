// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"github.com/apptimistco/asn"
	"github.com/apptimistco/encr"
)

type ses struct {
	asn *asn.ASN

	peer, user encr.Pub
}

var poolSes chan *ses

func init() { poolSes = make(chan *ses, 16) }

// del[ete] an ses
func delSes(p *ses) {
	if p == nil {
		return
	}
	if p.asn != nil {
		p.asn.Free()
		p.asn = nil
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
	return &ses{asn: asn.NewASN()}
}

// pull an ses from the pool or create a new one if necessary.
func pullSes() (p *ses) {
	select {
	case p = <-poolSes:
		p.asn = asn.NewASN()
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
		p.asn.Free()
		p.asn = nil
	default:
		delSes(p)
	}
	*pp = nil
}
