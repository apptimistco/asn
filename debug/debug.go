// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package debug provides log and trace facilities as enabled or disabled with
// these build tags: fixme, diag, nolog, notrace.
package debug

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"path/filepath"
	"sync"
)

const (
	DefaultDepth = 2
	TraceSize    = 64
)

func init() {
	sl, err := syslog.New(syslog.LOG_ERR|syslog.LOG_USER, tag())
	if err != nil {
		panic(err)
	}
	Failure = &Logger{log.New(sl, "", log.Lshortfile)}
}

// Create (or truncate) then chmod the named log file.
func Create(fn string) (*os.File, error) {
	f, err := os.Create(fn)
	if err == nil {
		if err = f.Chmod(0664); err != nil {
			f.Close()
			f = nil
		}
	}
	return f, err
}

/*
FilterDepth strips any such parameter given as the first or last item of the
variadic argument.

Usage:

	debuf.FilterDepth(debug.Depth(3), err)
*/
func FilterDepth(v ...interface{}) (int, []interface{}) {
	if d, ok := v[0].(Depth); ok {
		return int(d) + 1, v[1:]
	} else if i := len(v) - 1; i > 0 {
		if d, ok := v[i].(Depth); ok {
			return int(d) + 1, v[:i]
		}
	}
	return DefaultDepth, v
}

// Redirect all debug loggers.
func Redirect(v interface{}) error {
	for _, l := range []*Logger{Failure, Fixme, Diag, Log} {
		if err := l.Redirect(v); err != nil {
			return err
		}
	}
	return nil
}

/*
Include Debug as an annonymous member of any structure to add
FIXME[f], Diag[f], Log, and Trace methods.

Usage:

	var foo struct {
		debug.Debug
		...
	}

	...

		foo.Debug.Set("foo")
		...
		foo.FIXME(...)
		foo.Diag(...)
		foo.Log(...)
		foo.Trace(...)

*/
type Debug string

/*
Depth strips any such parameter given as the first or last item of the variadic
argument.

Usage:

	foo.Diag(debug.Depth(3), err)
*/
func (x *Debug) Depth(v ...interface{}) (int, []interface{}) {
	return FilterDepth(v...)
}

// Diag, after stripping any leading or trailing DEPTH parameters, sends
// Println(v...) output to the Diag logger; either syslog INFO or a redirected
// file.
func (x *Debug) Diag(v ...interface{}) {
	if Diag == nil {
		return
	}
	depth, v := x.Depth(v...)
	Diag.Output(depth, x.String()+" "+fmt.Sprintln(v...))
}

// Diagf sends Printf(format, v...) output to the Diag logger.
func (x *Debug) Diagf(format string, v ...interface{}) {
	if Diag == nil {
		return
	}
	depth, v := x.Depth(v...)
	Diag.Output(depth, x.String()+" "+fmt.Sprintf(format, v...))
}

// Failure, after stripping any leading or trailing DEPTH parameters, sends
// Println(v...) output to the Failure logger; either syslog DEBUG or a
// redirected file.
func (x *Debug) Failure(v ...interface{}) {
	if Failure == nil {
		return
	}
	depth, v := x.Depth(v...)
	Failure.Output(depth, x.String()+" failure "+fmt.Sprintln(v...))
}

// Failure sends Printf(format, v...) output to the Failure logger.
func (x *Debug) Failuref(format string, v ...interface{}) {
	if Failure == nil {
		return
	}
	depth, v := x.Depth(v...)
	Failure.Output(depth, x.String()+" failure "+fmt.Sprintf(format, v...))
}

// Fixme, after stripping any leading or trailing DEPTH parameters, sends
// Println(v...) output to the Fixme logger; either syslog DEBUG or a
// redirected file.
func (x *Debug) Fixme(v ...interface{}) {
	if Fixme == nil {
		return
	}
	depth, v := x.Depth(v...)
	Fixme.Output(depth, x.String()+" fixme "+fmt.Sprintln(v...))
}

// Fixmef sends Printf(format, v...) output to the Fixme logger.
func (x *Debug) Fixmef(format string, v ...interface{}) {
	if Fixme == nil {
		return
	}
	depth, v := x.Depth(v...)
	Fixme.Output(depth, x.String()+" fixme "+fmt.Sprintf(format, v...))
}

// Log sends Println(v...) output to the logger; either syslog NOTICE or
// a redirected file.
func (x *Debug) Log(v ...interface{}) {
	if Log == nil {
		return
	}
	Log.Output(2, x.String()+" "+fmt.Sprintln(v...))
}

// Logf sends Printf(format, v...) output to the logger.
func (x *Debug) Logf(format string, v ...interface{}) {
	if Log == nil {
		return
	}
	Log.Output(2, x.String()+" "+fmt.Sprintf(format, v...))
}

// Reset the prefix.
func (x *Debug) Reset() {
	*x = Debug("")
}

// Set the prefix.
func (x *Debug) Set(v interface{}) (err error) {
	if s, ok := v.(string); ok {
		*x = Debug(s)
	} else {
		err = os.ErrInvalid
	}
	return
}

// String returns prefix.
func (x *Debug) String() string {
	return string(*x)
}

// Trace adds Println(v...) output to the circular ring.
func (x *Debug) Trace(v ...interface{}) {
	if Diag == nil || Trace == nil {
		return
	}
	if id, isId := v[0].(Id); isId {
		if _, filtered := Trace.filter[id]; filtered {
			return
		}
		v = v[1:]
	}
	Trace.Lock()
	defer Trace.Unlock()
	Trace.ring[Trace.i].Reset()
	fmt.Fprint(Trace, x.String(), " ")
	fmt.Fprintln(Trace, v...)
	Diag.Output(2, Trace.ring[Trace.i].String())
	Trace.i += 1
	if Trace.i == len(Trace.ring) {
		Trace.i = 0
	}
}

// Depth may be included as the first or last variadic parameter to the Diag
// and FIXME methods to change the back trace from the default, 2.
type Depth int

// If the first (*Debug).Trace() parameter is an Id, it's used as a key in the
// trace filter map that qualifies whether the remaining variadic arguments are
// Println()'d to the trace ring.
type Id uint8

// Logger is a wrapper for the standard library.
type Logger struct {
	*log.Logger
}

var Failure, Fixme, Diag, Log *Logger

// Redirect output to given or named file.
func (l *Logger) Redirect(v interface{}) error {
	if l == nil {
		return nil
	}
	flags := l.Flags()
	switch t := v.(type) {
	default:
		return os.ErrInvalid
	case nil:
		*l = Logger{log.New(ioutil.Discard, "", flags)}
	case io.Writer:
		*l = Logger{log.New(t, "", flags)}
	case string:
		if t == os.DevNull {
			*l = Logger{log.New(ioutil.Discard, "", flags)}
			return nil
		}
		f, err := Create(t)
		if err != nil {
			return err
		}
		*l = Logger{log.New(f, "", flags)}
	}
	return nil
}

func (l *Logger) Write(b []byte) (int, error) {
	if l == nil {
		return 0, nil
	}
	l.Output(2, string(b))
	return len(b), nil
}

type Tracer struct {
	sync.Mutex
	ring   []*bytes.Buffer
	filter map[Id]struct{}
	i      int
}

var Trace = &Tracer{}

// Filter tracing of the given Id.
func (trace *Tracer) Filter(id Id) {
	if trace == nil {
		return
	}
	trace.filter[id] = struct{}{}
}

// Reset and resize the trace ring.
func (trace *Tracer) Resize(n int) {
	if trace == nil {
		return
	}
	trace.Lock()
	defer trace.Unlock()
	if len(trace.ring) > n {
		trace.ring = trace.ring[:n]
	} else {
		for i := len(trace.ring); i < n; i++ {
			trace.ring = append(trace.ring, &bytes.Buffer{})
		}
	}
	for _, b := range trace.ring {
		b.Reset()
	}
}

// Unfilter tracing of the given Id.
func (trace *Tracer) Unfilter(id Id) {
	if trace == nil {
		return
	}
	delete(trace.filter, id)
}

// Write to the current ring buffer.
func (trace *Tracer) Write(b []byte) (int, error) {
	if trace == nil {
		return 0, nil
	}
	return trace.ring[trace.i].Write(b)
}

// LIFO write each non-empty trace ring buffer to the given writer.
func (trace *Tracer) WriteTo(w io.Writer) (int64, error) {
	var total int64
	if trace == nil {
		return 0, nil
	}
	wf := func(i int) error {
		if trace.ring[i].Len() > 0 {
			b := trace.ring[i]
			n, err := b.WriteTo(w)
			b.Reset()
			if err != nil {
				return err
			} else {
				total += n
			}
		}
		return nil
	}
	for i := trace.i; i < len(trace.ring); i++ {
		if err := wf(i); err != nil {
			return total, err
		}
	}
	if trace.i > 0 {
		for i := 0; i < trace.i; i++ {
			if err := wf(i); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

var (
	once sync.Once
	stag string
)

func tag() string {
	once.Do(func() { stag = filepath.Base(os.Args[0]) })
	return stag
}
