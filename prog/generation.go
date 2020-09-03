// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"fmt"
	"time"
)
//modified by Rrooach 
func (target *Target) GenerateTask(rs rand.Source, ncalls int, ct *ChoiceTable) *Task {
	var t *Task
	fmt.Println("123")
	rand.Seed(time.Now().Unix())
	tLen := rand.Intn(5)
	for i := 0; i < tLen; i++ {
		p := &Prog{
			Target: target,
		}
		r := newRand(target, rs)
		//real-time piro is [0, 99]
		p.Prio = uint32(r.Intn(100))
		s := newState(target, ct, nil)
		for len(p.Calls) < ncalls {
			calls := r.generateCall(s, p, len(p.Calls))
			for _, c := range calls {
				s.analyze(c)
				p.Calls = append(p.Calls, c)
			}
		}
		// For the last generated call we could get additional calls that create
		// resources and overflow ncalls. Remove some of these calls.
		// The resources in the last call will be replaced with the default values,
		// which is exactly what we want.
		for len(p.Calls) > ncalls {
			p.removeCall(ncalls - 1)
		}
		p.sanitizeFix()
		p.debugValidate()
		t.Progs = append(t.Progs, p) 
	} 
	fmt.Println("1233333")
	return t
} 

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.removeCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}
