// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"time"
	"github.com/google/syzkaller/pkg/log"
)

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

//modified by Rrooach
// func initMap(mmp map[string]int) {
// 	mmp = make(map[string]int)
// 	mmp["open"] = 1
// 	mmp["close"] = -1

// }

// func CheckMatch(callName string) int {

// }

// func TaskStateUpdate(task []*Prog, len int, ncalls int) []*Prog {
// 	CheckMatchNum := 0
// 	var callToidx map[string]int
// 	callToidx = initMap(callToidx)
// 	for _, prog := range task {
// 		for _, call := range prog.Calls {
// 			isExist := CheckMatch(call.Meta.CallName)
// 			if isExist == 1
// 				CheckMatchNum = CheckMatchNum | (1 << callToidx[call.Meta.CallName])
// 			if isExist == -1
// 				CheckMatchNum = CheckMatchNum ^ (1 << callToidx[call.Meta.CallName])
// 		}
// 		for i := 0; i < CheckMatchNum; i++ {
// 			tmp := 1<<i
// 			if tmp ^ CheckMatchNum == 1 {
// 				if len(p.Calls) < ncalls {
// 					generateCall()
// 				} 
// 			}
// 		}
// 	}
// }

func (target *Target) TaskGenerate(rs rand.Source, ncalls int, ct *ChoiceTable) []*Prog {
	var ProgList []*Prog
	rand.Seed(time.Now().Unix())
	ListLen := rand.Intn(8-2)+2
	
	for i := 0; i < ListLen; i++ {
		Prio := rand.Intn(100)
		p := &Prog{
			Target: target,
			Prio:   Prio,
		}
		r := newRand(target, rs)
		s := newState(target, ct, nil)
		
		for len(p.Calls) < ncalls {
			calls := r.generateCall(s, p, len(p.Calls))
			for _, c := range calls {
				s.analyze(c)
				log.Logf(0, "======calls = %v", c)
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
		ProgList = append(ProgList, p)
	}
	
	// ProgList = TaskStateUpdate(ProgList, ListLen, ncalls)
	return ProgList
}
