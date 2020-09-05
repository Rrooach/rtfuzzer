// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	env               *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsNoCollide := *fuzzer.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	log.Logf(0, "proc:64")
	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i := 0; ; i++ {
		log.Logf(0, "proc:64 %v", i)
		item := proc.fuzzer.workQueue.dequeue() 
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				log.Logf(0, "proc:78")
				// proc.triageInput(item)
				proc.TasktriageInput(item)
				log.Logf(0, "proc:77")
			case *WorkCandidate:
				log.Logf(0, "proc:83")
				// proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				// if item.task == nil {
				// 	log.Logf(0, "proc:411")
				// 	item.task = append(item.task, item.p)
				// }
				proc.Taskexecute(proc.execOpts, item.task, item.flags, StatCandidate)
				log.Logf(0, "proc:81")
			case *WorkSmash:
				log.Logf(0, "proc:88")
				// proc.smashInput(item)
				proc.TasksmashInput(item)
				log.Logf(0, "proc:85")
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}
		log.Logf(0, "proc:93 %v", i)
		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		log.Logf(0, "proc:96")
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			log.Logf(0, "proc:98")
			// Generate a new prog.
			// p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			task := proc.fuzzer.target.TaskGenerate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(0, "proc:102")
			log.Logf(1, "#%v: generated", proc.pid)
			// proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			proc.Taskexecute(proc.execOpts, task, ProgNormal, StatGenerate)
			log.Logf(0, "proc:106")
		} else {
			// Mutate an existing prog.
			// modified by Rrooach
			log.Logf(0, "proc:110")
			rand.Seed(time.Now().Unix())
			taskLeng := rand.Intn(8-2) + 2
			var task []*prog.Prog
			for i := 0; i < taskLeng; i++ {
				p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
				log.Logf(0, "proc:116")
				task = append(task, p)
			}
			for _, p := range task {
				p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
				log.Logf(0, "proc:121")
			}
			// p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			// p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			// proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			proc.Taskexecute(proc.execOpts, task, ProgNormal, StatFuzz)
			log.Logf(0, "proc:128")
		}
	}
}

//modified by Rrooach
func (proc *Proc) TasktriageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)
	//	wg := sync.WaitGroup{}
	//	wg.Add(len(item.task))
	// ch  := make(chan ProgTypes, len(item.task))
	log.Logf(0, "proc:146")
	//	for _, p := range item.task {
	log.Logf(0, "proc:148")
	tempItem := &WorkTriage{
		p:     item.task[item.pIndex],
		call:  item.call,
		info:  item.info,
		flags: item.flags,
		// pIndex: item.pIndex,
	}
	log.Logf(0, "proc:158")
	//	go func() {
	proc.triageInput(tempItem)
	// wg.Done()
	// }()
	// 	log.Logf(0, "proc:159")
	// }
	// wg.Wait()
	log.Logf(0, "proc:163")
	// for i := 0; i < len(item.task); i++ {
	// 	log.Logf(0, "proc:165")
	if item.flags&ProgSmashed == 0 {
		log.Logf(0, "proc:167")
		proc.fuzzer.workQueue.enqueue(&WorkSmash{
			task: item.task,
			p:    item.task[item.pIndex],
			call: item.call,
		})
	}
	// 	break
	// 	log.Logf(0, "proc:174")
	// }
	// 	log.Logf(0, "proc:176")
	// 	}
	// for flags := range ch {
	// 	log.Logf(0, "proc:165")
	// 	if flags&ProgSmashed == 0 {
	// 		log.Logf(0, "proc:167")
	// 		proc.fuzzer.workQueue.enqueue(&WorkSmash{
	// 													task: 	item.task,
	// 													p:		item.p,
	// 													call:	item.call,
	// 												})
	// 		break
	// 		log.Logf(0, "proc:174")
	// 	}
	// }
}

// func (p *Proc) triageInputWrapper()item *WorkTriage, ch chan ProgTypes{
// 	ch <- p.triageInput(item)
// }

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(0, "proc:195")
	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	log.Logf(0, "proc:198")
	if newSignal.Empty() {
		return
	}
	log.Logf(0, "proc:203")
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	log.Logf(0, "proc:218")
	for i := 0; i < signalRuns; i++ {
		log.Logf(0, "proc:220 %v, %v, %v", proc.execOptsCover, item.p, StatTriage)

		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		log.Logf(0, "proc:222")
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		log.Logf(0, "proc:231")
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)
		log.Logf(0, "proc:234")
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
		log.Logf(0, "proc:241")
	}
	log.Logf(0, "proc:165")
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}
	log.Logf(0, "proc:261")
	data := item.p.Serialize()
	sig := hash.Hash(data)
	log.Logf(0, "proc:264")
	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})
	log.Logf(0, "proc:272")
	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)
	log.Logf(0, "proc:275")
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

//modified by Rrooach
func (proc *Proc) TasksmashInput(item *WorkSmash) {
	// var wg sync.WaitGroup
	// for _, p := range item.task {
	// 	wg.Add(1)
	tempItem := &WorkSmash{
		p:    item.p,
		call: item.call,
	}
	//		go func(){
	proc.smashInput(tempItem)
	//			wg.Done()
	//		}()
	//	wg.Wait()
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		opts := *proc.execOpts
		opts.Flags |= ipc.FlagInjectFault
		opts.FaultCall = call
		opts.FaultNth = nth
		info := proc.executeRaw(&opts, p, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

//modified by Rrooach
func (proc *Proc) Taskexecute(execOpts *ipc.ExecOpts, task []*prog.Prog, flags ProgTypes, stat Stat) []*ipc.ProgInfo {
	var infos []*ipc.ProgInfo
	log.Logf(0, "proc:410")
	ch := make(chan *ipc.ProgInfo, len(task))
	wg := sync.WaitGroup{}
	log.Logf(0, "proc:413 %v", task)
	for _, p := range task {
		log.Logf(0, "proc:415")
		wg.Add(1)
		log.Logf(0, "proc:416")
		go func() {
			proc.TaskexecuteRaw(execOpts, p, stat, ch)
			wg.Done()
		}()
		log.Logf(0, "proc:418")
	}
	log.Logf(0, "proc:421")
	wg.Wait()
	log.Logf(0, "proc:423")
	cnt := 0
	for i := 0; i < len(task); i++ {
		info := <-ch
		infos = append(infos, info)

		log.Logf(0, "proc:431 cnt=%v", cnt)
		cnt++
	} 
	log.Logf(0, "##########################\nproc:427")
	for j, p := range task {
		log.Logf(0, "proc:430 %v, %v", p, infos[j])
		calls, extra := proc.fuzzer.checkNewSignal(p, infos[j])
		log.Logf(0, "proc:432")
		for _, callIndex := range calls {
			proc.TaskenqueueCallTriage(task, flags, callIndex, infos[j].Calls[callIndex], j)
		}
		log.Logf(0, "proc:436")
		if extra {
			log.Logf(0, "proc:438")
			proc.TaskenqueueCallTriage(task, flags, -1, infos[j].Extra, j)
			log.Logf(0, "proc:440")
		}
	}
	return infos
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat)
	// calls, extra := proc.fuzzer.checkNewSignal(p, info)
	// for _, callIndex := range calls {
	// 	proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	// }
	// if extra {
	// 	proc.enqueueCallTriage(p, flags, -1, info.Extra)
	// }
	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

//modified by Rrooach
func (proc *Proc) TaskenqueueCallTriage(task []*prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo, pIndex int) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		task:   task,
		call:   callIndex,
		info:   info,
		flags:  flags,
		pIndex: pIndex,
	})
}

func (proc *Proc) TaskexecuteRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat, ch chan *ipc.ProgInfo) {
	// log.Logf(0, "proc:490")
	// if opts.Flags&ipc.FlagDedupCover == 0 {
	// 	log.Fatalf("dedup cover is not enabled")
	// }
	// for _, call := range p.Calls {
	// 	if !proc.fuzzer.choiceTable.Enabled(call.Meta.ID) {
	// 		fmt.Printf("executing disabled syscall %v", call.Meta.Name)
	// 		panic("disabled syscall")
	// 	}
	// }
	// log.Logf(0, "proc:500")
	// // Limit concurrency window and do leak checking once in a while.
	// ticket := proc.fuzzer.gate.Enter()
	// defer proc.fuzzer.gate.Leave(ticket)

	// proc.logProgram(opts, p)
	// for try := 0; ; try++ {
	// 	atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
	// 	output, info, hanged, err := proc.env.Exec(opts, p)
	// 	if err != nil {
	// 		if try > 10 {
	// 			log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
	// 		}
	// 		log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
	// 		debug.FreeOSMemory()
	// 		time.Sleep(time.Second)
	// 		continue
	// 	}
	// 	log.Logf(2, "result hanged=%v: %s", hanged, output)
	// 	c <- info
	// }
	ch <- proc.executeRaw(opts, p, stat)
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	log.Logf(0, "proc:578")
	for _, call := range p.Calls {
		if !proc.fuzzer.choiceTable.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v", call.Meta.Name)
			panic("disabled syscall")
		}
	}
	log.Logf(0, "proc:585")
	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)
	log.Logf(0, "proc:589")
	proc.logProgram(opts, p)
	log.Logf(0, "proc:591")
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		log.Logf(0, "proc:594")
		output, info, hanged, err := proc.env.Exec(opts, p)
		log.Logf(0, "proc:596")
		if err != nil {
			if try > 10 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		log.Logf(0, "proc:607")
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()
	strOpts := ""
	if opts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", opts.FaultCall, opts.FaultNth)
	}

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v%v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, strOpts, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s\n",
				proc.pid, strOpts, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			if strOpts != "" {
				fmt.Fprintf(f, "#%v\n", strOpts)
			}
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
