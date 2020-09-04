func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) []*Prog {
	var ProgList []*Prog
	rand.Seed(time.Now().Unix())
	ListLen := rand.Intn(8-2)+2
	
	for i = 0; i < ListLen; i++ {
		p := &Prog{
			Target: target,
		}
		r := newRand(target, rs)
		s := newState(target, ct, nil)
		p.Prio = r.Int(100)
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
		ProgList = append(ProgList, p)
	}
	
	return ProgList
}
