package replay

import "testing"

func TestReplay(t *testing.T) {
	var filter Filter
	const tLim = windowSize + 1
	testNumber := 0
	run := func(n uint64, expected bool) {
		testNumber++
		if filter.ValidateCounter(n, RejectAfterMessages) != expected {
			t.Fatalf("test %d failed: %d expected %v", testNumber, n, expected)
		}
	}

	filter.Reset()
	run(0, true)
	run(1, true)
	run(1, false)
	run(9, true)
	run(8, true)
	run(7, true)
	run(7, false)
	run(tLim, true)
	run(tLim-1, true)
	run(tLim-1, false)
	run(tLim-2, true)
	run(2, true)
	run(2, false)
	run(tLim+16, true)
	run(3, false)
	run(tLim+16, false)
	run(tLim*4, true)
	run(tLim*4-(tLim-1), true)
	run(10, false)
	run(tLim*4-tLim, false)
	run(tLim*4-(tLim+1), false)
	run(tLim*4-(tLim-2), true)
	run(tLim*4+1-tLim, false)
	run(0, false)
	run(RejectAfterMessages, false)
	run(RejectAfterMessages-1, true)
	run(RejectAfterMessages, false)
	run(RejectAfterMessages-1, false)
	run(RejectAfterMessages-2, true)
	run(RejectAfterMessages+1, false)
	run(RejectAfterMessages+2, false)
	run(RejectAfterMessages-2, false)
	run(RejectAfterMessages-3, true)
	run(0, false)

	t.Log("bulk test 1")
	filter.Reset()
	testNumber = 0
	for i := uint64(1); i <= windowSize; i++ {
		run(i, true)
	}
	run(0, true)
	run(0, false)

	t.Log("bulk test 2")
	filter.Reset()
	testNumber = 0
	for i := uint64(2); i <= windowSize+1; i++ {
		run(i, true)
	}
	run(1, true)
	run(0, false)

	t.Log("bulk test 3")
	filter.Reset()
	testNumber = 0
	for i := uint64(windowSize + 1); i > 0; i-- {
		run(i, true)
	}

	t.Log("bulk test 4")
	filter.Reset()
	testNumber = 0
	for i := uint64(windowSize + 2); i > 1; i-- {
		run(i, true)
	}
	run(0, false)

	t.Log("bulk test 5")
	filter.Reset()
	testNumber = 0
	for i := uint64(windowSize); i > 0; i-- {
		run(i, true)
	}
	run(windowSize+1, true)
	run(0, false)

	t.Log("bulk test 6")
	filter.Reset()
	testNumber = 0
	for i := uint64(windowSize); i > 0; i-- {
		run(i, true)
	}
	run(0, true)
	run(windowSize+1, true)
}
