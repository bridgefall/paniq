package replay

type block uint64

const (
	blockBitLog = 6
	blockBits   = 1 << blockBitLog
	ringBlocks  = 1 << 7
	windowSize  = (ringBlocks - 1) * blockBits
	blockMask   = ringBlocks - 1
	bitMask     = blockBits - 1
)

const RejectAfterMessages = 1<<64 - 1<<13 - 1

// Filter rejects replayed messages by tracking a sliding window of counters.
// The zero value is ready for use. Not safe for concurrent use.
type Filter struct {
	last uint64
	ring [ringBlocks]block
}

// Reset clears the filter state.
func (f *Filter) Reset() {
	f.last = 0
	f.ring[0] = 0
}

// ValidateCounter returns true when the counter is accepted.
func (f *Filter) ValidateCounter(counter, limit uint64) bool {
	if counter >= limit {
		return false
	}
	indexBlock := counter >> blockBitLog
	if counter > f.last {
		current := f.last >> blockBitLog
		diff := indexBlock - current
		if diff > ringBlocks {
			diff = ringBlocks
		}
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i&blockMask] = 0
		}
		f.last = counter
	} else if f.last-counter > windowSize {
		return false
	}
	indexBlock &= blockMask
	indexBit := counter & bitMask
	old := f.ring[indexBlock]
	newVal := old | 1<<indexBit
	f.ring[indexBlock] = newVal
	return old != newVal
}
