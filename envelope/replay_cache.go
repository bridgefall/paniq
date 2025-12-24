package envelope

import (
	"container/list"
	"sync"
)

type replayCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[[32]byte]*list.Element
	order    *list.List
}

type replayEntry struct {
	key [32]byte
}

func newReplayCache(capacity int) *replayCache {
	if capacity <= 0 {
		capacity = 4096
	}
	return &replayCache{
		capacity: capacity,
		entries:  make(map[[32]byte]*list.Element, capacity),
		order:    list.New(),
	}
}

// Seen marks a key and returns true if it was already present.
func (c *replayCache) Seen(key [32]byte) (replayed bool, evicted int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.entries[key]; ok {
		c.order.MoveToFront(elem)
		return true, 0
	}
	elem := c.order.PushFront(replayEntry{key: key})
	c.entries[key] = elem
	for c.order.Len() > c.capacity {
		back := c.order.Back()
		if back == nil {
			break
		}
		entry := back.Value.(replayEntry)
		delete(c.entries, entry.key)
		c.order.Remove(back)
		evicted++
	}
	return false, evicted
}

func (c *replayCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[[32]byte]*list.Element, c.capacity)
	c.order.Init()
}
