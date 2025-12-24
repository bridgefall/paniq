package envelope

import "testing"

func TestReplayCacheSeen(t *testing.T) {
	cache := newReplayCache(2)
	var key1 [32]byte
	var key2 [32]byte
	var key3 [32]byte
	key1[0] = 1
	key2[0] = 2
	key3[0] = 3

	if replayed, _ := cache.Seen(key1); replayed {
		t.Fatalf("expected first key to be new")
	}
	if replayed, _ := cache.Seen(key1); !replayed {
		t.Fatalf("expected key to be replayed")
	}
	if replayed, _ := cache.Seen(key2); replayed {
		t.Fatalf("expected second key to be new")
	}
	if replayed, evicted := cache.Seen(key3); replayed || evicted == 0 {
		t.Fatalf("expected eviction when capacity exceeded")
	}
}
