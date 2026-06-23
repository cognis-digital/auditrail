package main

import "testing"

const sample = `[{"ts":"2026-06-08T09:00:00Z","actor":"alice","action":"login"},{"ts":"2026-06-08T09:01:00Z","actor":"alice","action":"read","resource":"r1"},{"ts":"2026-06-08T09:02:00Z","actor":"bob","action":"delete","resource":"r1"}]`

// Reference head computed by the Python implementation over the same sample.
const referenceHead = "8ae3d48a5736f485bd64d7d812d5255a5548962684e79a85d05bbbfac1ea94d3"

func TestCanonicalJSONSorted(t *testing.T) {
	in := map[string]interface{}{"b": "2", "a": "1"}
	if got := canonicalJSON(in); got != `{"a":"1","b":"2"}` {
		t.Fatalf("canonical sort failed: %s", got)
	}
}

func TestBuildAndVerify(t *testing.T) {
	evs, err := loadEvents(sample)
	if err != nil {
		t.Fatal(err)
	}
	links := buildChain(evs)
	if len(links) != 3 {
		t.Fatalf("want 3 links, got %d", len(links))
	}
	if links[0].Prev != genesis {
		t.Fatal("first link prev must be genesis")
	}
	if got := head(links); got != referenceHead {
		t.Fatalf("head mismatch: want %s got %s", referenceHead, got)
	}
	if b := verifyChain(links); len(b) != 0 {
		t.Fatalf("intact chain reported %d breaks", len(b))
	}
}

func TestDeterministic(t *testing.T) {
	a, _ := loadEvents(sample)
	b, _ := loadEvents(sample)
	if head(buildChain(a)) != head(buildChain(b)) {
		t.Fatal("non-deterministic head")
	}
}

func TestMissingFieldRejected(t *testing.T) {
	if _, err := loadEvents(`[{"actor":"a","action":"x"}]`); err == nil {
		t.Fatal("expected error for missing ts")
	}
}

func TestJSONL(t *testing.T) {
	jsonl := "{\"ts\":\"t1\",\"actor\":\"a\",\"action\":\"x\"}\n{\"ts\":\"t2\",\"actor\":\"b\",\"action\":\"y\"}"
	evs, err := loadEvents(jsonl)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
}

func TestTamperDetected(t *testing.T) {
	evs, _ := loadEvents(sample)
	links := buildChain(evs)
	links[1].ev.Actor = "mallory" // mutate embedded content, keep stored digest
	breaks := verifyChain(links)
	if len(breaks) == 0 {
		t.Fatal("tamper not detected")
	}
	if breaks[0]["index"] != 1 {
		t.Fatalf("tamper should be at index 1, got %v", breaks[0]["index"])
	}
}

func TestEmptyGenesis(t *testing.T) {
	evs, _ := loadEvents("")
	if head(buildChain(evs)) != genesis {
		t.Fatal("empty chain head must be genesis")
	}
}
