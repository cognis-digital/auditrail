// Go port of the AUDITRAIL core — mirrors the Python `chain`/`verify`/`attest`
// command surface and produces byte-identical sha256 hash-chain digests
// (digest = sha256(prev || 0x1f || canonical-json(event))). Single binary, stdlib only.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

var requiredFields = []string{"ts", "actor", "action"}

type event struct {
	TS     string
	Actor  string
	Action string
	Extra  map[string]interface{}
}

type link struct {
	Index  int    `json:"index"`
	Prev   string `json:"prev"`
	Digest string `json:"digest"`
	ev     event
}

// canonicalJSON emits sorted-key, whitespace-free JSON matching Python's
// json.dumps(sort_keys=True, separators=(",",":")).
func canonicalJSON(v interface{}) string {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.WriteString(canonicalJSON(t[k]))
		}
		b.WriteByte('}')
		return b.String()
	case []interface{}:
		var b strings.Builder
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(canonicalJSON(e))
		}
		b.WriteByte(']')
		return b.String()
	default:
		bb, _ := json.Marshal(v)
		return string(bb)
	}
}

func (e event) canonical() map[string]interface{} {
	p := map[string]interface{}{"ts": e.TS, "actor": e.Actor, "action": e.Action}
	for k, v := range e.Extra {
		if _, ok := p[k]; !ok {
			p[k] = v
		}
	}
	return p
}

func linkDigest(prev string, e event) string {
	material := prev + "\x1f" + canonicalJSON(e.canonical())
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func fromRaw(raw map[string]interface{}, idx int) (event, error) {
	for _, f := range requiredFields {
		v, ok := raw[f]
		if !ok || v == nil || v == "" {
			return event{}, fmt.Errorf("event %d: missing required field: %s", idx, f)
		}
	}
	extra := map[string]interface{}{}
	for k, v := range raw {
		if k != "ts" && k != "actor" && k != "action" {
			extra[k] = v
		}
	}
	str := func(v interface{}) string { return fmt.Sprintf("%v", v) }
	return event{TS: str(raw["ts"]), Actor: str(raw["actor"]), Action: str(raw["action"]), Extra: extra}, nil
}

func loadEvents(text string) ([]event, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	var records []map[string]interface{}
	if text[0] == '[' {
		if err := json.Unmarshal([]byte(text), &records); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %v", err)
		}
	} else {
		sc := bufio.NewScanner(strings.NewReader(text))
		sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
		ln := 0
		for sc.Scan() {
			ln++
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var r map[string]interface{}
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil, fmt.Errorf("line %d: invalid JSON: %v", ln, err)
			}
			records = append(records, r)
		}
	}
	evs := make([]event, 0, len(records))
	for i, r := range records {
		e, err := fromRaw(r, i)
		if err != nil {
			return nil, err
		}
		evs = append(evs, e)
	}
	return evs, nil
}

func buildChain(evs []event) []link {
	links := make([]link, 0, len(evs))
	prev := genesis
	for i, e := range evs {
		d := linkDigest(prev, e)
		links = append(links, link{Index: i, Prev: prev, Digest: d, ev: e})
		prev = d
	}
	return links
}

func head(links []link) string {
	if len(links) == 0 {
		return genesis
	}
	return links[len(links)-1].Digest
}

func verifyChain(links []link) []map[string]interface{} {
	breaks := []map[string]interface{}{}
	prev := genesis
	for _, l := range links {
		if l.Prev != prev {
			breaks = append(breaks, map[string]interface{}{
				"index": l.Index, "reason": "prev-pointer mismatch",
				"expected_prev": prev, "stored_prev": l.Prev, "action": l.ev.Action,
			})
		}
		rec := linkDigest(l.Prev, l.ev)
		if rec != l.Digest {
			breaks = append(breaks, map[string]interface{}{
				"index": l.Index, "reason": "digest mismatch (content altered)",
				"expected_digest": rec, "stored_digest": l.Digest, "action": l.ev.Action,
			})
			prev = l.Digest
		} else {
			prev = rec
		}
	}
	return breaks
}

func attest(links []link, source string) map[string]interface{} {
	breaks := verifyChain(links)
	seen := map[string]bool{}
	for _, l := range links {
		seen[l.ev.Actor] = true
	}
	actors := make([]string, 0, len(seen))
	for a := range seen {
		actors = append(actors, a)
	}
	sort.Strings(actors)
	var firstTS, lastTS interface{}
	if len(links) > 0 {
		firstTS = links[0].ev.TS
		lastTS = links[len(links)-1].ev.TS
	}
	m := map[string]interface{}{
		"tool": "auditrail", "version": "1.0.0", "source": source,
		"attested_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"event_count": len(links), "genesis": genesis, "head": head(links),
		"first_ts": firstTS, "last_ts": lastTS, "distinct_actors": actors,
		"intact": len(breaks) == 0, "break_count": len(breaks),
	}
	sum := sha256.Sum256([]byte(canonicalJSON(m)))
	m["manifest_digest"] = hex.EncodeToString(sum[:])
	return m
}

func readInput(path string) (string, error) {
	if path == "" || path == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: auditrail <chain|verify|attest> [file]")
		os.Exit(1)
	}
	cmd := os.Args[1]
	input := "-"
	if len(os.Args) > 2 {
		input = os.Args[2]
	}
	text, err := readInput(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	evs, err := loadEvents(text)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	links := buildChain(evs)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	switch cmd {
	case "chain":
		type outLink struct {
			Index  int    `json:"index"`
			Prev   string `json:"prev"`
			Digest string `json:"digest"`
			TS     string `json:"ts"`
			Actor  string `json:"actor"`
			Action string `json:"action"`
		}
		ol := make([]outLink, len(links))
		for i, l := range links {
			ol[i] = outLink{l.Index, l.Prev, l.Digest, l.ev.TS, l.ev.Actor, l.ev.Action}
		}
		enc.Encode(map[string]interface{}{"head": head(links), "event_count": len(links), "links": ol})
	case "verify":
		breaks := verifyChain(links)
		enc.Encode(map[string]interface{}{
			"intact": len(breaks) == 0, "event_count": len(links),
			"break_count": len(breaks), "breaks": breaks,
		})
		if len(breaks) > 0 {
			os.Exit(2)
		}
	case "attest":
		src := input
		if src == "-" {
			src = "<stdin>"
		}
		m := attest(links, src)
		enc.Encode(m)
		if m["intact"] != true {
			os.Exit(2)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		os.Exit(1)
	}
}
