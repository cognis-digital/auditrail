// Rust port of the AUDITRAIL core — mirrors the Python `chain`/`verify`/`attest`
// command surface and produces byte-identical sha256 hash-chain digests
// (digest = sha256(prev || 0x1f || canonical-json(event))). Single binary, ZERO
// external crates: SHA-256 and a minimal JSON parser/canonicalizer are implemented
// here so the port builds and tests offline with stock `cargo`.
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::exit;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------- SHA-256 (FIPS 180-4) ----------
fn sha256_hex(msg: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut data = msg.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in data.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{:08x}", x)).collect()
}

// ---------- minimal JSON ----------
#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    Num(String), // keep raw lexeme to round-trip integers exactly
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Parser { b: s.as_bytes(), i: 0 }
    }
    fn ws(&mut self) {
        while self.i < self.b.len() && (self.b[self.i] as char).is_whitespace() {
            self.i += 1;
        }
    }
    fn parse(&mut self) -> Result<Json, String> {
        self.ws();
        let v = self.value()?;
        Ok(v)
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        if self.i >= self.b.len() {
            return Err("unexpected end".into());
        }
        match self.b[self.i] {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => {
                self.lit("true")?;
                Ok(Json::Bool(true))
            }
            b'f' => {
                self.lit("false")?;
                Ok(Json::Bool(false))
            }
            b'n' => {
                self.lit("null")?;
                Ok(Json::Null)
            }
            _ => self.number(),
        }
    }
    fn lit(&mut self, s: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(())
        } else {
            Err(format!("expected {}", s))
        }
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while self.i < self.b.len() {
            match self.b[self.i] {
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E' => self.i += 1,
                _ => break,
            }
        }
        if start == self.i {
            return Err("invalid number".into());
        }
        Ok(Json::Num(String::from_utf8_lossy(&self.b[start..self.i]).into_owned()))
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let hex = std::str::from_utf8(&self.b[self.i..self.i + 4]).unwrap();
                            let cp = u32::from_str_radix(hex, 16).map_err(|_| "bad \\u")?;
                            self.i += 4;
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => {
                    // collect the full UTF-8 byte sequence
                    let mut buf = vec![c];
                    let extra = match c {
                        0xF0..=0xF7 => 3,
                        0xE0..=0xEF => 2,
                        0xC0..=0xDF => 1,
                        _ => 0,
                    };
                    for _ in 0..extra {
                        buf.push(self.b[self.i]);
                        self.i += 1;
                    }
                    out.push_str(&String::from_utf8_lossy(&buf));
                }
            }
        }
        Err("unterminated string".into())
    }
    fn array(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut v = Vec::new();
        self.ws();
        if self.i < self.b.len() && self.b[self.i] == b']' {
            self.i += 1;
            return Ok(Json::Arr(v));
        }
        loop {
            v.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected , or ]".into()),
            }
        }
        Ok(Json::Arr(v))
    }
    fn object(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.i < self.b.len() && self.b[self.i] == b'}' {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err("expected :".into());
            }
            self.i += 1;
            let val = self.value()?;
            m.insert(k, val);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected , or }".into()),
            }
        }
        Ok(Json::Obj(m))
    }
}

fn esc(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

// canonical JSON: BTreeMap already sorts keys; no whitespace.
fn canonical(j: &Json) -> String {
    match j {
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Num(n) => n.clone(),
        Json::Str(s) => esc(s),
        Json::Arr(a) => {
            let items: Vec<String> = a.iter().map(canonical).collect();
            format!("[{}]", items.join(","))
        }
        Json::Obj(m) => {
            let items: Vec<String> = m.iter().map(|(k, v)| format!("{}:{}", esc(k), canonical(v))).collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

fn as_str(j: &Json) -> String {
    match j {
        Json::Str(s) => s.clone(),
        Json::Num(n) => n.clone(),
        Json::Bool(b) => b.to_string(),
        Json::Null => "".into(),
        _ => String::new(),
    }
}

struct Event {
    canon: Json, // ts/actor/action + extras (sorted)
    ts: String,
    actor: String,
    action: String,
}

fn from_raw(obj: &BTreeMap<String, Json>, idx: usize) -> Result<Event, String> {
    for f in ["ts", "actor", "action"] {
        match obj.get(f) {
            None => return Err(format!("event {}: missing required field: {}", idx, f)),
            Some(Json::Null) => return Err(format!("event {}: missing required field: {}", idx, f)),
            Some(Json::Str(s)) if s.is_empty() => {
                return Err(format!("event {}: missing required field: {}", idx, f))
            }
            _ => {}
        }
    }
    let mut m: BTreeMap<String, Json> = BTreeMap::new();
    let ts = as_str(obj.get("ts").unwrap());
    let actor = as_str(obj.get("actor").unwrap());
    let action = as_str(obj.get("action").unwrap());
    m.insert("ts".into(), Json::Str(ts.clone()));
    m.insert("actor".into(), Json::Str(actor.clone()));
    m.insert("action".into(), Json::Str(action.clone()));
    for (k, v) in obj {
        if k != "ts" && k != "actor" && k != "action" {
            m.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    Ok(Event { canon: Json::Obj(m), ts, actor, action })
}

fn load_events(text: &str) -> Result<Vec<Event>, String> {
    let t = text.trim();
    if t.is_empty() {
        return Ok(vec![]);
    }
    let mut raws: Vec<Json> = Vec::new();
    if t.as_bytes()[0] == b'[' {
        match Parser::new(t).parse()? {
            Json::Arr(a) => raws = a,
            _ => return Err("top-level JSON must be an array".into()),
        }
    } else {
        for (ln, line) in t.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match Parser::new(line).parse() {
                Ok(j) => raws.push(j),
                Err(e) => return Err(format!("line {}: invalid JSON: {}", ln + 1, e)),
            }
        }
    }
    let mut out = Vec::new();
    for (i, r) in raws.iter().enumerate() {
        match r {
            Json::Obj(o) => out.push(from_raw(o, i)?),
            _ => return Err(format!("event {} is not an object", i)),
        }
    }
    Ok(out)
}

fn link_digest(prev: &str, ev: &Event) -> String {
    let material = format!("{}\u{001f}{}", prev, canonical(&ev.canon));
    sha256_hex(material.as_bytes())
}

struct Link {
    index: usize,
    prev: String,
    digest: String,
}

fn build_chain(evs: &[Event]) -> Vec<Link> {
    let mut links = Vec::new();
    let mut prev = GENESIS.to_string();
    for (i, ev) in evs.iter().enumerate() {
        let d = link_digest(&prev, ev);
        links.push(Link { index: i, prev: prev.clone(), digest: d.clone() });
        prev = d;
    }
    links
}

fn head(links: &[Link]) -> String {
    links.last().map(|l| l.digest.clone()).unwrap_or_else(|| GENESIS.to_string())
}

fn verify_chain(links: &[Link], evs: &[Event]) -> Vec<String> {
    let mut breaks = Vec::new();
    let mut prev = GENESIS.to_string();
    for (k, l) in links.iter().enumerate() {
        if l.prev != prev {
            breaks.push(format!(
                "{{\"index\":{},\"reason\":\"prev-pointer mismatch\",\"action\":{}}}",
                l.index,
                esc(&evs[k].action)
            ));
        }
        let rec = link_digest(&l.prev, &evs[k]);
        if rec != l.digest {
            breaks.push(format!(
                "{{\"index\":{},\"reason\":\"digest mismatch (content altered)\",\"action\":{}}}",
                l.index,
                esc(&evs[k].action)
            ));
            prev = l.digest.clone();
        } else {
            prev = rec;
        }
    }
    breaks
}

fn read_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        fs::read_to_string(path)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: auditrail <chain|verify|attest> [file]");
        exit(1);
    }
    let cmd = &args[1];
    let input = if args.len() > 2 { args[2].clone() } else { "-".to_string() };
    let text = match read_input(&input) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {}", e);
            exit(1);
        }
    };
    let evs = match load_events(&text) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {}", e);
            exit(1);
        }
    };
    let links = build_chain(&evs);
    match cmd.as_str() {
        "chain" => {
            let mut parts = Vec::new();
            for (k, l) in links.iter().enumerate() {
                parts.push(format!(
                    "{{\"index\":{},\"prev\":{},\"digest\":{},\"ts\":{},\"actor\":{},\"action\":{}}}",
                    l.index,
                    esc(&l.prev),
                    esc(&l.digest),
                    esc(&evs[k].ts),
                    esc(&evs[k].actor),
                    esc(&evs[k].action)
                ));
            }
            println!(
                "{{\"head\":{},\"event_count\":{},\"links\":[{}]}}",
                esc(&head(&links)),
                links.len(),
                parts.join(",")
            );
        }
        "verify" => {
            let breaks = verify_chain(&links, &evs);
            println!(
                "{{\"intact\":{},\"event_count\":{},\"break_count\":{},\"breaks\":[{}]}}",
                breaks.is_empty(),
                links.len(),
                breaks.len(),
                breaks.join(",")
            );
            if !breaks.is_empty() {
                exit(2);
            }
        }
        "attest" => {
            let breaks = verify_chain(&links, &evs);
            // distinct actors, sorted
            let mut set: Vec<String> = evs.iter().map(|e| e.actor.clone()).collect();
            set.sort();
            set.dedup();
            let actors: Vec<String> = set.iter().map(|a| esc(a)).collect();
            println!(
                "{{\"tool\":\"auditrail\",\"head\":{},\"event_count\":{},\"intact\":{},\"break_count\":{},\"distinct_actors\":[{}]}}",
                esc(&head(&links)),
                links.len(),
                breaks.is_empty(),
                breaks.len(),
                actors.join(",")
            );
            if !breaks.is_empty() {
                exit(2);
            }
        }
        _ => {
            eprintln!("unknown command: {}", cmd);
            exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[{"ts":"2026-06-08T09:00:00Z","actor":"alice","action":"login"},{"ts":"2026-06-08T09:01:00Z","actor":"alice","action":"read","resource":"r1"},{"ts":"2026-06-08T09:02:00Z","actor":"bob","action":"delete","resource":"r1"}]"#;

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn matches_reference_head() {
        let evs = load_events(SAMPLE).unwrap();
        let links = build_chain(&evs);
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].prev, GENESIS);
        // byte-identical to the Python reference implementation
        assert_eq!(
            head(&links),
            "8ae3d48a5736f485bd64d7d812d5255a5548962684e79a85d05bbbfac1ea94d3"
        );
        assert!(verify_chain(&links, &evs).is_empty());
    }

    #[test]
    fn missing_field_rejected() {
        assert!(load_events(r#"[{"actor":"a","action":"x"}]"#).is_err());
    }

    #[test]
    fn jsonl_parses() {
        let jsonl = "{\"ts\":\"t1\",\"actor\":\"a\",\"action\":\"x\"}\n{\"ts\":\"t2\",\"actor\":\"b\",\"action\":\"y\"}";
        assert_eq!(load_events(jsonl).unwrap().len(), 2);
    }
}
