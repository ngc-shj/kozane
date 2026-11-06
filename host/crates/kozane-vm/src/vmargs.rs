//! The argv `tools/vm.py` renders for the launcher (`render_launcher_args`,
//! M9 plan C4), embedded at build time: `vm.py` stays the one source of the
//! machine. The file is ours, not untrusted input, but it is still read
//! strictly: a JSON subset of objects, arrays, ASCII strings and small
//! non-negative integers, and the exact shape below.

/// The highest fd a child may be given; the launcher keeps every lower
/// number busy so its own resources never land on one (see `spawn`).
pub const MAX_CHILD_FD: i32 = 63;

#[derive(Debug, PartialEq)]
pub enum Json {
    Obj(Vec<(String, Json)>),
    Arr(Vec<Json>),
    Str(String),
    Num(u32),
}

struct Parser<'a> {
    s: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, b: u8) -> Result<(), String> {
        self.ws();
        if self.peek() == Some(b) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!("expected `{}` at byte {}", b as char, self.at))
        }
    }

    fn value(&mut self, depth: u32) -> Result<Json, String> {
        if depth > 8 {
            return Err("nested too deeply".into());
        }
        self.ws();
        match self.peek() {
            Some(b'{') => {
                self.at += 1;
                let mut fields = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.at += 1;
                    return Ok(Json::Obj(fields));
                }
                loop {
                    self.ws();
                    let key = self.string()?;
                    if fields.iter().any(|(k, _)| *k == key) {
                        return Err(format!("duplicate key {key}"));
                    }
                    self.eat(b':')?;
                    fields.push((key, self.value(depth + 1)?));
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Json::Obj(fields));
                        }
                        _ => return Err(format!("expected `,` or `}}` at byte {}", self.at)),
                    }
                }
            }
            Some(b'[') => {
                self.at += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.at += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return Err(format!("expected `,` or `]` at byte {}", self.at)),
                    }
                }
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'0'..=b'9') => {
                let start = self.at;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
                let digits = self.s.get(start..self.at).unwrap_or_default();
                let text = core::str::from_utf8(digits).map_err(|_| "bad number")?;
                if text.len() > 1 && text.starts_with('0') {
                    return Err(format!("non-canonical number at byte {start}"));
                }
                text.parse().map(Json::Num).map_err(|_| format!("number out of range at byte {start}"))
            }
            _ => Err(format!("unexpected input at byte {}", self.at)),
        }
    }

    /// A string of printable ASCII; the only escapes are `\"` and `\\`.
    fn string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err(format!("expected a string at byte {}", self.at));
        }
        self.at += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    match self.peek() {
                        Some(c @ (b'"' | b'\\')) => out.push(c as char),
                        _ => return Err(format!("unsupported escape at byte {}", self.at)),
                    }
                    self.at += 1;
                }
                Some(c @ 0x20..=0x7e) => {
                    out.push(c as char);
                    self.at += 1;
                }
                _ => return Err(format!("bad string byte at {}", self.at)),
            }
        }
    }
}

pub fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser { s: text.as_bytes(), at: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.at != p.s.len() {
        return Err(format!("trailing input at byte {}", p.at));
    }
    Ok(v)
}

#[derive(Debug, PartialEq, Eq)]
pub struct QemuFds {
    pub firmware: i32,
    pub tpm: i32,
    pub outside: i32,
    pub inside: i32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SwtpmFds {
    pub ctrl: i32,
    pub key: i32,
}

/// One boot medium: a file of the node directory and the fd QEMU reads it
/// from.
#[derive(Debug, PartialEq, Eq)]
pub struct Medium {
    pub name: String,
    pub fd: i32,
}

/// The swtpm state directory the launcher runs on (tools/vm.py's
/// LAUNCHER_SWTPM_STATE).
pub const SWTPM_STATE: &str = "/var/lib/kozane/swtpm";

#[derive(Debug, PartialEq, Eq)]
pub struct VmArgs {
    pub qemu: Vec<String>,
    pub qemu_fds: QemuFds,
    pub media: Vec<Medium>,
    pub swtpm: Vec<String>,
    pub swtpm_fds: SwtpmFds,
    pub swtpm_state: String,
}

fn field<'a>(obj: &'a [(String, Json)], key: &str) -> Result<&'a Json, String> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v).ok_or(format!("missing `{key}`"))
}

fn strings(v: &Json, what: &str) -> Result<Vec<String>, String> {
    let Json::Arr(items) = v else { return Err(format!("`{what}` is not an array")) };
    items
        .iter()
        .map(|i| match i {
            Json::Str(s) => Ok(s.clone()),
            _ => Err(format!("`{what}` holds a non-string")),
        })
        .collect()
}

fn fd(obj: &[(String, Json)], key: &str) -> Result<i32, String> {
    match field(obj, key)? {
        Json::Num(n) if (3..=MAX_CHILD_FD as u32).contains(n) => Ok(*n as i32),
        _ => Err(format!("`{key}` is not an fd in 3..={MAX_CHILD_FD}")),
    }
}

fn object<'a>(v: &'a Json, what: &str) -> Result<&'a [(String, Json)], String> {
    match v {
        Json::Obj(o) => Ok(o),
        _ => Err(format!("`{what}` is not an object")),
    }
}

fn distinct(fds: &[i32], what: &str) -> Result<(), String> {
    for (i, a) in fds.iter().enumerate() {
        if fds.iter().skip(i + 1).any(|b| b == a) {
            return Err(format!("{what}: fd {a} is used twice"));
        }
    }
    Ok(())
}

impl VmArgs {
    pub fn parse(text: &str) -> Result<Self, String> {
        let root = parse(text)?;
        let top = object(&root, "vm-args")?;
        const KEYS: [&str; 6] = ["media", "qemu", "qemu_fds", "swtpm", "swtpm_fds", "swtpm_state"];
        if top.len() != KEYS.len() || !top.iter().all(|(k, _)| KEYS.contains(&k.as_str())) {
            return Err(format!("vm-args: the keys are not exactly {}", KEYS.join(", ")));
        }
        let q = object(field(top, "qemu_fds")?, "qemu_fds")?;
        let qemu_fds = QemuFds { firmware: fd(q, "firmware")?, tpm: fd(q, "tpm")?, outside: fd(q, "outside")?, inside: fd(q, "inside")? };
        let s = object(field(top, "swtpm_fds")?, "swtpm_fds")?;
        let swtpm_fds = SwtpmFds { ctrl: fd(s, "ctrl")?, key: fd(s, "key")? };
        let Json::Arr(items) = field(top, "media")? else { return Err("`media` is not an array".into()) };
        let media = items
            .iter()
            .map(|m| {
                let o = object(m, "medium")?;
                let Json::Str(name) = field(o, "name")? else { return Err("a medium's name is not a string".to_string()) };
                if name.is_empty() || name.contains('/') || name.starts_with('.') {
                    return Err(format!("medium `{name}` is not a plain file name"));
                }
                Ok(Medium { name: name.clone(), fd: fd(o, "fd")? })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let Json::Str(swtpm_state) = field(top, "swtpm_state")? else { return Err("`swtpm_state` is not a string".into()) };
        // The one provisioned state (host.md); a file that moves both it and
        // the argv is refused here too, not only by vm.py.
        if swtpm_state != SWTPM_STATE {
            return Err(format!("`swtpm_state` {swtpm_state} is not {SWTPM_STATE}"));
        }
        let args = Self {
            qemu: strings(field(top, "qemu")?, "qemu")?,
            qemu_fds,
            media,
            swtpm: strings(field(top, "swtpm")?, "swtpm")?,
            swtpm_fds,
            swtpm_state: swtpm_state.clone(),
        };
        let mut qfds = vec![args.qemu_fds.firmware, args.qemu_fds.tpm, args.qemu_fds.outside, args.qemu_fds.inside];
        qfds.extend(args.media.iter().map(|m| m.fd));
        distinct(&qfds, "qemu")?;
        distinct(&[args.swtpm_fds.ctrl, args.swtpm_fds.key], "swtpm")?;
        if args.swtpm.iter().filter(|a| **a == args.state_arg()).count() != 1 {
            return Err("swtpm: the state directory argument is not there exactly once".into());
        }
        Ok(args)
    }

    /// swtpm's `--tpmstate` value, the one argument the launcher rewrites
    /// (only `--root-prefix` moves it).
    pub fn state_arg(&self) -> String {
        format!("dir={}", self.swtpm_state)
    }

    /// The highest fd any child is given.
    pub fn max_fd(&self) -> i32 {
        let q = &self.qemu_fds;
        [q.firmware, q.tpm, q.outside, q.inside, self.swtpm_fds.ctrl, self.swtpm_fds.key]
            .into_iter()
            .chain(self.media.iter().map(|m| m.fd))
            .max()
            .unwrap_or(2)
    }
}
