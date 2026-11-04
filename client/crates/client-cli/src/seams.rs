//! Path and user resolution, and the only place `test-seams` changes
//! anything (M9 plan C4's seams, applied to C10). With the feature,
//! `--root-prefix <dir>` puts every fixed path under `<dir>`, and
//! `--user-map <user>=<uid>[,...]` resolves the service users without the
//! user database, so the tests run in a single-uid user namespace (VE26).
//! Without it, both options are unknown and the paths and users are the
//! system's.

use std::path::PathBuf;

use crate::sys;

/// Whether this build carries the seams; `--build-info` prints it.
pub const SEAMS: bool = cfg!(feature = "test-seams");

#[derive(Debug, Default)]
pub struct Env {
    #[cfg(feature = "test-seams")]
    root: Option<PathBuf>,
    #[cfg(feature = "test-seams")]
    users: Vec<(String, u32)>,
}

impl Env {
    /// Takes the seam options off `args` and returns the rest. A build
    /// without seams takes nothing.
    pub fn from_args(args: Vec<String>) -> Result<(Self, Vec<String>), String> {
        #[cfg(feature = "test-seams")]
        {
            let mut env = Self::default();
            let mut rest = Vec::new();
            let mut it = args.into_iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--root-prefix" => env.root = Some(PathBuf::from(it.next().ok_or("--root-prefix: no value")?)),
                    "--user-map" => {
                        for pair in it.next().ok_or("--user-map: no value")?.split(',') {
                            let (user, uid) = pair.split_once('=').ok_or("--user-map: want user=uid")?;
                            let uid = uid.parse().map_err(|_| format!("--user-map: bad uid {uid:?}"))?;
                            env.users.push((user.to_string(), uid));
                        }
                    }
                    _ => rest.push(a),
                }
            }
            Ok((env, rest))
        }
        #[cfg(not(feature = "test-seams"))]
        Ok((Self::default(), args))
    }

    /// `fixed`, an absolute path, under the root prefix if there is one.
    pub fn path(&self, fixed: &str) -> PathBuf {
        #[cfg(feature = "test-seams")]
        if let Some(root) = &self.root {
            return root.join(fixed.trim_start_matches('/'));
        }
        PathBuf::from(fixed)
    }

    /// The uid and gid of a service user.
    pub fn user(&self, name: &str) -> Result<(u32, u32), String> {
        #[cfg(feature = "test-seams")]
        if let Some((_, uid)) = self.users.iter().find(|(u, _)| u == name) {
            return Ok((*uid, *uid));
        }
        sys::getpwnam(name).map_err(|e| format!("{name}: {e}"))?.ok_or_else(|| format!("{name}: no such user"))
    }
}
