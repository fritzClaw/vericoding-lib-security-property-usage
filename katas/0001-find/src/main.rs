//! `vfind`: the TRUSTED shell around the verified core in lib.rs.
//! Intent: intents/0001-find.md (D3, D21).
//!
//! This file is NOT verified by Verus. Its only job: pass argv (without the
//! program name, as raw bytes) to `find::Walker::new`, then loop on
//! `Walker::next` and do exactly what each `find::Step` says:
//!   - `Look(path, follow)`: `stat` (follow) or `lstat` the path; answer
//!     `Look::Found(kind, dev, ino)` or `Look::Missing(os message)`;
//!   - `List(path)`: read the directory's entry names (raw bytes, any order);
//!     answer `Listing::Names(..)` or `Listing::Unreadable(os message)`;
//!   - `Stdout(bytes)` / `Stderr(bytes)`: write the bytes unchanged;
//!   - `Exit(code)`: flush and exit with `code`.
//! No traversal, sorting, filtering, escaping or formatting here.
//! The skeleton is locked; the region is written in the vericode stage and
//! reviewed by a human.

#[allow(unused_imports)]
use vstd::prelude::*;  // required by Verus for every crate root

fn main() {
    // <vc-shell>
    // </vc-shell>
}
