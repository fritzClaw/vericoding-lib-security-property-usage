//! Differential test of the trusted shell (intent 0001-find, "Not verified"):
//! on a real temp tree of plain-ASCII names (no `:` or `\`, so escaping is
//! the identity), `vfind`'s stdout must equal GNU `find`'s, put in `vfind`'s
//! order (D4: pre-order, siblings by bytes = component-wise byte order), per
//! start path, with the paths `vfind` reports as filesystem loops removed
//! (GNU omits them, D10 prints them). Exit statuses must agree: 0 on success,
//! non-zero (vfind: 1) on any error. Skipped if GNU `find` isn't installed.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

fn gnu_find_available() -> bool {
    Command::new("find")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("GNU findutils"))
        .unwrap_or(false)
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| o.stdout.trim_ascii() == b"0")
        .unwrap_or(true)
}

/// t/{b, .h, a-c, a/x, l -> a, dead -> nowhere}, u/up -> ., n/deep/er/f,
/// s/{sp ace, z-1, Z, 0}, and (unless root) an unreadable r/ containing s.
fn build_tree(root: &Path, unreadable: bool) {
    let mk = |p: &str| fs::create_dir_all(root.join(p)).unwrap();
    let touch = |p: &str| fs::write(root.join(p), b"").unwrap();
    mk("t/a");
    for f in ["t/b", "t/.h", "t/a-c", "t/a/x"] {
        touch(f);
    }
    symlink("a", root.join("t/l")).unwrap();
    symlink("nowhere", root.join("t/dead")).unwrap();
    mk("u");
    symlink(".", root.join("u/up")).unwrap();
    mk("n/deep/er");
    touch("n/deep/er/f");
    mk("s");
    for f in ["s/sp ace", "s/z-1", "s/Z", "s/0"] {
        touch(f);
    }
    if unreadable {
        mk("r");
        touch("r/s");
        fs::set_permissions(root.join("r"), fs::Permissions::from_mode(0o000)).unwrap();
    }
}

fn lines(b: &[u8]) -> Vec<Vec<u8>> {
    b.split(|&c| c == b'\n').filter(|l| !l.is_empty()).map(|l| l.to_vec()).collect()
}

/// D4: pre-order with siblings in byte order == component-wise byte order.
fn sort_preorder(mut ps: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    ps.sort_by(|a, b| {
        let ca: Vec<&[u8]> = a.split(|&c| c == b'/').collect();
        let cb: Vec<&[u8]> = b.split(|&c| c == b'/').collect();
        ca.cmp(&cb)
    });
    ps
}

fn check(root: &Path, follow: bool, starts: &[&str]) {
    let mut args: Vec<&str> = if follow { vec!["-L"] } else { vec![] };
    args.extend_from_slice(starts);
    let v = Command::new(env!("CARGO_BIN_EXE_vfind")).args(&args).current_dir(root).output().unwrap();

    // GNU find, once per start path (its output isn't ordered), in vfind's order.
    let mut expected = Vec::new();
    let mut gnu_failed = false;
    let default_start = ["."];
    let starts: &[&str] = if starts.is_empty() { &default_start } else { starts };
    for s in starts {
        let mut gargs: Vec<&str> = if follow { vec!["-L"] } else { vec![] };
        gargs.push(s);
        let g = Command::new("find").args(&gargs).current_dir(root).output().unwrap();
        gnu_failed |= !g.status.success();
        expected.extend(sort_preorder(lines(&g.stdout)));
    }

    // Paths vfind reports as loops are printed by vfind, omitted by GNU find.
    let loops: Vec<Vec<u8>> = lines(&v.stderr)
        .into_iter()
        .filter_map(|l| l.strip_prefix(&b"vfind: filesystem loop: "[..]).map(|p| p.to_vec()))
        .collect();
    let got: Vec<Vec<u8>> = lines(&v.stdout).into_iter().filter(|p| !loops.contains(p)).collect();

    let show = |ps: &[Vec<u8>]| ps.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect::<Vec<_>>();
    assert_eq!(show(&got), show(&expected), "stdout differs for vfind {args:?}");
    assert_eq!(v.status.code() == Some(0), !gnu_failed, "exit status differs for vfind {args:?}: {:?}", v.status);
    assert!(v.status.code() == Some(0) || v.status.code() == Some(1), "vfind exit status must be 0 or 1");
    assert_eq!(v.stderr.is_empty(), v.status.code() == Some(0), "stderr non-empty iff exit 1 (P7)");
}

#[test]
fn differential_against_gnu_find() {
    if !gnu_find_available() {
        eprintln!("skipped: GNU find not installed");
        return;
    }
    let root: PathBuf = std::env::temp_dir().join(format!("vfind-diff-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let unreadable = !is_root();
    build_tree(&root, unreadable);

    for follow in [false, true] {
        check(&root, follow, &["t"]);
        check(&root, follow, &["t/"]);
        check(&root, follow, &["u"]);
        check(&root, follow, &["n", "s"]);
        check(&root, follow, &["t", "missing", "t/b"]);
        check(&root, follow, &["t", "t/a"]);
        check(&root, follow, &["t/l"]);
        check(&root, follow, &[]);
        if unreadable {
            check(&root, follow, &["r"]);
        }
    }

    if unreadable {
        fs::set_permissions(root.join("r"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::remove_dir_all(&root).unwrap();
}
