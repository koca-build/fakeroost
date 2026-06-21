//! End-to-end tests driving the real `fakeroot-rs` binary against system tools
//! (bash/coreutils/tar). These run the CLI as a separate process, so the
//! fork+ptrace supervisor runs unencumbered by the test harness's threads.
//!
//! They assume a Linux host with bash, coreutils and tar — i.e. normal CI.

use assert_cmd::Command;
use std::path::Path;
use tempfile::TempDir;

/// Run `bash -c <script>` under fakeroot-rs in `dir`; assert success; return stdout.
fn fakeroot_sh(dir: &Path, script: &str) -> String {
    let out = Command::cargo_bin("fakeroot-rs")
        .unwrap()
        .arg("bash")
        .arg("-c")
        .arg(script)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fakeroot-rs failed: status={:?}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn fakes_root_identity() {
    let dir = TempDir::new().unwrap();
    assert_eq!(fakeroot_sh(dir.path(), "id -u").trim(), "0");
    assert_eq!(fakeroot_sh(dir.path(), "id -g").trim(), "0");
}

#[test]
fn created_files_appear_root_owned() {
    // The core packaging behavior: files created under fakeroot look root-owned
    // without any explicit chown ("unknown is root").
    let dir = TempDir::new().unwrap();
    let out = fakeroot_sh(dir.path(), "touch f; mkdir d; stat -c '%n %u:%g' f d");
    assert!(out.contains("f 0:0"), "got: {out}");
    assert!(out.contains("d 0:0"), "got: {out}");
}

#[test]
fn chown_to_arbitrary_uid_reads_back_via_statx() {
    // `stat` uses statx(2) on modern systems — the syscall fakeroot-ng missed.
    let dir = TempDir::new().unwrap();
    let out = fakeroot_sh(dir.path(), "touch g; chown 200:200 g; stat -c '%u:%g' g");
    assert_eq!(out.trim(), "200:200");
}

#[test]
fn partial_chown_keeps_fake_current_id() {
    // chown(-1, gid) must keep the *fake* uid (root), not the real user.
    let dir = TempDir::new().unwrap();
    let out = fakeroot_sh(dir.path(), "touch g; chown :7 g; stat -c '%u:%g' g");
    assert_eq!(out.trim(), "0:7");
}

#[test]
fn tar_records_mixed_fake_ownership() {
    let dir = TempDir::new().unwrap();
    let out = fakeroot_sh(
        dir.path(),
        "touch r u; chown 0:0 r; chown 200:200 u; \
         tar --numeric-owner -cf out.tar r u; tar --numeric-owner -tvf out.tar",
    );
    assert!(out.contains("0/0"), "got: {out}");
    assert!(out.contains("200/200"), "got: {out}");
}

#[test]
fn mknod_reports_device_node() {
    let dir = TempDir::new().unwrap();
    let out = fakeroot_sh(dir.path(), "mknod cdev c 1 3 && stat -c '%n %F %t,%T' cdev");
    assert!(out.contains("character special file"), "got: {out}");
    assert!(out.contains("1,3"), "got: {out}");
}

#[test]
fn inode_reuse_does_not_inherit_stale_owner() {
    let dir = TempDir::new().unwrap();
    let out = fakeroot_sh(
        dir.path(),
        "touch a; chown 200:200 a; rm a; touch b; stat -c '%u:%g' b",
    );
    assert_eq!(out.trim(), "0:0", "reused inode wrongly kept fake owner");
}

#[test]
fn real_filesystem_is_untouched() {
    // Nothing is actually chowned on disk; outside fakeroot the file is still ours.
    use std::os::unix::fs::MetadataExt;
    let dir = TempDir::new().unwrap();
    fakeroot_sh(dir.path(), "touch realf; chown 200:200 realf");
    // The temp dir was created by us (real uid); the file must match it on disk.
    let real_uid = std::fs::metadata(dir.path()).unwrap().uid();
    let file_uid = std::fs::metadata(dir.path().join("realf")).unwrap().uid();
    assert_eq!(file_uid, real_uid, "fakeroot must not really chown on disk");
}
