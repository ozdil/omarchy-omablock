use std::fs::{self, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Verifies that the state directory exists with secure 0700 permissions
pub fn ensure_state_dir(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|e| format!("Failed to create state dir: {}", e))?;
    }

    let meta = fs::symlink_metadata(dir).map_err(|e| format!("Failed to read metadata for state dir: {}", e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("Security violation: State directory is a symlink: {:?}", dir));
    }
    if !meta.file_type().is_dir() {
        return Err(format!("Security violation: State directory is not a directory: {:?}", dir));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: getuid() is a standard POSIX libc call with no preconditions.
        let uid = unsafe { libc::getuid() };
        if meta.uid() != uid {
            return Err(format!("Security violation: State directory owner UID mismatch: {} != {}", meta.uid(), uid));
        }

        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            fs::set_permissions(dir, Permissions::from_mode(0o700))
                .map_err(|e| format!("Failed to set 0700 permissions on state dir: {}", e))?;
        }
    }

    Ok(())
}

/// Verifies that a target file is safe:
/// - Not a symlink
/// - Regular file
/// - Owned by current user
pub fn verify_secure_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let meta = fs::symlink_metadata(path).map_err(|e| format!("Failed to read metadata: {}", e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("Security violation: Target is a symlink: {:?}", path));
    }
    if !meta.file_type().is_file() {
        return Err(format!("Security violation: Target is not a regular file: {:?}", path));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: getuid() is a standard POSIX libc call with no preconditions.
        let uid = unsafe { libc::getuid() };
        if meta.uid() != uid {
            return Err(format!("Security violation: Owner UID mismatch on {:?}: {} != {}", path, meta.uid(), uid));
        }
    }

    Ok(())
}

/// Atomically writes data to a secure file with mode 0600:
/// 1. Verifies target is not a symlink.
/// 2. Creates a temporary staging file `.tmp_state_*` in the same directory with mode 0600 and O_NOFOLLOW.
/// 3. Writes all bytes.
/// 4. Dispatches sync_all() to guarantee persistence to disk.
/// 5. Performs atomic rename to destination.
pub fn atomic_write_secure(path: &Path, data: &[u8]) -> Result<(), String> {
    verify_secure_file(path)?;

    let parent = path.parent().ok_or_else(|| "Target path has no parent directory".to_string())?;
    ensure_state_dir(parent)?;

    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // SAFETY: getpid() is a standard POSIX libc call with no preconditions.
    let pid = unsafe { libc::getpid() };
    let tmp_name = format!(".tmp_state_{}_{}", pid, now_nanos);
    let tmp_path = parent.join(tmp_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create temporary state file: {}", e))?;

    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set 0600 on temporary file: {}", e))?;

    file.write_all(data)
        .map_err(|e| format!("Failed to write data to temporary file: {}", e))?;

    file.sync_all()
        .map_err(|e| format!("Failed to sync file to disk: {}", e))?;

    drop(file);

    if path.exists() {
        verify_secure_file(path)?;
    }

    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!("Failed to atomically rename temporary file to destination: {}", e)
    })?;

    Ok(())
}

/// Reads a secure file ensuring bounded memory consumption, no symlinks, regular file type, and correct ownership
pub fn read_secure_file_bounded(path: &Path, max_bytes: usize) -> Result<String, String> {
    verify_secure_file(path)?;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to open file safely with O_NOFOLLOW: {}", e))?;

    let fd_meta = file.metadata().map_err(|e| format!("Failed to read descriptor metadata: {}", e))?;
    if !fd_meta.is_file() {
        return Err(format!("Security violation: Descriptor is not a regular file: {:?}", path));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: getuid() is standard POSIX syscall.
        let uid = unsafe { libc::getuid() };
        if fd_meta.uid() != uid {
            return Err(format!("Security violation: Descriptor UID mismatch on {:?}: {} != {}", path, fd_meta.uid(), uid));
        }
    }

    let mut buf = String::with_capacity(fd_meta.len().min(max_bytes as u64) as usize);
    let mut handle = (&mut file).take((max_bytes.saturating_add(1)) as u64);
    handle.read_to_string(&mut buf).map_err(|e| format!("Failed to read file contents: {}", e))?;

    if buf.len() > max_bytes {
        return Err(format!("Security violation: File {:?} exceeds maximum allowed limit of {} bytes", path, max_bytes));
    }

    Ok(buf)
}

/// Reads a secure file with default 1 MiB ceiling
pub fn read_secure_file(path: &Path) -> Result<String, String> {
    read_secure_file_bounded(path, 1024 * 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_write_secure_and_permissions() {
        let dir = std::env::temp_dir().join("omablock_sec_test_dir");
        let _ = fs::remove_dir_all(&dir);
        ensure_state_dir(&dir).expect("ensure_state_dir failed");

        let file_path = dir.join("test.txt");
        atomic_write_secure(&file_path, b"hello omablock").expect("atomic write failed");

        let content = read_secure_file(&file_path).expect("read failed");
        assert_eq!(content, "hello omablock");

        let meta = fs::symlink_metadata(&file_path).expect("meta failed");
        assert!(!meta.file_type().is_symlink());
        assert!(meta.file_type().is_file());
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_symlink_rejection() {
        let dir = std::env::temp_dir().join("omablock_symlink_test_dir");
        let _ = fs::remove_dir_all(&dir);
        ensure_state_dir(&dir).expect("ensure_state_dir failed");

        let target_file = dir.join("real.txt");
        atomic_write_secure(&target_file, b"real").expect("write real failed");

        let link_file = dir.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target_file, &link_file).expect("symlink failed");

        assert!(verify_secure_file(&link_file).is_err());
        assert!(read_secure_file(&link_file).is_err());
        assert!(atomic_write_secure(&link_file, b"overwritten").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_bounded_reads() {
        let dir = std::env::temp_dir().join("omablock_bounded_read_test");
        let _ = fs::remove_dir_all(&dir);
        ensure_state_dir(&dir).expect("ensure_state_dir failed");

        let file_path = dir.join("bounded.txt");
        let payload = "A".repeat(100);
        atomic_write_secure(&file_path, payload.as_bytes()).expect("write failed");

        // Reading with enough capacity succeeds
        let res_ok = read_secure_file_bounded(&file_path, 150);
        assert!(res_ok.is_ok());
        assert_eq!(res_ok.unwrap().len(), 100);

        // Reading with lower ceiling fails safely
        let res_err = read_secure_file_bounded(&file_path, 50);
        assert!(res_err.is_err());
        assert!(res_err.unwrap_err().contains("exceeds maximum allowed limit"));

        let _ = fs::remove_dir_all(&dir);
    }
}
