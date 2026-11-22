use super::*;

pub(crate) fn lookup_group_gid(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut group = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0; 1024];
    loop {
        let code = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                group.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        match code {
            0 if !result.is_null() => return Some(unsafe { group.assume_init() }.gr_gid),
            libc::ERANGE if buffer.len() < 64 * 1024 => buffer.resize(buffer.len() * 2, 0),
            _ => return None,
        }
    }
}

fn confined_parent(
    path: &Path,
    expected_users: &[&str],
) -> std::io::Result<(job_receipts::ReceiptDirectory, Vec<u32>)> {
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = job_receipts::ReceiptDirectory::open_existing(parent)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let mut owners = Vec::new();
    if unsafe { libc::geteuid() } == 0 {
        owners.push(0);
        owners.extend(
            expected_users
                .iter()
                .filter_map(|name| lookup_passwd_uid_reentrant(name)),
        );
        dir.verify_owners(&owners)?;
    }
    Ok((dir, owners))
}

fn check_confined_owner(file: &fs::File, owners: &[u32]) -> std::io::Result<fs::Metadata> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !owners.is_empty() && !owners.contains(&metadata.uid()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unexpected file owner",
        ));
    }
    Ok(metadata)
}

pub(crate) fn confined_file_name(path: &Path) -> std::io::Result<&std::ffi::OsStr> {
    path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected a regular file name",
        )
    })
}

pub(crate) fn open_confined_file(path: &Path, users: &[&str]) -> std::io::Result<fs::File> {
    let (dir, owners) = confined_parent(path, users)?;
    let file = dir.open_file(confined_file_name(path)?, libc::O_RDONLY, 0)?;
    check_confined_owner(&file, &owners)?;
    Ok(file)
}

pub(crate) fn read_confined_text(path: &Path, users: &[&str]) -> std::io::Result<String> {
    use std::io::Read;
    const LIMIT: u64 = 2 * 1024 * 1024;
    let file = open_confined_file(path, users)?;
    let mut text = String::new();
    file.take(LIMIT + 1).read_to_string(&mut text)?;
    if text.len() as u64 > LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "configuration exceeds 2 MiB",
        ));
    }
    Ok(text)
}

fn dns_provider_users(pihole: bool) -> &'static [&'static str] {
    if pihole {
        &["pihole"]
    } else {
        &["dnsmasq"]
    }
}

pub fn dns_provider_directory_exists(path: &Path, pihole: bool) -> std::io::Result<bool> {
    let Some(directory) = job_receipts::ReceiptDirectory::open_existing(path)? else {
        return Ok(false);
    };
    if unsafe { libc::geteuid() } == 0 {
        let mut owners = vec![0];
        owners.extend(
            dns_provider_users(pihole)
                .iter()
                .filter_map(|name| lookup_passwd_uid_reentrant(name)),
        );
        directory.verify_owners(&owners)?;
    }
    Ok(true)
}

pub fn remove_dns_provider_file(path: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let (dir, owners) = confined_parent(path, dns_provider_users(false))?;
    let name = confined_file_name(path)?;
    let file = match dir.open_file(name, libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    check_confined_owner(&file, &owners)?;
    dir.verify()?;
    job_receipts::verify_entry(dir.file(), name, &file, false)?;
    if unsafe {
        libc::unlinkat(
            dir.file().as_raw_fd(),
            job_receipts::c_name(name)?.as_ptr(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn read_dns_provider_text(path: &Path, pihole: bool) -> std::io::Result<String> {
    read_confined_text(path, dns_provider_users(pihole))
}

pub fn write_dns_provider_text(path: &Path, content: &str, pihole: bool) -> std::io::Result<()> {
    replace_confined_text(path, content, dns_provider_users(pihole), false, pihole)
}

pub(crate) fn write_hosts_file_atomically(path: &Path, content: &str) -> anyhow::Result<()> {
    replace_confined_text(path, content, &[], true, false)?;
    Ok(())
}

pub(crate) fn replace_confined_text(
    path: &Path,
    content: &str,
    users: &[&str],
    hosts: bool,
    pihole: bool,
) -> std::io::Result<()> {
    replace_confined_file(
        path,
        content.as_bytes(),
        Some(users),
        None,
        hosts,
        pihole,
        None,
    )
}

pub(crate) fn replace_confined_file(
    path: &Path,
    content: &[u8],
    users: Option<&[&str]>,
    force_mode: Option<u32>,
    hosts: bool,
    pihole: bool,
    owner_override: Option<(u32, u32)>,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (dir, owners) = if let Some(users) = users {
        confined_parent(path, users)?
    } else {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = job_receipts::ReceiptDirectory::open_existing(parent)?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        (dir, Vec::new())
    };
    let name = confined_file_name(path)?;
    let mut previous =
        match dir.open_file(name, if hosts { libc::O_RDWR } else { libc::O_RDONLY }, 0) {
            Ok(file) => Some(file),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
    let previous_metadata = previous
        .as_ref()
        .map(|file| check_confined_owner(file, &owners))
        .transpose()?;
    let root = unsafe { libc::geteuid() } == 0;
    let (mode, owner) = if hosts {
        (0o644, root.then_some((0, 0)))
    } else if let Some(metadata) = previous_metadata {
        (
            metadata.mode() & if users.is_some() { 0o7777 } else { 0o777 },
            Some((metadata.uid(), metadata.gid())),
        )
    } else {
        (
            if users.is_some() { 0o640 } else { 0o600 },
            root.then(|| {
                (
                    0,
                    if pihole {
                        lookup_group_gid("pihole").unwrap_or(0)
                    } else {
                        0
                    },
                )
            }),
        )
    };
    let mode = force_mode.unwrap_or(mode);
    let owner = owner_override.or(owner);
    let configure = |file: &fs::File| -> std::io::Result<()> {
        if let Some((uid, gid)) = owner {
            let metadata = file.metadata()?;
            if (uid != metadata.uid() || gid != metadata.gid())
                && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
            {
                let error = std::io::Error::last_os_error();
                if users.is_some() || root || error.raw_os_error() != Some(libc::EPERM) {
                    return Err(error);
                }
            }
        }
        file.set_permissions(fs::Permissions::from_mode(mode))
    };
    let temporary = format!(".aetherflow.tmp.{}", uuid::Uuid::new_v4());
    let temporary = std::ffi::OsStr::new(&temporary);
    let mut file = dir.open_file(
        temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let parent = dir.file().as_raw_fd();
    let temporary_c = job_receipts::c_name(temporary)?;
    let name_c = job_receipts::c_name(name)?;
    let result = (|| {
        file.write_all(content)?;
        configure(&file)?;
        file.sync_all()?;
        dir.verify()?;
        job_receipts::verify_entry(dir.file(), temporary, &file, false)?;
        if let Some(previous) = &previous {
            job_receipts::verify_entry(dir.file(), name, previous, false)?;
        } else if !matches!(job_receipts::entry_at(dir.file(), name), Err(err) if err.kind() == std::io::ErrorKind::NotFound)
        {
            return Err(std::io::Error::other(
                "configuration appeared during update",
            ));
        }
        if unsafe { libc::renameat(parent, temporary_c.as_ptr(), parent, name_c.as_ptr()) } == 0 {
            return dir.file().sync_all();
        }
        let error = std::io::Error::last_os_error();
        // Bind-mounted /etc/hosts cannot be replaced. Use only the previously verified inode.
        if hosts && matches!(error.raw_os_error(), Some(libc::EXDEV) | Some(libc::EBUSY)) {
            if let Some(destination) = &mut previous {
                if unsafe { libc::flock(destination.as_raw_fd(), libc::LOCK_EX) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                dir.verify()?;
                job_receipts::verify_entry(dir.file(), name, destination, false)?;
                configure(destination)?;
                destination.set_len(0)?;
                destination.write_all(content)?;
                return destination.sync_all();
            }
        }
        Err(error)
    })();
    unsafe {
        libc::unlinkat(parent, temporary_c.as_ptr(), 0);
    }
    result
}

pub(crate) fn create_package_lock_directory(path: &Path) -> std::io::Result<()> {
    if path.file_name() != Some(std::ffi::OsStr::new("install")) {
        return fs::create_dir_all(path);
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory = job_receipts::ReceiptDirectory::open_existing(path)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    if unsafe { libc::geteuid() } == 0 {
        directory.verify_owners(&[0])?;
        if created {
            let metadata = directory.file().metadata()?;
            let gid = lookup_group_gid("aetherflow").unwrap_or(metadata.gid());
            if metadata.gid() != gid
                && unsafe { libc::fchown(directory.file().as_raw_fd(), 0, gid) } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    if created {
        directory
            .file()
            .set_permissions(fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}
