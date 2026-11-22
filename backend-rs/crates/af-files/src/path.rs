use std::io::{self, Error, ErrorKind};

pub(crate) const MAX_PATH_COMPONENTS: usize = 64;
pub(crate) const MAX_SYMLINK_EXPANSIONS: usize = 40;
pub(crate) const UPLOAD_TEMP_PREFIX: &str = ".af-upload-tmp.";

pub(crate) fn is_internal_upload_temp(name: &str) -> bool {
    name.starts_with(UPLOAD_TEMP_PREFIX)
}

pub(crate) fn parse_relative_path(path: &str, allow_root: bool) -> io::Result<Vec<&str>> {
    if path.len() > 4096 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "path length exceeds limit",
        ));
    }
    if path.as_bytes().contains(&0) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "path contains NUL byte",
        ));
    }
    if path.is_empty() {
        if allow_root {
            return Ok(Vec::new());
        }
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "operation not allowed on root directory",
        ));
    }
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "absolute or backslash paths are not allowed",
        ));
    }

    let mut components = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        if segment == "." || segment == ".." {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "traversal segments are not allowed",
            ));
        }
        if is_internal_upload_temp(segment) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "reserved temporary filename is not allowed",
            ));
        }
        if segment.len() > 255 || components.len() >= MAX_PATH_COMPONENTS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "path component limit exceeded",
            ));
        }
        components.push(segment);
    }

    if components.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid empty path"));
    }

    Ok(components)
}

pub(crate) fn parse_symlink_target_segments(target: &str) -> io::Result<Vec<String>> {
    if target.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "empty symlink target is not allowed",
        ));
    }
    if target.len() > 4096 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "symlink target length exceeds limit",
        ));
    }
    if target.as_bytes().contains(&0) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "symlink target contains NUL byte",
        ));
    }
    if target.starts_with('/') || target.contains('\\') {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "absolute or backslash symlink targets are not permitted",
        ));
    }
    let mut segments = Vec::new();
    for segment in target.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if is_internal_upload_temp(segment) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "symlink target referencing reserved temporary filename is not permitted",
            ));
        }
        if segment.len() > 255 || segments.len() >= MAX_PATH_COMPONENTS {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "symlink target component limit exceeded",
            ));
        }
        segments.push(segment.to_string());
    }
    Ok(segments)
}

pub(crate) fn push_symlink_alias_trace(
    resolution_paths: &mut Vec<String>,
    name_stack: &[String],
    segment: &str,
    pending: &[String],
) {
    let has_parent_traversal = pending.iter().any(|s| s == "..");
    if !has_parent_traversal {
        return;
    }
    let path = if name_stack.is_empty() {
        segment.to_string()
    } else {
        format!("{}/{segment}", name_stack.join("/"))
    };
    if resolution_paths.last() != Some(&path) {
        resolution_paths.push(path);
    }
}

pub(crate) fn push_clean_trace_path(
    resolution_paths: &mut Vec<String>,
    name_stack: &[String],
    current_segment: Option<&str>,
    pending: &[String],
) {
    let mut stack_prefix: Vec<&str> = name_stack.iter().map(String::as_str).collect();
    let mut suffix: Vec<&str> = Vec::new();
    let mut seen_non_parent = false;

    for s in current_segment
        .into_iter()
        .chain(pending.iter().rev().map(String::as_str))
    {
        if s.is_empty() || s == "." {
            continue;
        }
        if s == ".." {
            if seen_non_parent {
                return;
            }
            if stack_prefix.pop().is_none() {
                return;
            }
        } else {
            seen_non_parent = true;
            suffix.push(s);
        }
    }

    stack_prefix.extend(suffix);
    let path = stack_prefix.join("/");
    if resolution_paths.last() != Some(&path) {
        resolution_paths.push(path);
    }
}
