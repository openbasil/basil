// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::attestor_protocol::wire;
use crate::attestor_protocol::{ABSOLUTE_MAX_ID_MAP_RANGES, ABSOLUTE_MAX_STRING_BYTES};

const MAX_PROC_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProcessFact {
    pub peer: wire::PinnedPeer,
    pub uid_map: Vec<wire::IdMapRange>,
    pub gid_map: Vec<wire::IdMapRange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProcError {
    Unavailable,
    Changed,
    Unsupported,
}

pub(super) trait ProcessFactSource: Send + Sync {
    fn observe(&self, pid: u32) -> Result<ProcessFact, ProcError>;
}

#[derive(Clone, Debug)]
pub(super) struct LinuxProcfs {
    root: PathBuf,
}

impl Default for LinuxProcfs {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/proc"),
        }
    }
}

impl LinuxProcfs {
    fn observe_once(&self, pid: u32) -> Result<ProcessFact, ProcError> {
        if pid == 0 {
            return Err(ProcError::Unsupported);
        }
        let directory = self.root.join(pid.to_string());
        let first_stat = read_bounded(&directory.join("stat"))?;
        let start_time_ticks = parse_start_time(&first_stat)?;
        let cgroup = parse_cgroup(&read_bounded(&directory.join("cgroup"))?)?;
        let namespaces = read_namespaces(&directory.join("ns"))?;
        let uid_map = parse_id_map(&read_bounded(&directory.join("uid_map"))?)?;
        let gid_map = parse_id_map(&read_bounded(&directory.join("gid_map"))?)?;
        let second_stat = read_bounded(&directory.join("stat"))?;
        if parse_start_time(&second_stat)? != start_time_ticks {
            return Err(ProcError::Changed);
        }
        Ok(ProcessFact {
            peer: wire::PinnedPeer {
                pid,
                start_time_ticks,
                cgroup,
                namespaces: Some(namespaces),
            },
            uid_map,
            gid_map,
        })
    }
}

impl ProcessFactSource for LinuxProcfs {
    fn observe(&self, pid: u32) -> Result<ProcessFact, ProcError> {
        self.observe_once(pid)
    }
}

fn read_bounded(path: &Path) -> Result<String, ProcError> {
    let mut file = fs::File::open(path).map_err(|_| ProcError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| ProcError::Unavailable)?;
    if metadata.len() > MAX_PROC_FILE_BYTES {
        return Err(ProcError::Unsupported);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_PROC_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProcError::Unavailable)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_PROC_FILE_BYTES) {
        return Err(ProcError::Unsupported);
    }
    String::from_utf8(bytes).map_err(|_| ProcError::Unavailable)
}

fn parse_start_time(stat: &str) -> Result<u64, ProcError> {
    let (_, fields) = stat.rsplit_once(") ").ok_or(ProcError::Unavailable)?;
    fields
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or(ProcError::Unavailable)
}

fn parse_cgroup(raw: &str) -> Result<String, ProcError> {
    let mut unified = raw.lines().filter_map(|line| line.strip_prefix("0::"));
    let value = unified.next().ok_or(ProcError::Unsupported)?;
    if unified.next().is_some()
        || value.is_empty()
        || value.len() > ABSOLUTE_MAX_STRING_BYTES
        || !value.starts_with('/')
        || value.contains('\0')
    {
        return Err(ProcError::Unsupported);
    }
    Ok(value.to_string())
}

fn read_namespaces(directory: &Path) -> Result<wire::NamespaceInodes, ProcError> {
    Ok(wire::NamespaceInodes {
        user: read_namespace(directory, "user")?,
        pid: read_namespace(directory, "pid")?,
        mount: read_namespace(directory, "mnt")?,
        network: read_namespace(directory, "net")?,
        uts: read_namespace(directory, "uts")?,
        ipc: read_namespace(directory, "ipc")?,
        cgroup: read_namespace(directory, "cgroup")?,
    })
}

fn read_namespace(directory: &Path, name: &str) -> Result<u64, ProcError> {
    let target = fs::read_link(directory.join(name)).map_err(|_| ProcError::Unavailable)?;
    let target = target.to_string_lossy();
    target
        .strip_suffix(']')
        .and_then(|value| value.rsplit_once('['))
        .and_then(|(_, inode)| inode.parse().ok())
        .filter(|inode| *inode != 0)
        .ok_or(ProcError::Unavailable)
}

fn parse_id_map(raw: &str) -> Result<Vec<wire::IdMapRange>, ProcError> {
    let mut ranges = Vec::new();
    for line in raw.lines() {
        if ranges.len() >= ABSOLUTE_MAX_ID_MAP_RANGES {
            return Err(ProcError::Unsupported);
        }
        let values = line
            .split_ascii_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProcError::Unavailable)?;
        let [inside_id, outside_id, length] = values.as_slice() else {
            return Err(ProcError::Unavailable);
        };
        if *length == 0 {
            return Err(ProcError::Unsupported);
        }
        let range = wire::IdMapRange {
            inside_id: *inside_id,
            outside_id: *outside_id,
            length: *length,
        };
        if u64::from(range.inside_id) + u64::from(range.length) > u64::from(u32::MAX) + 1
            || u64::from(range.outside_id) + u64::from(range.length) > u64::from(u32::MAX) + 1
        {
            return Err(ProcError::Unsupported);
        }
        ranges.push(range);
    }
    if ranges.is_empty() {
        return Err(ProcError::Unsupported);
    }
    for (index, left) in ranges.iter().enumerate() {
        if ranges.iter().skip(index + 1).any(|right| {
            overlaps(left.inside_id, left.length, right.inside_id, right.length)
                || overlaps(left.outside_id, left.length, right.outside_id, right.length)
        }) {
            return Err(ProcError::Unsupported);
        }
    }
    Ok(ranges)
}

fn overlaps(first: u32, first_len: u32, second: u32, second_len: u32) -> bool {
    let first_start = u64::from(first);
    let first_end = first_start + u64::from(first_len);
    let second_start = u64::from(second);
    let second_end = second_start + u64::from(second_len);
    first_start < second_end && second_start < first_end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_v2_parser_rejects_legacy_and_ambiguous_membership() {
        assert_eq!(
            parse_cgroup("0::/system.slice/docker.scope\n").unwrap(),
            "/system.slice/docker.scope"
        );
        assert_eq!(parse_cgroup("2:cpu:/legacy\n"), Err(ProcError::Unsupported));
        assert_eq!(
            parse_cgroup("0::/one\n0::/two\n"),
            Err(ProcError::Unsupported)
        );
    }

    #[test]
    fn id_maps_are_bounded_and_non_overlapping() {
        assert_eq!(
            parse_id_map("0 0 4294967295\n").unwrap(),
            [wire::IdMapRange {
                inside_id: 0,
                outside_id: 0,
                length: u32::MAX,
            }]
        );
        assert_eq!(
            parse_id_map("0 0 10\n5 20 10\n"),
            Err(ProcError::Unsupported)
        );
    }
}
