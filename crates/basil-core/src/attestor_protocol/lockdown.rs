// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Post-init runtime lockdown primitive (`basil-rslz`; design `basil-kqc7`
//! via review `basil-pb33`, maintainer resolution 2026-07-20).
//!
//! [`engage`] establishes the ordered lockdown contract required by
//! `docs/attestor-realm-contract/SPEC.md` rev 1.2 ("Socket and release
//! authentication"): after every thread and long-lived descriptor already
//! exists, the process becomes non-dumpable and installs a set of
//! thread-synchronized (`TSYNC`) post-init seccomp filters, verifies the live
//! state, and only then may a socket be bound. The returned [`LockdownGuard`]
//! is the witness the bind entry points
//! ([`crate::attestor_protocol::AttestorListener::bind`] and the helper
//! `HelperListener::bind`) require by reference, so the ordering is a
//! compile-time property: no socket can be bound without a guard, and a guard
//! only exists after `engage` returned.
//!
//! ## Filter composition (SPEC-required denies vs defense-in-depth)
//!
//! The kill/errno split is expressed as multiple deterministic filters, each
//! with a single action, installed in one `TSYNC` sequence (a `SeccompFilter`
//! carries one match action, so a mixed table must be several filters):
//!
//! - **Kill filter** (`KillProcess`) — the SPEC-required denies: `execve`,
//!   `execveat`, `fork`, `vfork`, process-creating `clone` (masked on
//!   `CLONE_THREAD`), `ptrace`, `process_vm_readv`/`writev`, `pidfd_getfd`,
//!   plus the lockdown-reversal attempts `prctl(PR_SET_DUMPABLE, 1)` and
//!   `prctl(PR_SET_PTRACER, ...)`.
//! - **`clone3` filter** (`Errno(ENOSYS)`) — `clone3` cannot be arg-filtered
//!   (its flags live behind a pointer BPF cannot read), so it is denied with
//!   `ENOSYS`, which makes `glibc`/`tokio` fall back to the arg-filterable
//!   `clone` mediated by the kill filter.
//! - **Indirect-surface filter** (`Errno(EPERM)`) — defense-in-depth beyond
//!   the SPEC set: `io_uring_setup`/`enter`/`register` and
//!   `kexec_load`/`kexec_file_load`/`init_module`/`finit_module`/
//!   `delete_module`. The unit bounding set already removes these; the filter
//!   is belt-and-braces.
//!
//! The compiled filter stack also kills on a `seccomp-data` architecture
//! mismatch (every program carries the arch-validation prologue) and, on
//! x86-64, on any x32-ABI syscall number: x32 calls report
//! `AUDIT_ARCH_X86_64` with `X32_SYSCALL_BIT` set in the number, so a
//! dedicated guard program kills every number with that bit — a native
//! syscall-number denylist without it would be bypassable by entering through
//! the x32 ABI. Both properties are proven by unit tests interpreting the
//! compiled BPF programs.
//!
//! ## Honest limits
//!
//! Seccomp cannot inspect `sendmsg` ancillary data, so `SCM_RIGHTS` descriptor
//! transfer as such is not seccomp-deniable while `sendmsg` stays allowed (the
//! helper response path needs it); the explicit `pidfd_getfd` denial plus the
//! LSM/socket-authentication layers cover descriptor theft. The manager's
//! `SystemCallFilter=` baseline stacks additively with these filters.

use super::helper::ident;

/// `CLONE_THREAD` flag: a `clone` carrying it creates a thread, not a process.
///
/// Documented kernel ABI constant (`linux/sched.h`); kept local so the module
/// needs no direct `libc` dependency (the arch-specific syscall numbers below
/// are likewise documented ABI values).
const CLONE_THREAD: u64 = 0x0001_0000;

/// `prctl` option `PR_SET_DUMPABLE` (`linux/prctl.h`).
const PR_SET_DUMPABLE: u64 = 4;

/// `prctl` argument re-enabling core dumps and same-UID `ptrace`/`/proc/mem`.
const PR_SET_DUMPABLE_ENABLE: u64 = 1;

/// `prctl` option `PR_SET_PTRACER` (Yama; `linux/prctl.h`).
const PR_SET_PTRACER: u64 = 0x5961_6d61;

/// `errno` `ENOSYS` (function not implemented).
const ENOSYS: u32 = 38;

/// `errno` `EPERM` (operation not permitted).
const EPERM: u32 = 1;

/// x32-ABI marker bit in an x86-64 syscall number (`__X32_SYSCALL_BIT`,
/// `arch/x86/include/uapi/asm/unistd.h`). x32 calls carry
/// `AUDIT_ARCH_X86_64`, so the arch prologue alone does not stop them.
#[cfg(target_os = "linux")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// `AUDIT_ARCH_X86_64` (`linux/audit.h`).
#[cfg(target_os = "linux")]
const AUDIT_ARCH_X86_64: u32 = 0x3e | 0x8000_0000 | 0x4000_0000;

/// `AUDIT_ARCH_AARCH64` (`linux/audit.h`).
#[cfg(all(target_os = "linux", test))]
const AUDIT_ARCH_AARCH64: u32 = 0xb7 | 0x8000_0000 | 0x4000_0000;

// Classic-BPF opcodes used by the hand-built x32 guard program
// (`linux/bpf_common.h`); documented, stable kernel ABI values.
/// `BPF_LD | BPF_W | BPF_ABS`: load a 32-bit `seccomp_data` word.
#[cfg(target_os = "linux")]
const BPF_LD_W_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`: jump if the accumulator equals `k`.
#[cfg(target_os = "linux")]
const BPF_JEQ_K: u16 = 0x15;
/// `BPF_JMP | BPF_JGE | BPF_K`: jump if the accumulator is `>= k` (unsigned).
#[cfg(target_os = "linux")]
const BPF_JGE_K: u16 = 0x35;
/// `BPF_RET | BPF_K`: return `k` as the filter action.
#[cfg(target_os = "linux")]
const BPF_RET_K: u16 = 0x06;

/// `SECCOMP_RET_KILL_PROCESS` (`linux/seccomp.h`).
#[cfg(target_os = "linux")]
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// `SECCOMP_RET_ALLOW` (`linux/seccomp.h`).
#[cfg(target_os = "linux")]
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// `seccomp_data.arch` byte offset.
#[cfg(target_os = "linux")]
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// `seccomp_data.nr` byte offset.
#[cfg(target_os = "linux")]
const SECCOMP_DATA_NR_OFFSET: u32 = 0;

/// One syscall the lockdown profile references, with its per-architecture
/// numbers.
///
/// Numbers are documented, stable kernel ABI values (cross-checked against
/// the `seccompiler` per-arch syscall tables at adoption). `fork`/`vfork` do
/// not exist on `aarch64` (`glibc` uses `clone` there), so their `aarch64`
/// number is `None` and they are simply absent from the `aarch64` filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SyscallNumbers {
    name: &'static str,
    x86_64: Option<i64>,
    aarch64: Option<i64>,
}

impl SyscallNumbers {
    const fn number_for(self, arch: LockdownArch) -> Option<i64> {
        match arch {
            LockdownArch::X86_64 => self.x86_64,
            LockdownArch::Aarch64 => self.aarch64,
        }
    }
}

const EXECVE: SyscallNumbers = SyscallNumbers {
    name: "execve",
    x86_64: Some(59),
    aarch64: Some(221),
};
const EXECVEAT: SyscallNumbers = SyscallNumbers {
    name: "execveat",
    x86_64: Some(322),
    aarch64: Some(281),
};
const FORK: SyscallNumbers = SyscallNumbers {
    name: "fork",
    x86_64: Some(57),
    aarch64: None,
};
const VFORK: SyscallNumbers = SyscallNumbers {
    name: "vfork",
    x86_64: Some(58),
    aarch64: None,
};
const CLONE: SyscallNumbers = SyscallNumbers {
    name: "clone",
    x86_64: Some(56),
    aarch64: Some(220),
};
const CLONE3: SyscallNumbers = SyscallNumbers {
    name: "clone3",
    x86_64: Some(435),
    aarch64: Some(435),
};
const PTRACE: SyscallNumbers = SyscallNumbers {
    name: "ptrace",
    x86_64: Some(101),
    aarch64: Some(117),
};
const PROCESS_VM_READV: SyscallNumbers = SyscallNumbers {
    name: "process_vm_readv",
    x86_64: Some(310),
    aarch64: Some(270),
};
const PROCESS_VM_WRITEV: SyscallNumbers = SyscallNumbers {
    name: "process_vm_writev",
    x86_64: Some(311),
    aarch64: Some(271),
};
const PIDFD_GETFD: SyscallNumbers = SyscallNumbers {
    name: "pidfd_getfd",
    x86_64: Some(438),
    aarch64: Some(438),
};
const PRCTL: SyscallNumbers = SyscallNumbers {
    name: "prctl",
    x86_64: Some(157),
    aarch64: Some(167),
};
const IO_URING_SETUP: SyscallNumbers = SyscallNumbers {
    name: "io_uring_setup",
    x86_64: Some(425),
    aarch64: Some(425),
};
const IO_URING_ENTER: SyscallNumbers = SyscallNumbers {
    name: "io_uring_enter",
    x86_64: Some(426),
    aarch64: Some(426),
};
const IO_URING_REGISTER: SyscallNumbers = SyscallNumbers {
    name: "io_uring_register",
    x86_64: Some(427),
    aarch64: Some(427),
};
const KEXEC_LOAD: SyscallNumbers = SyscallNumbers {
    name: "kexec_load",
    x86_64: Some(246),
    aarch64: Some(104),
};
const KEXEC_FILE_LOAD: SyscallNumbers = SyscallNumbers {
    name: "kexec_file_load",
    x86_64: Some(320),
    aarch64: Some(294),
};
const INIT_MODULE: SyscallNumbers = SyscallNumbers {
    name: "init_module",
    x86_64: Some(175),
    aarch64: Some(105),
};
const FINIT_MODULE: SyscallNumbers = SyscallNumbers {
    name: "finit_module",
    x86_64: Some(313),
    aarch64: Some(273),
};
const DELETE_MODULE: SyscallNumbers = SyscallNumbers {
    name: "delete_module",
    x86_64: Some(176),
    aarch64: Some(106),
};

/// An argument match condition on one syscall register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArgCondition {
    /// Zero-based syscall argument index.
    arg_index: u8,
    /// Comparison to apply.
    compare: ArgCompare,
    /// Comparand.
    value: u64,
}

/// Comparison an [`ArgCondition`] performs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArgCompare {
    /// Exact equality.
    Eq,
    /// Masked equality: `(arg & mask) == (value & mask)`.
    MaskedEq(u64),
}

/// One syscall rule: match action fires when every condition holds (an empty
/// condition list matches on the syscall number alone).
#[derive(Clone, Debug)]
struct SyscallRule {
    syscall: SyscallNumbers,
    conditions: Vec<ArgCondition>,
}

/// The abstract action applied by one filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilterAction {
    /// Kill the whole process (`SCMP_ACT_KILL_PROCESS`).
    KillProcess,
    /// Return the given `errno`.
    Errno(u32),
}

/// One single-action filter: every rule shares the same match action, and the
/// default (mismatch) action is always `Allow`.
#[derive(Clone, Debug)]
struct FilterSpec {
    action: FilterAction,
    rules: Vec<SyscallRule>,
}

const fn kill_number_only(syscall: SyscallNumbers) -> SyscallRule {
    SyscallRule {
        syscall,
        conditions: Vec::new(),
    }
}

/// The abstract, architecture-independent filter specs for one profile kind.
///
/// This is the normative denylist; it is translated to a concrete BPF program
/// per architecture in [`compile`]. Keeping it abstract makes the membership,
/// actions, and `clone` mask directly testable without a live install.
fn filter_specs(kind: LockdownProfileKind) -> Vec<FilterSpec> {
    // The kill filter's process-creating `clone` rule: kill when CLONE_THREAD
    // is clear. The helper is synchronous and serial, so it denies all
    // `clone`; the attestor runs tokio, so thread-only `clone` stays allowed.
    let clone_rule = match kind {
        LockdownProfileKind::AttestorV1 => SyscallRule {
            syscall: CLONE,
            conditions: vec![ArgCondition {
                arg_index: 0,
                compare: ArgCompare::MaskedEq(CLONE_THREAD),
                value: 0,
            }],
        },
        LockdownProfileKind::MeasureHelperV1 => kill_number_only(CLONE),
    };

    let kill = FilterSpec {
        action: FilterAction::KillProcess,
        rules: vec![
            kill_number_only(EXECVE),
            kill_number_only(EXECVEAT),
            kill_number_only(FORK),
            kill_number_only(VFORK),
            clone_rule,
            kill_number_only(PTRACE),
            kill_number_only(PROCESS_VM_READV),
            kill_number_only(PROCESS_VM_WRITEV),
            kill_number_only(PIDFD_GETFD),
            // Lockdown-reversal attempts, argument-filtered so ordinary prctl
            // options (thread naming, the pre-lockdown no-new-privs) stay
            // allowed.
            SyscallRule {
                syscall: PRCTL,
                conditions: vec![
                    ArgCondition {
                        arg_index: 0,
                        compare: ArgCompare::Eq,
                        value: PR_SET_DUMPABLE,
                    },
                    ArgCondition {
                        arg_index: 1,
                        compare: ArgCompare::Eq,
                        value: PR_SET_DUMPABLE_ENABLE,
                    },
                ],
            },
            SyscallRule {
                syscall: PRCTL,
                conditions: vec![ArgCondition {
                    arg_index: 0,
                    compare: ArgCompare::Eq,
                    value: PR_SET_PTRACER,
                }],
            },
        ],
    };

    let clone3 = FilterSpec {
        action: FilterAction::Errno(ENOSYS),
        rules: vec![kill_number_only(CLONE3)],
    };

    let indirect = FilterSpec {
        action: FilterAction::Errno(EPERM),
        rules: vec![
            kill_number_only(IO_URING_SETUP),
            kill_number_only(IO_URING_ENTER),
            kill_number_only(IO_URING_REGISTER),
            kill_number_only(KEXEC_LOAD),
            kill_number_only(KEXEC_FILE_LOAD),
            kill_number_only(INIT_MODULE),
            kill_number_only(FINIT_MODULE),
            kill_number_only(DELETE_MODULE),
        ],
    };

    vec![kill, clone3, indirect]
}

/// Which compiled filter body to install.
///
/// The identity is authority data; the body is compiled into the binary and
/// versioned by this enum, so a body change forces a new profile kind and
/// therefore a new profile identity under a new authority generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockdownProfileKind {
    /// Attestor: tokio multi-thread runtime; thread-only `clone` stays allowed.
    AttestorV1,
    /// Measurement helper: synchronous and serial; denies all `clone`.
    MeasureHelperV1,
}

impl LockdownProfileKind {
    /// The canonical, generation-independent base of this kind's profile
    /// identity (a valid identity appends `-g<generation>`).
    #[must_use]
    pub const fn identity_base(self) -> &'static str {
        match self {
            Self::AttestorV1 => "basil-attestor-lockdown",
            Self::MeasureHelperV1 => "basil-measure-helper-lockdown",
        }
    }
}

/// A target architecture the profile can be compiled for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockdownArch {
    /// `x86_64`.
    X86_64,
    /// `aarch64`.
    Aarch64,
}

impl LockdownArch {
    /// The architecture this binary was compiled for, when supported.
    #[must_use]
    pub const fn native() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            Some(Self::X86_64)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Some(Self::Aarch64)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            None
        }
    }
}

/// A checked, generation-qualified lockdown profile identity.
///
/// Reuses the helper canonical-identity grammar and the checked
/// generation-qualifier binding, so a profile identity is nameable by broker
/// configuration exactly when it is valid here. A `kind` couples the identity
/// to the compiled body: the identity base must match the kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockdownProfileId {
    identity: String,
    generation: std::num::NonZeroU64,
    kind: LockdownProfileKind,
}

impl LockdownProfileId {
    /// Validate `identity` as this kind's generation-`generation` profile.
    ///
    /// # Errors
    ///
    /// Returns [`LockdownError::Identity`] when the identity is not canonical,
    /// does not embed the exact generation qualifier, or does not name this
    /// kind's compiled body.
    pub fn new(
        identity: &str,
        generation: std::num::NonZeroU64,
        kind: LockdownProfileKind,
    ) -> Result<Self, LockdownError> {
        if !ident::is_valid_identity(identity)
            || !ident::embeds_exact_generation(identity, generation.get())
        {
            return Err(LockdownError::Identity);
        }
        // The identity must be exactly the kind's base plus the generation
        // qualifier, so a valid identity of the wrong body cannot be presented
        // for this kind.
        let expected = format!("{}-g{generation}", kind.identity_base());
        if identity != expected {
            return Err(LockdownError::Identity);
        }
        Ok(Self {
            identity: identity.to_owned(),
            generation,
            kind,
        })
    }

    /// The validated identity string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.identity
    }

    /// The bound authority generation.
    #[must_use]
    pub const fn generation(&self) -> std::num::NonZeroU64 {
        self.generation
    }

    /// The compiled body this identity names.
    #[must_use]
    pub const fn kind(&self) -> LockdownProfileKind {
        self.kind
    }
}

/// A lockdown profile: the compiled body plus its checked authority identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockdownProfile {
    identity: LockdownProfileId,
}

impl LockdownProfile {
    /// Pair a checked identity with the body it names.
    #[must_use]
    pub const fn new(identity: LockdownProfileId) -> Self {
        Self { identity }
    }

    /// The compiled body kind.
    #[must_use]
    pub const fn kind(&self) -> LockdownProfileKind {
        self.identity.kind
    }

    /// The checked profile identity.
    #[must_use]
    pub const fn identity(&self) -> &LockdownProfileId {
        &self.identity
    }
}

/// Witness that lockdown is engaged on this process.
///
/// Constructed only by [`engage`] (and, under `cfg(test)`, by
/// [`LockdownGuard::for_test`]); required by reference at every socket-bind
/// entry point, which makes the ordered contract a compile-time property. Not
/// `Clone`.
#[derive(Debug)]
pub struct LockdownGuard {
    profile: LockdownProfileId,
}

impl LockdownGuard {
    /// The engaged profile identity.
    #[must_use]
    pub const fn profile(&self) -> &LockdownProfileId {
        &self.profile
    }

    /// Test-only guard construction, so bind-path tests can exercise the
    /// witness parameter without engaging seccomp (which would filter or kill
    /// the shared cargo-test harness process).
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn for_test(profile: LockdownProfileId) -> Self {
        Self { profile }
    }
}

/// A failure engaging or validating lockdown.
///
/// Every variant before the guard is returned is fatal to startup: the caller
/// must exit before binding any socket, never serve degraded.
#[derive(Debug, thiserror::Error)]
pub enum LockdownError {
    /// The profile identity is not canonical, wrongly generationed, or names the
    /// wrong body.
    #[error("invalid lockdown profile identity")]
    Identity,
    /// This platform has no lockdown implementation.
    #[error("post-init lockdown is not supported on this platform")]
    Unsupported,
    /// Compiling the filter body to BPF failed.
    #[error("failed to compile the lockdown filter: {0}")]
    Compile(String),
    /// Setting the process non-dumpable failed.
    #[error("failed to set the process non-dumpable: {0}")]
    NonDumpable(String),
    /// Thread-synchronized filter install failed because a peer thread could
    /// not be synchronized.
    #[error("thread-synchronized seccomp install conflicted on thread {thread_id}")]
    TsyncConflict {
        /// Kernel id of the thread that could not be synchronized.
        thread_id: i64,
    },
    /// Installing a compiled filter failed.
    #[error("failed to install the lockdown filter: {0}")]
    Install(String),
    /// Live post-install verification did not observe the engaged state.
    #[error("lockdown verification failed: {0}")]
    Verify(String),
}

/// Engage the ordered lockdown contract and return the witness guard.
///
/// Call only after every thread and long-lived descriptor already exists
/// (step 1 of the contract is the caller's obligation). `engage` then:
///
/// 1. sets `PR_SET_DUMPABLE(0)` (closes same-UID `/proc/<pid>/mem` and
///    `ptrace` from this instant; the pre-instant window is the LSM domain's
///    responsibility per the SPEC split);
/// 2. compiles the profile body for the native architecture and installs each
///    filter with `TSYNC` in one sequence — any conflict is fatal;
/// 3. verifies the live state (`Seccomp: 2`, `NoNewPrivs: 1`, dumpable
///    disabled) and, for the attestor body, proves the `clone3` → `ENOSYS` →
///    thread-`clone` fallback with a real `std::thread` spawn/join round-trip.
///
/// Only after this returns may the caller remove a stale socket, bind, listen,
/// and advertise readiness; the bind helpers require the returned guard.
///
/// # Errors
///
/// Returns [`LockdownError`] on any step; the caller must exit before binding.
#[cfg(target_os = "linux")]
pub fn engage(profile: &LockdownProfile) -> Result<LockdownGuard, LockdownError> {
    let arch = LockdownArch::native().ok_or(LockdownError::Unsupported)?;
    let programs = compile(profile.kind(), arch)?;

    // Step 2 (dumpable) precedes filter install so a re-enable attempt after
    // install is itself a killed syscall.
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|error| LockdownError::NonDumpable(error.to_string()))?;

    for program in &programs {
        seccompiler::apply_filter_all_threads(program).map_err(|error| match error {
            seccompiler::Error::ThreadSync(thread_id) => LockdownError::TsyncConflict { thread_id },
            other => LockdownError::Install(other.to_string()),
        })?;
    }

    verify_engaged(profile.kind())?;
    Ok(LockdownGuard {
        profile: profile.identity.clone(),
    })
}

/// Non-Linux stub: lockdown has no implementation, so it fails closed.
#[cfg(not(target_os = "linux"))]
pub fn engage(_profile: &LockdownProfile) -> Result<LockdownGuard, LockdownError> {
    Err(LockdownError::Unsupported)
}

/// Compile one profile kind's filter set to installable BPF programs for
/// `arch`.
///
/// Architecture-parameterized from the start so both `x86_64` and `aarch64`
/// programs are produced (and tested) regardless of the build host.
#[cfg(target_os = "linux")]
fn compile(
    kind: LockdownProfileKind,
    arch: LockdownArch,
) -> Result<Vec<seccompiler::BpfProgram>, LockdownError> {
    use std::collections::BTreeMap;

    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    let target = match arch {
        LockdownArch::X86_64 => TargetArch::x86_64,
        LockdownArch::Aarch64 => TargetArch::aarch64,
    };

    let mut programs = Vec::new();
    if arch == LockdownArch::X86_64 {
        // First program in the stack: kill any x32-ABI syscall number.
        // seccompiler's own prologue validates only `seccomp_data.arch`, and
        // x32 calls report AUDIT_ARCH_X86_64, so without this guard the
        // native-number denylist below would be bypassable via the x32 ABI.
        programs.push(x32_guard_program());
    }
    for spec in filter_specs(kind) {
        let match_action = match spec.action {
            FilterAction::KillProcess => SeccompAction::KillProcess,
            FilterAction::Errno(code) => SeccompAction::Errno(code),
        };
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for rule in spec.rules {
            let Some(number) = rule.syscall.number_for(arch) else {
                // Syscall absent on this architecture (e.g. fork/vfork on
                // aarch64); nothing to deny.
                continue;
            };
            let entry = rules.entry(number).or_default();
            if rule.conditions.is_empty() {
                // Match on the syscall number alone: an empty rule vector for
                // this number carries that meaning to seccompiler.
                continue;
            }
            let conditions = rule
                .conditions
                .into_iter()
                .map(|condition| {
                    let operator = match condition.compare {
                        ArgCompare::Eq => SeccompCmpOp::Eq,
                        ArgCompare::MaskedEq(mask) => SeccompCmpOp::MaskedEq(mask),
                    };
                    SeccompCondition::new(
                        condition.arg_index,
                        SeccompCmpArgLen::Qword,
                        operator,
                        condition.value,
                    )
                    .map_err(|error| LockdownError::Compile(error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            entry.push(
                SeccompRule::new(conditions)
                    .map_err(|error| LockdownError::Compile(error.to_string()))?,
            );
        }
        let filter = SeccompFilter::new(rules, SeccompAction::Allow, match_action, target)
            .map_err(|error| LockdownError::Compile(error.to_string()))?;
        let program = seccompiler::BpfProgram::try_from(filter)
            .map_err(|error| LockdownError::Compile(error.to_string()))?;
        programs.push(program);
    }
    Ok(programs)
}

/// The hand-built x86-64 x32 guard program.
///
/// ```text
/// 0: A = seccomp_data.arch
/// 1: if A == AUDIT_ARCH_X86_64 skip the kill        (jt=1)
/// 2: return KILL_PROCESS                            (foreign architecture)
/// 3: A = seccomp_data.nr
/// 4: if A >= X32_SYSCALL_BIT fall through to kill   (jf=1 skips it)
/// 5: return KILL_PROCESS                            (x32-ABI number)
/// 6: return ALLOW
/// ```
///
/// Native x86-64 syscall numbers are all below `X32_SYSCALL_BIT`, so the
/// unsigned `>=` comparison kills exactly the foreign-ABI number space.
#[cfg(target_os = "linux")]
fn x32_guard_program() -> seccompiler::BpfProgram {
    let statement = |code: u16, k: u32| seccompiler::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u16, k: u32, jt: u8, jf: u8| seccompiler::sock_filter { code, jt, jf, k };
    vec![
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JGE_K, X32_SYSCALL_BIT, 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]
}

/// Verify the live post-install state without any destructive probe.
///
/// Kill-mode rules cannot be probed in-process (they would kill this process);
/// the live conformance lane proves those. Here we require `/proc/self/status`
/// to report `Seccomp: 2` (filter mode) and `NoNewPrivs: 1`, the dumpable
/// attribute to read back disabled, and — for the attestor body, whose runtime
/// creates threads for its whole life — a real `std::thread` spawn/join
/// round-trip proving the `clone3` → `ENOSYS` → thread-`clone` fallback under
/// the installed filters. The helper body denies all `clone`, so no thread
/// probe runs there.
///
/// The reviewed verify step also names an `io_uring_setup` probe expecting
/// `EPERM`; `rustix` 1.1.4 exposes `io_uring_setup` only as `unsafe`, so under
/// the workspace `unsafe_code = forbid` there is no safe probe path today.
/// The `EPERM` filter itself is installed and asserted against the compiled
/// program in unit tests; the live conformance lane proves it end to end.
#[cfg(target_os = "linux")]
fn verify_engaged(kind: LockdownProfileKind) -> Result<(), LockdownError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| LockdownError::Verify(error.to_string()))?;
    let field = |name: &str| -> Option<u32> {
        status.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(':'))
                .and_then(|value| value.trim().parse().ok())
        })
    };
    if field("Seccomp") != Some(2) {
        return Err(LockdownError::Verify(
            "`/proc/self/status` did not report `Seccomp: 2`".to_owned(),
        ));
    }
    if field("NoNewPrivs") != Some(1) {
        return Err(LockdownError::Verify(
            "`/proc/self/status` did not report `NoNewPrivs: 1`".to_owned(),
        ));
    }
    match rustix::process::dumpable_behavior() {
        Ok(rustix::process::DumpableBehavior::NotDumpable) => {}
        Ok(_) => {
            return Err(LockdownError::Verify(
                "the process reads back as dumpable after lockdown".to_owned(),
            ));
        }
        Err(error) => {
            return Err(LockdownError::Verify(format!(
                "could not read the dumpable attribute: {error}"
            )));
        }
    }
    if kind == LockdownProfileKind::AttestorV1 {
        let joined = std::thread::Builder::new()
            .name("lockdown-verify".to_owned())
            .spawn(|| ())
            .map_err(|error| {
                LockdownError::Verify(format!(
                    "thread creation failed under the engaged filter \
                     (`clone3` fallback broken): {error}"
                ))
            })?
            .join();
        if joined.is_err() {
            return Err(LockdownError::Verify(
                "the post-lockdown probe thread did not join cleanly".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::num::NonZeroU64;

    use super::*;

    fn generation(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    #[test]
    fn identity_binds_generation_and_body() {
        let id = LockdownProfileId::new(
            "basil-attestor-lockdown-g3",
            generation(3),
            LockdownProfileKind::AttestorV1,
        )
        .expect("canonical generation-qualified identity");
        assert_eq!(id.as_str(), "basil-attestor-lockdown-g3");
        assert_eq!(id.generation().get(), 3);
        assert_eq!(id.kind(), LockdownProfileKind::AttestorV1);

        let helper = LockdownProfileId::new(
            "basil-measure-helper-lockdown-g1",
            generation(1),
            LockdownProfileKind::MeasureHelperV1,
        )
        .expect("helper identity");
        assert_eq!(helper.kind(), LockdownProfileKind::MeasureHelperV1);
    }

    #[test]
    fn identity_rejects_wrong_generation_kind_or_grammar() {
        // Generation qualifier names a different generation.
        assert!(matches!(
            LockdownProfileId::new(
                "basil-attestor-lockdown-g2",
                generation(3),
                LockdownProfileKind::AttestorV1
            ),
            Err(LockdownError::Identity)
        ));
        // Body base does not match the kind.
        assert!(matches!(
            LockdownProfileId::new(
                "basil-measure-helper-lockdown-g3",
                generation(3),
                LockdownProfileKind::AttestorV1
            ),
            Err(LockdownError::Identity)
        ));
        // No generation qualifier at all.
        assert!(matches!(
            LockdownProfileId::new(
                "basil-attestor-lockdown",
                generation(3),
                LockdownProfileKind::AttestorV1
            ),
            Err(LockdownError::Identity)
        ));
        // Leading-zero generation token can never validate.
        assert!(matches!(
            LockdownProfileId::new(
                "basil-attestor-lockdown-g03",
                generation(3),
                LockdownProfileKind::AttestorV1
            ),
            Err(LockdownError::Identity)
        ));
        // Non-canonical grammar (uppercase).
        assert!(matches!(
            LockdownProfileId::new(
                "Basil-Attestor-Lockdown-g3",
                generation(3),
                LockdownProfileKind::AttestorV1
            ),
            Err(LockdownError::Identity)
        ));
    }

    /// The abstract denylist covers exactly the SPEC-required denies plus the
    /// stated defense-in-depth set, split by action into three filters.
    #[test]
    fn filter_specs_cover_the_documented_set() {
        for kind in [
            LockdownProfileKind::AttestorV1,
            LockdownProfileKind::MeasureHelperV1,
        ] {
            let specs = filter_specs(kind);
            assert_eq!(specs.len(), 3, "kill + clone3 + indirect filters");

            let kill = &specs[0];
            assert_eq!(kill.action, FilterAction::KillProcess);
            let kill_names: Vec<&str> = kill.rules.iter().map(|rule| rule.syscall.name).collect();
            for required in [
                "execve",
                "execveat",
                "fork",
                "vfork",
                "clone",
                "ptrace",
                "process_vm_readv",
                "process_vm_writev",
                "pidfd_getfd",
            ] {
                assert!(
                    kill_names.contains(&required),
                    "kill filter missing {required}"
                );
            }
            // Both lockdown-reversal prctl rules are present and argument
            // filtered (never a blanket prctl kill).
            let prctl_rules: Vec<&SyscallRule> = kill
                .rules
                .iter()
                .filter(|rule| rule.syscall.name == "prctl")
                .collect();
            assert_eq!(prctl_rules.len(), 2);
            assert!(prctl_rules.iter().all(|rule| !rule.conditions.is_empty()));

            assert_eq!(specs[1].action, FilterAction::Errno(ENOSYS));
            assert_eq!(specs[1].rules.len(), 1);
            assert_eq!(specs[1].rules[0].syscall.name, "clone3");

            assert_eq!(specs[2].action, FilterAction::Errno(EPERM));
            let indirect: Vec<&str> = specs[2]
                .rules
                .iter()
                .map(|rule| rule.syscall.name)
                .collect();
            for required in [
                "io_uring_setup",
                "io_uring_enter",
                "io_uring_register",
                "kexec_load",
                "kexec_file_load",
                "init_module",
                "finit_module",
                "delete_module",
            ] {
                assert!(
                    indirect.contains(&required),
                    "indirect filter missing {required}"
                );
            }
        }
    }

    /// The attestor mediates process-creating `clone` by masking on
    /// `CLONE_THREAD` (thread-only clone stays allowed); the helper denies all
    /// `clone` unconditionally.
    #[test]
    fn clone_rule_differs_by_kind() {
        let attestor = filter_specs(LockdownProfileKind::AttestorV1);
        let clone_rule = attestor[0]
            .rules
            .iter()
            .find(|rule| rule.syscall.name == "clone")
            .unwrap();
        assert_eq!(clone_rule.conditions.len(), 1);
        let condition = clone_rule.conditions[0];
        assert_eq!(condition.arg_index, 0);
        assert_eq!(condition.compare, ArgCompare::MaskedEq(CLONE_THREAD));
        assert_eq!(condition.value, 0);

        let helper = filter_specs(LockdownProfileKind::MeasureHelperV1);
        let helper_clone = helper[0]
            .rules
            .iter()
            .find(|rule| rule.syscall.name == "clone")
            .unwrap();
        assert!(
            helper_clone.conditions.is_empty(),
            "helper denies all clone"
        );
    }

    /// `fork`/`vfork` exist only on `x86_64`; the `aarch64` table omits them, and no
    /// syscall number is shared across the two architectures for a name that
    /// differs.
    #[test]
    fn fork_family_is_x86_64_only() {
        assert_eq!(FORK.number_for(LockdownArch::X86_64), Some(57));
        assert_eq!(FORK.number_for(LockdownArch::Aarch64), None);
        assert_eq!(VFORK.number_for(LockdownArch::Aarch64), None);
        assert_eq!(EXECVE.number_for(LockdownArch::Aarch64), Some(221));
    }

    /// The profile compiles for both architectures from day one (the review's
    /// arch-parameterized-compiler requirement), for both kinds. x86-64 gains
    /// the dedicated x32 guard program.
    #[cfg(target_os = "linux")]
    #[test]
    fn both_architectures_compile_for_both_kinds() {
        for kind in [
            LockdownProfileKind::AttestorV1,
            LockdownProfileKind::MeasureHelperV1,
        ] {
            let x86 = compile(kind, LockdownArch::X86_64).expect("x86_64 profile compiles");
            assert_eq!(x86.len(), 4, "x32 guard + kill + clone3 + indirect");
            let aarch64 = compile(kind, LockdownArch::Aarch64).expect("aarch64 profile compiles");
            assert_eq!(aarch64.len(), 3, "kill + clone3 + indirect");
            // Every program carries at least the arch-validation prologue plus
            // a body; none is empty (an empty program would refuse to install).
            assert!(
                x86.iter()
                    .chain(aarch64.iter())
                    .all(|program| program.len() > 3)
            );
        }
    }

    /// Assertions against the compiled BPF programs themselves (the review's
    /// compiled-program requirement): a tiny classic-BPF interpreter runs the
    /// installed filter stack over synthetic `seccomp_data` records exactly the
    /// way the kernel would, taking the most restrictive result across the
    /// stack.
    #[cfg(target_os = "linux")]
    mod compiled {
        use super::*;

        /// `SECCOMP_RET_ERRNO` base (`linux/seccomp.h`).
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

        /// Synthetic `seccomp_data`.
        struct SeccompData {
            nr: u32,
            arch: u32,
            args: [u64; 6],
        }

        impl SeccompData {
            fn on(arch: LockdownArch, nr: u32) -> Self {
                let audit = match arch {
                    LockdownArch::X86_64 => AUDIT_ARCH_X86_64,
                    LockdownArch::Aarch64 => AUDIT_ARCH_AARCH64,
                };
                Self {
                    nr,
                    arch: audit,
                    args: [0; 6],
                }
            }

            fn with_arg0(mut self, value: u64) -> Self {
                self.args[0] = value;
                self
            }

            fn with_arg1(mut self, value: u64) -> Self {
                self.args[1] = value;
                self
            }
        }

        /// Load one little-endian 32-bit word of `seccomp_data` (both target
        /// architectures are little-endian).
        fn word(data: &SeccompData, offset: u32) -> u32 {
            match offset {
                0 => data.nr,
                4 => data.arch,
                8 | 12 => 0, // instruction pointer, never referenced
                argument_area @ 16..64 if argument_area.is_multiple_of(4) => {
                    let byte = argument_area - 16;
                    let argument = data.args[(byte / 8) as usize];
                    if byte.is_multiple_of(8) {
                        u32::try_from(argument & 0xffff_ffff).expect("masked to 32 bits")
                    } else {
                        u32::try_from(argument >> 32).expect("shifted to 32 bits")
                    }
                }
                other => panic!("unexpected BPF load offset {other}"),
            }
        }

        /// Interpret one classic-BPF seccomp program over `data`.
        ///
        /// Covers exactly the opcode set `seccompiler` 0.5.0 and the x32 guard
        /// emit: absolute 32-bit loads, `AND` immediate, conditional/unconditional
        /// jumps, and immediate returns. Anything else fails the test loudly.
        fn interpret(program: &[seccompiler::sock_filter], data: &SeccompData) -> u32 {
            let mut accumulator: u32 = 0;
            let mut counter = 0_usize;
            loop {
                let instruction = &program[counter];
                let taken = usize::from(instruction.jt);
                let not_taken = usize::from(instruction.jf);
                match instruction.code {
                    // BPF_LD | BPF_W | BPF_ABS
                    0x20 => {
                        accumulator = word(data, instruction.k);
                        counter += 1;
                    }
                    // BPF_ALU | BPF_AND | BPF_K
                    0x54 => {
                        accumulator &= instruction.k;
                        counter += 1;
                    }
                    // BPF_JMP | BPF_JA
                    0x05 => {
                        counter += 1 + usize::try_from(instruction.k).expect("jump offset");
                    }
                    // BPF_JMP | {BPF_JEQ, BPF_JGT, BPF_JGE} | BPF_K
                    0x15 => {
                        counter += 1 + if accumulator == instruction.k {
                            taken
                        } else {
                            not_taken
                        };
                    }
                    0x25 => {
                        counter += 1 + if accumulator > instruction.k {
                            taken
                        } else {
                            not_taken
                        };
                    }
                    0x35 => {
                        counter += 1 + if accumulator >= instruction.k {
                            taken
                        } else {
                            not_taken
                        };
                    }
                    // BPF_RET | BPF_K
                    0x06 => return instruction.k,
                    other => panic!("unhandled BPF opcode {other:#06x}"),
                }
            }
        }

        /// Restrictiveness rank per the kernel's action precedence (lower wins).
        fn rank(action: u32) -> u8 {
            match action & 0xffff_0000 {
                0x8000_0000 => 0,       // KILL_PROCESS
                0x0000_0000 => 1,       // KILL_THREAD
                0x0003_0000 => 2,       // TRAP
                SECCOMP_RET_ERRNO => 3, // ERRNO
                0x7ff0_0000 => 4,       // TRACE
                0x7ffc_0000 => 5,       // LOG
                SECCOMP_RET_ALLOW => 6, // ALLOW
                other => panic!("unknown seccomp action {other:#010x}"),
            }
        }

        /// Run the whole installed stack: every filter executes and the most
        /// restrictive result wins, as in the kernel.
        fn run_stack(kind: LockdownProfileKind, arch: LockdownArch, data: &SeccompData) -> u32 {
            compile(kind, arch)
                .expect("profile compiles")
                .iter()
                .map(|program| interpret(program, data))
                .min_by_key(|action| rank(*action))
                .expect("at least one program")
        }

        fn number(syscall: SyscallNumbers, arch: LockdownArch) -> u32 {
            u32::try_from(syscall.number_for(arch).expect("syscall exists on arch"))
                .expect("syscall number fits u32")
        }

        const BOTH_KINDS: [LockdownProfileKind; 2] = [
            LockdownProfileKind::AttestorV1,
            LockdownProfileKind::MeasureHelperV1,
        ];
        const BOTH_ARCHES: [LockdownArch; 2] = [LockdownArch::X86_64, LockdownArch::Aarch64];

        /// A `seccomp_data` architecture mismatch is killed by every program in
        /// the stack, for both kinds and both compiled architectures.
        #[test]
        fn architecture_mismatch_is_killed() {
            for kind in BOTH_KINDS {
                for arch in BOTH_ARCHES {
                    let foreign = match arch {
                        LockdownArch::X86_64 => AUDIT_ARCH_AARCH64,
                        LockdownArch::Aarch64 => AUDIT_ARCH_X86_64,
                    };
                    // A benign syscall number under a foreign architecture.
                    let data = SeccompData {
                        nr: 0,
                        arch: foreign,
                        args: [0; 6],
                    };
                    for program in compile(kind, arch).expect("profile compiles") {
                        assert_eq!(
                            interpret(&program, &data),
                            SECCOMP_RET_KILL_PROCESS,
                            "every program must kill a foreign architecture"
                        );
                    }
                }
            }
        }

        /// On x86-64, any x32-ABI syscall number (`X32_SYSCALL_BIT` set) is
        /// killed even though it reports `AUDIT_ARCH_X86_64` — the guard the
        /// native-number denylist requires to not be a bypass.
        #[test]
        fn x32_syscall_numbers_are_killed_on_x86_64() {
            for kind in BOTH_KINDS {
                // x32 execve is 0x208 | bit; also probe the bit alone and a
                // masked native denylist number.
                for nr in [
                    X32_SYSCALL_BIT,
                    X32_SYSCALL_BIT | 0x208,
                    X32_SYSCALL_BIT | number(EXECVE, LockdownArch::X86_64),
                    X32_SYSCALL_BIT | 0x0fff_ffff,
                ] {
                    let data = SeccompData::on(LockdownArch::X86_64, nr);
                    assert_eq!(
                        run_stack(kind, LockdownArch::X86_64, &data),
                        SECCOMP_RET_KILL_PROCESS,
                        "x32 number {nr:#x} must be killed"
                    );
                }
                // The guard does not disturb native numbers: the largest
                // native number below the bit is allowed by default.
                let data = SeccompData::on(LockdownArch::X86_64, X32_SYSCALL_BIT - 1);
                assert_eq!(
                    run_stack(kind, LockdownArch::X86_64, &data),
                    SECCOMP_RET_ALLOW
                );
            }
        }

        /// Membership and actions of the compiled stack: SPEC denies kill,
        /// `clone3` returns `ENOSYS`, the indirect surface returns `EPERM`,
        /// and unlisted syscalls take the default `Allow` — for both kinds and
        /// both architectures.
        #[test]
        fn membership_actions_and_default_allow() {
            for kind in BOTH_KINDS {
                for arch in BOTH_ARCHES {
                    for killed in [
                        EXECVE,
                        EXECVEAT,
                        PTRACE,
                        PROCESS_VM_READV,
                        PROCESS_VM_WRITEV,
                        PIDFD_GETFD,
                    ] {
                        let data = SeccompData::on(arch, number(killed, arch));
                        assert_eq!(
                            run_stack(kind, arch, &data),
                            SECCOMP_RET_KILL_PROCESS,
                            "{} must be killed on {arch:?}",
                            killed.name
                        );
                    }
                    if arch == LockdownArch::X86_64 {
                        for killed in [FORK, VFORK] {
                            let data = SeccompData::on(arch, number(killed, arch));
                            assert_eq!(
                                run_stack(kind, arch, &data),
                                SECCOMP_RET_KILL_PROCESS,
                                "{} must be killed on x86_64",
                                killed.name
                            );
                        }
                    }
                    let clone3 = SeccompData::on(arch, number(CLONE3, arch));
                    assert_eq!(
                        run_stack(kind, arch, &clone3),
                        SECCOMP_RET_ERRNO | ENOSYS,
                        "clone3 returns ENOSYS so glibc/tokio fall back to clone"
                    );
                    for eperm in [
                        IO_URING_SETUP,
                        IO_URING_ENTER,
                        IO_URING_REGISTER,
                        KEXEC_LOAD,
                        KEXEC_FILE_LOAD,
                        INIT_MODULE,
                        FINIT_MODULE,
                        DELETE_MODULE,
                    ] {
                        let data = SeccompData::on(arch, number(eperm, arch));
                        assert_eq!(
                            run_stack(kind, arch, &data),
                            SECCOMP_RET_ERRNO | EPERM,
                            "{} must return EPERM on {arch:?}",
                            eperm.name
                        );
                    }
                    // Default Allow: read(2) is 0 on x86_64 and 63 on aarch64,
                    // and is in no filter.
                    let read_nr = match arch {
                        LockdownArch::X86_64 => 0,
                        LockdownArch::Aarch64 => 63,
                    };
                    let benign = SeccompData::on(arch, read_nr);
                    assert_eq!(run_stack(kind, arch, &benign), SECCOMP_RET_ALLOW);
                }
            }
        }

        /// The compiled `clone` rule: the attestor kills exactly the
        /// process-creating form (`flags & CLONE_THREAD == 0`) and allows
        /// thread creation; the helper kills every `clone`. The lockdown
        /// reversal `prctl` forms are killed while benign `prctl` stays
        /// allowed.
        #[test]
        fn clone_mask_and_prctl_reversal_behavior() {
            for arch in BOTH_ARCHES {
                let clone_nr = number(CLONE, arch);
                let thread_flags = CLONE_THREAD | 0x0000_0f00;
                let process_flags = 0x0000_0f00_u64;

                let thread = SeccompData::on(arch, clone_nr).with_arg0(thread_flags);
                assert_eq!(
                    run_stack(LockdownProfileKind::AttestorV1, arch, &thread),
                    SECCOMP_RET_ALLOW,
                    "attestor keeps thread-only clone"
                );
                let process = SeccompData::on(arch, clone_nr).with_arg0(process_flags);
                assert_eq!(
                    run_stack(LockdownProfileKind::AttestorV1, arch, &process),
                    SECCOMP_RET_KILL_PROCESS,
                    "attestor kills process-creating clone"
                );
                for flags in [thread_flags, process_flags, 0] {
                    let any = SeccompData::on(arch, clone_nr).with_arg0(flags);
                    assert_eq!(
                        run_stack(LockdownProfileKind::MeasureHelperV1, arch, &any),
                        SECCOMP_RET_KILL_PROCESS,
                        "helper kills every clone form"
                    );
                }

                let prctl_nr = number(PRCTL, arch);
                for kind in BOTH_KINDS {
                    let re_enable = SeccompData::on(arch, prctl_nr)
                        .with_arg0(PR_SET_DUMPABLE)
                        .with_arg1(PR_SET_DUMPABLE_ENABLE);
                    assert_eq!(
                        run_stack(kind, arch, &re_enable),
                        SECCOMP_RET_KILL_PROCESS,
                        "prctl(PR_SET_DUMPABLE, 1) is a killed reversal attempt"
                    );
                    let disable = SeccompData::on(arch, prctl_nr).with_arg0(PR_SET_DUMPABLE);
                    assert_eq!(
                        run_stack(kind, arch, &disable),
                        SECCOMP_RET_ALLOW,
                        "prctl(PR_SET_DUMPABLE, 0) stays allowed"
                    );
                    let ptracer = SeccompData::on(arch, prctl_nr)
                        .with_arg0(PR_SET_PTRACER)
                        .with_arg1(1);
                    assert_eq!(
                        run_stack(kind, arch, &ptracer),
                        SECCOMP_RET_KILL_PROCESS,
                        "prctl(PR_SET_PTRACER, ...) is a killed reversal attempt"
                    );
                    // PR_SET_NAME (15) is unrelated and allowed.
                    let benign = SeccompData::on(arch, prctl_nr).with_arg0(15);
                    assert_eq!(run_stack(kind, arch, &benign), SECCOMP_RET_ALLOW);
                }
            }
        }
    }
}
