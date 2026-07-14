#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly SCHEMA_VERSION="basil.compose.phase1.capacity-preflight/v1"
readonly TARGET_CONTAINERS=1000
readonly MIN_CPUS=8
readonly MIN_MEMORY_BYTES=$((32 * 1024 * 1024 * 1024))
readonly MIN_DISK_BYTES=$((40 * 1024 * 1024 * 1024))
readonly MIN_FREE_INODES=100000
readonly MIN_FD_SOFT=32768
readonly MIN_PID_MAX=65536
readonly MIN_NAMESPACE_LIMIT=4096
readonly PODMAN_LOCK_RESERVE=128
readonly MAX_RUNTIME_JSON_BYTES=$((1024 * 1024))
readonly COMMAND_TIMEOUT_SECONDS=20
# Readiness-only ladder-sizing estimates. These are conservative planning
# numbers, NOT measured per-container costs; the real numbers come from the later
# basil-9tj.4 serial ladder. `TASKS_PER_CONTAINER`/`FDS_PER_CONTAINER` bound the
# process and descriptor headroom a 1,000-container ladder is expected to draw;
# the nominal byte constants size a retained run's fixed evidence overhead.
readonly TASKS_PER_CONTAINER=4
readonly FDS_PER_CONTAINER=16
readonly LADDER_STEP_LATENCY_CEILING_MS=$((5 * 60 * 1000))
readonly MANIFEST_NOMINAL_BYTES=16384
readonly SNAPSHOT_NOMINAL_BYTES=12288
# The measurement scale ladder, kept as a bash array so the start event, the
# evidence-retention projection, and the derived thresholds all agree.
readonly SCALE_LADDER=(1 10 50 100 250 500 750 1000)

runtime_selection="${BASIL_CAPACITY_RUNTIME:-both}"
probe_command="${BASIL_COMPOSE_PHASE1_PROBE:-compose_phase1_probe}"
evidence_root="${BASIL_EVIDENCE_ROOT:-$PWD}"
run_id="${BASIL_EVIDENCE_RUN_ID:-capacity-preflight-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
lane_id="${BASIL_EVIDENCE_LANE_ID:-native-x86_64}"
seq=0
blockers='[]'
warnings='[]'

usage() {
    printf '%s\n' 'usage: capacity-preflight.sh [--runtime docker|podman|both] [--probe PATH] [--evidence-root PATH] [--run-id ID] [--lane-id ID]' >&2
}

while (($# > 0)); do
    case "$1" in
        --runtime)
            (($# >= 2)) || { usage; exit 2; }
            runtime_selection=$2
            shift 2
            ;;
        --probe)
            (($# >= 2)) || { usage; exit 2; }
            probe_command=$2
            shift 2
            ;;
        --evidence-root)
            (($# >= 2)) || { usage; exit 2; }
            evidence_root=$2
            shift 2
            ;;
        --run-id)
            (($# >= 2)) || { usage; exit 2; }
            run_id=$2
            shift 2
            ;;
        --lane-id)
            (($# >= 2)) || { usage; exit 2; }
            lane_id=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

case "$runtime_selection" in
    docker|podman|both) ;;
    *)
        printf 'invalid runtime selection: %s\n' "$runtime_selection" >&2
        exit 2
        ;;
esac

if ! command -v jq >/dev/null 2>&1; then
    printf '%s\n' 'capacity preflight requires jq for bounded JSONL output' >&2
    exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
    printf '%s\n' 'capacity preflight requires timeout' >&2
    exit 2
fi

bounded_id() {
    local value=$1
    printf '%s' "${value:0:128}"
}

run_id=$(bounded_id "$run_id")
lane_id=$(bounded_id "$lane_id")

emit_event() {
    local event=$1
    local status=$2
    local reason_code=$3
    local runtime=$4
    local data=$5
    seq=$((seq + 1))
    jq -cn \
        --arg schema_version "$SCHEMA_VERSION" \
        --arg run_id "$run_id" \
        --arg lane_id "$lane_id" \
        --argjson seq "$seq" \
        --arg event "$event" \
        --arg status "$status" \
        --arg reason_code "$reason_code" \
        --arg runtime "$runtime" \
        --argjson data "$data" \
        '{schema_version:$schema_version,run_id:$run_id,lane_id:$lane_id,seq:$seq,event:$event,status:$status,reason_code:$reason_code,runtime:(if $runtime == "" then null else $runtime end),data:$data}'
}

add_blocker() {
    local code=$1
    local scope=$2
    local detail=$3
    blockers=$(jq -cn \
        --argjson current "$blockers" \
        --arg code "$code" \
        --arg scope "$scope" \
        --arg detail "${detail:0:256}" \
        '$current + [{code:$code,scope:$scope,detail:$detail}]')
}

add_warning() {
    local code=$1
    local scope=$2
    local detail=$3
    warnings=$(jq -cn \
        --argjson current "$warnings" \
        --arg code "$code" \
        --arg scope "$scope" \
        --arg detail "${detail:0:256}" \
        '$current + [{code:$code,scope:$scope,detail:$detail}]')
}

read_integer_file() {
    local path=$1
    local value=''
    if [[ -r "$path" ]] && IFS= read -r value <"$path" && [[ "$value" =~ ^[0-9]+$ ]]; then
        printf '%s' "$value"
        return 0
    fi
    return 1
}

read_cgroup_leaf_value() {
    local name=$1
    local value=''
    if [[ -r "$cgroup_directory/$name" ]] && IFS= read -r value <"$cgroup_directory/$name"; then
        printf '%s' "$value"
        return 0
    fi
    return 1
}

read_cgroup_effective_limit() {
    local name=$1
    local value=''
    local minimum=''
    local found=false
    local directory=$cgroup_directory
    while [[ "$directory" == /sys/fs/cgroup* ]]; do
        if [[ -r "$directory/$name" ]] && IFS= read -r value <"$directory/$name"; then
            found=true
            if [[ "$value" =~ ^[0-9]+$ ]] && { [[ -z "$minimum" ]] || ((value < minimum)); }; then
                minimum=$value
            fi
        fi
        [[ "$directory" == /sys/fs/cgroup ]] && break
        directory=${directory%/*}
    done
    if [[ -n "$minimum" ]]; then
        printf '%s' "$minimum"
        return 0
    fi
    if [[ "$found" == true ]]; then
        printf '%s' max
        return 0
    fi
    return 1
}

filesystem_snapshot() {
    local path=$1
    local scope=$2
    if [[ ! -e "$path" ]]; then
        jq -cn --arg path "$path" --arg scope "$scope" '{scope:$scope,path:$path,available:false}'
        return 0
    fi

    local fs_type block_size blocks_available blocks_total inodes_available inodes_total
    fs_type=$(stat -f -c '%T' -- "$path" 2>/dev/null || true)
    block_size=$(stat -f -c '%S' -- "$path" 2>/dev/null || true)
    blocks_available=$(stat -f -c '%a' -- "$path" 2>/dev/null || true)
    blocks_total=$(stat -f -c '%b' -- "$path" 2>/dev/null || true)
    inodes_available=$(stat -f -c '%d' -- "$path" 2>/dev/null || true)
    inodes_total=$(stat -f -c '%c' -- "$path" 2>/dev/null || true)
    if [[ ! "$block_size" =~ ^[0-9]+$ || ! "$blocks_available" =~ ^[0-9]+$ || ! "$blocks_total" =~ ^[0-9]+$ || ! "$inodes_available" =~ ^[0-9]+$ || ! "$inodes_total" =~ ^[0-9]+$ ]]; then
        jq -cn --arg path "$path" --arg scope "$scope" '{scope:$scope,path:$path,available:false}'
        return 0
    fi

    local bytes_available=$((block_size * blocks_available))
    local bytes_total=$((block_size * blocks_total))
    jq -cn \
        --arg path "$path" \
        --arg scope "$scope" \
        --arg fs_type "${fs_type:0:64}" \
        --argjson bytes_available "$bytes_available" \
        --argjson bytes_total "$bytes_total" \
        --argjson inodes_available "$inodes_available" \
        --argjson inodes_total "$inodes_total" \
        '{scope:$scope,path:$path,available:true,fs_type:$fs_type,bytes_available:$bytes_available,bytes_total:$bytes_total,inodes_available:$inodes_available,inodes_total:$inodes_total}'
}

check_filesystem_headroom() {
    local snapshot=$1
    local scope=$2
    local available bytes_available inodes_available
    available=$(jq -r '.available' <<<"$snapshot")
    if [[ "$available" != true ]]; then
        add_blocker "DISK_BASELINE_UNKNOWN" "$scope" "filesystem baseline could not be read"
        return
    fi
    bytes_available=$(jq -r '.bytes_available' <<<"$snapshot")
    inodes_available=$(jq -r '.inodes_available' <<<"$snapshot")
    if ((bytes_available < MIN_DISK_BYTES)); then
        add_blocker "DISK_HEADROOM_INSUFFICIENT" "$scope" "available bytes are below the readiness-only reserve"
    fi
    if ((inodes_available < MIN_FREE_INODES)); then
        add_blocker "INODE_HEADROOM_INSUFFICIENT" "$scope" "available inodes are below the readiness-only reserve"
    fi
}

resolve_probe() {
    if [[ "$probe_command" == */* ]]; then
        [[ -x "$probe_command" ]] || return 1
        printf '%s' "$probe_command"
        return 0
    fi
    command -v "$probe_command"
}

scale_ladder_json=$(printf '%s\n' "${SCALE_LADDER[@]}" | jq -cs '.')

emit_event "start" "INCOMPLETE" "PREFLIGHT_STARTED" "" "$(jq -cn \
    --arg purpose 'environment readiness only; does not claim a 1,000-container ceiling' \
    --arg selection "$runtime_selection" \
    --argjson target "$TARGET_CONTAINERS" \
    --argjson ladder "$scale_ladder_json" \
    '{purpose:$purpose,runtime_selection:$selection,target_containers:$target,creates_containers:false,final_ceiling_evidence:false,scale_ladder:$ladder}')"

probe_path=''
probe_metadata='null'
probe_host='null'
if probe_path=$(resolve_probe 2>/dev/null); then
    if probe_metadata_raw=$(timeout "${COMMAND_TIMEOUT_SECONDS}s" "$probe_path" capacity-metadata 2>/dev/null) \
        && [[ ${#probe_metadata_raw} -le MAX_RUNTIME_JSON_BYTES ]] \
        && jq -e '.ok == true and .kind == "capacity-metadata"' >/dev/null 2>&1 <<<"$probe_metadata_raw"; then
        probe_metadata=$probe_metadata_raw
    else
        add_warning "PROBE_METADATA_UNAVAILABLE" "probe" "capacity metadata command failed or returned invalid output"
    fi
    if probe_host_raw=$(timeout "${COMMAND_TIMEOUT_SECONDS}s" "$probe_path" host-process-snapshot 2>/dev/null) \
        && [[ ${#probe_host_raw} -le MAX_RUNTIME_JSON_BYTES ]] \
        && jq -e '.ok == true and .kind == "host-process-snapshot"' >/dev/null 2>&1 <<<"$probe_host_raw"; then
        probe_host=$probe_host_raw
    else
        add_warning "PROBE_HOST_SNAPSHOT_UNAVAILABLE" "probe" "host/process snapshot command failed or returned invalid output"
    fi
else
    # The probe is a host-side supplement (SO_PEERCRED pinning, projection
    # sizing). It is dynamically linked against the devshell glibc and is not
    # expected to execute inside a distro guest, so its absence is a warning, not
    # a readiness blocker: the script reads the same facts directly from /proc.
    add_warning "PROBE_NOT_FOUND" "probe" "compose_phase1_probe is not executable on PATH or at --probe; continuing with direct /proc facts"
fi

architecture=$(uname -m)
logical_cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
[[ "$logical_cpus" =~ ^[0-9]+$ ]] || logical_cpus=0
if [[ "$architecture" != x86_64 && "$architecture" != amd64 ]]; then
    add_blocker "ARCHITECTURE_UNSUPPORTED" "host" "native x86_64 capacity lane required"
fi
if ((logical_cpus < MIN_CPUS)); then
    add_blocker "CPU_HEADROOM_INSUFFICIENT" "host" "logical CPU count is below the readiness-only threshold"
fi

mem_total_kib=0
mem_available_kib=0
swap_total_kib=0
swap_free_kib=0
while read -r key value _unit; do
    case "$key" in
        MemTotal:) [[ "$value" =~ ^[0-9]+$ ]] && mem_total_kib=$value ;;
        MemAvailable:) [[ "$value" =~ ^[0-9]+$ ]] && mem_available_kib=$value ;;
        SwapTotal:) [[ "$value" =~ ^[0-9]+$ ]] && swap_total_kib=$value ;;
        SwapFree:) [[ "$value" =~ ^[0-9]+$ ]] && swap_free_kib=$value ;;
    esac
done </proc/meminfo
mem_total_bytes=$((mem_total_kib * 1024))
mem_available_bytes=$((mem_available_kib * 1024))
swap_total_bytes=$((swap_total_kib * 1024))
swap_free_bytes=$((swap_free_kib * 1024))
if ((mem_available_bytes < MIN_MEMORY_BYTES)); then
    add_blocker "MEMORY_HEADROOM_INSUFFICIENT" "host" "available memory is below the readiness-only reserve"
fi

cgroup_fs=$(stat -fc '%T' /sys/fs/cgroup 2>/dev/null || true)
cgroup_v2=false
[[ "$cgroup_fs" == cgroup2fs ]] && cgroup_v2=true
if [[ "$cgroup_v2" != true ]]; then
    add_blocker "CGROUP_V2_REQUIRED" "host" "the capacity lane requires cgroup v2"
fi

cgroup_relative='/'
while IFS=: read -r hierarchy controllers path; do
    if [[ "$hierarchy" == 0 && -z "$controllers" ]]; then
        cgroup_relative=$path
        break
    fi
done </proc/self/cgroup
cgroup_directory="/sys/fs/cgroup${cgroup_relative}"
[[ -d "$cgroup_directory" ]] || cgroup_directory=/sys/fs/cgroup
pids_current=$(read_cgroup_leaf_value pids.current || true)
pids_max=$(read_cgroup_effective_limit pids.max || true)
memory_current=$(read_cgroup_leaf_value memory.current || true)
memory_max=$(read_cgroup_effective_limit memory.max || true)
memory_high=$(read_cgroup_effective_limit memory.high || true)
cpu_max=$(read_cgroup_leaf_value cpu.max || true)

fd_soft=$(ulimit -Sn)
fd_hard=$(ulimit -Hn)
user_process_soft=$(ulimit -Su)
user_process_hard=$(ulimit -Hu)
file_max=$(read_integer_file /proc/sys/fs/file-max || true)
file_nr=''
if [[ -r /proc/sys/fs/file-nr ]]; then
    IFS=$'\t ' read -r file_nr _allocated_unused _maximum </proc/sys/fs/file-nr || true
fi
if [[ ! "$fd_soft" =~ ^[0-9]+$ ]]; then
    add_blocker "FD_LIMIT_UNKNOWN" "host" "soft file-descriptor limit is not numeric"
elif ((fd_soft < MIN_FD_SOFT)); then
    add_blocker "FD_HEADROOM_INSUFFICIENT" "host" "soft file-descriptor limit is below the readiness-only threshold"
fi

pid_max=$(read_integer_file /proc/sys/kernel/pid_max || true)
threads_max=$(read_integer_file /proc/sys/kernel/threads-max || true)
if [[ ! "$pid_max" =~ ^[0-9]+$ ]]; then
    add_blocker "PID_LIMIT_UNKNOWN" "host" "kernel pid_max is unavailable"
elif ((pid_max < MIN_PID_MAX)); then
    add_blocker "PID_HEADROOM_INSUFFICIENT" "host" "kernel pid_max is below the readiness-only threshold"
fi
if [[ "$user_process_soft" =~ ^[0-9]+$ ]]; then
    if ((user_process_soft < TARGET_CONTAINERS * 4)); then
        add_blocker "USER_PROCESS_HEADROOM_INSUFFICIENT" "host" "per-user process limit is below four tasks per target container"
    fi
elif [[ "$user_process_soft" != unlimited ]]; then
    add_blocker "USER_PROCESS_LIMIT_UNKNOWN" "host" "per-user process limit is neither numeric nor unlimited"
fi
if [[ "$pids_max" != max && "$pids_max" =~ ^[0-9]+$ && "$pids_current" =~ ^[0-9]+$ ]]; then
    pids_headroom=$((pids_max - pids_current))
    if ((pids_headroom < TARGET_CONTAINERS * 4)); then
        add_blocker "CGROUP_PID_HEADROOM_INSUFFICIENT" "host" "effective cgroup PID headroom is below four tasks per target container"
    fi
fi

namespace_limits='{}'
for namespace in user pid mnt net ipc uts cgroup; do
    namespace_value=$(read_integer_file "/proc/sys/user/max_${namespace}_namespaces" || true)
    if [[ ! "$namespace_value" =~ ^[0-9]+$ ]]; then
        add_blocker "NAMESPACE_LIMIT_UNKNOWN" "host" "max_${namespace}_namespaces is unavailable"
        namespace_value=0
    elif ((namespace_value < MIN_NAMESPACE_LIMIT)); then
        add_blocker "NAMESPACE_HEADROOM_INSUFFICIENT" "host" "max_${namespace}_namespaces is below the readiness-only threshold"
    fi
    namespace_limits=$(jq -cn --argjson current "$namespace_limits" --arg key "$namespace" --argjson value "$namespace_value" '$current + {($key):$value}')
done

lsm_list=''
[[ -r /sys/kernel/security/lsm ]] && IFS= read -r lsm_list </sys/kernel/security/lsm || true
selinux_enforcing='unknown'
[[ -r /sys/fs/selinux/enforce ]] && IFS= read -r selinux_enforcing </sys/fs/selinux/enforce || true
apparmor_enabled='unknown'
[[ -r /sys/module/apparmor/parameters/enabled ]] && IFS= read -r apparmor_enabled </sys/module/apparmor/parameters/enabled || true

host_disk=$(filesystem_snapshot "$evidence_root" evidence)
check_filesystem_headroom "$host_disk" evidence

host_data=$(jq -cn \
    --arg architecture "$architecture" \
    --arg cgroup_fs "$cgroup_fs" \
    --arg cgroup_path "$cgroup_relative" \
    --arg pids_current "$pids_current" \
    --arg pids_max "$pids_max" \
    --arg memory_current "$memory_current" \
    --arg memory_max "$memory_max" \
    --arg memory_high "$memory_high" \
    --arg cpu_max "$cpu_max" \
    --arg fd_soft "$fd_soft" \
    --arg fd_hard "$fd_hard" \
    --arg file_max "$file_max" \
    --arg file_nr "$file_nr" \
    --arg pid_max "$pid_max" \
    --arg threads_max "$threads_max" \
    --arg user_process_soft "$user_process_soft" \
    --arg user_process_hard "$user_process_hard" \
    --arg lsm_list "${lsm_list:0:256}" \
    --arg selinux_enforcing "$selinux_enforcing" \
    --arg apparmor_enabled "$apparmor_enabled" \
    --argjson logical_cpus "$logical_cpus" \
    --argjson mem_total_bytes "$mem_total_bytes" \
    --argjson mem_available_bytes "$mem_available_bytes" \
    --argjson swap_total_bytes "$swap_total_bytes" \
    --argjson swap_free_bytes "$swap_free_bytes" \
    --argjson cgroup_v2 "$cgroup_v2" \
    --argjson namespace_limits "$namespace_limits" \
    --argjson evidence_filesystem "$host_disk" \
    --argjson probe_metadata "$probe_metadata" \
    --argjson probe_host "$probe_host" \
    '{architecture:$architecture,logical_cpus:$logical_cpus,memory:{total_bytes:$mem_total_bytes,available_bytes:$mem_available_bytes,swap_total_bytes:$swap_total_bytes,swap_free_bytes:$swap_free_bytes},cgroup:{version_2:$cgroup_v2,filesystem:$cgroup_fs,self_path:$cgroup_path,pids_current:$pids_current,pids_max:$pids_max,memory_current:$memory_current,memory_max:$memory_max,memory_high:$memory_high,cpu_max:$cpu_max},file_descriptors:{soft:$fd_soft,hard:$fd_hard,system_file_max:$file_max,system_allocated:$file_nr},processes:{pid_max:$pid_max,threads_max:$threads_max,user_soft:$user_process_soft,user_hard:$user_process_hard},namespace_limits:$namespace_limits,lsm:{list:$lsm_list,selinux_enforcing:$selinux_enforcing,apparmor_enabled:$apparmor_enabled},evidence_filesystem:$evidence_filesystem,probe:{capacity_metadata:$probe_metadata,host_process_snapshot:$probe_host}}')
emit_event "host_snapshot" "PASS" "HOST_BASELINE_RECORDED" "" "$host_data"

check_docker() {
    local runtime=docker
    if ! command -v docker >/dev/null 2>&1; then
        add_blocker "RUNTIME_NOT_FOUND" "$runtime" "docker executable not found"
        emit_event "runtime_snapshot" "UNSUPPORTED" "RUNTIME_NOT_FOUND" "$runtime" '{"available":false}'
        return
    fi
    local raw_info
    if ! raw_info=$(timeout "${COMMAND_TIMEOUT_SECONDS}s" docker info --format '{{json .}}' 2>/dev/null); then
        add_blocker "RUNTIME_INFO_UNAVAILABLE" "$runtime" "docker daemon info unavailable"
        emit_event "runtime_snapshot" "INFRA_ERROR" "RUNTIME_INFO_UNAVAILABLE" "$runtime" '{"available":false}'
        return
    fi
    if ((${#raw_info} > MAX_RUNTIME_JSON_BYTES)) || ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$raw_info"; then
        add_blocker "RUNTIME_INFO_INVALID" "$runtime" "docker info exceeded bounds or was invalid JSON"
        emit_event "runtime_snapshot" "INFRA_ERROR" "RUNTIME_INFO_INVALID" "$runtime" '{"available":false}'
        return
    fi
    local projected root_path disk userns rootless cgroup_version
    projected=$(jq -c '{server_version:.ServerVersion,storage_driver:.Driver,cgroup_driver:.CgroupDriver,cgroup_version:.CgroupVersion,root_dir:.DockerRootDir,cpus:.NCPU,memory_bytes:.MemTotal,containers:{total:.Containers,running:.ContainersRunning,paused:.ContainersPaused,stopped:.ContainersStopped},images:.Images,security_options:(.SecurityOptions // [])}' <<<"$raw_info")
    root_path=$(jq -r '.root_dir // empty' <<<"$projected")
    cgroup_version=$(jq -r '.cgroup_version // empty' <<<"$projected")
    userns=$(jq -r '[.security_options[]? | select(startswith("name=userns"))] | length' <<<"$projected")
    rootless=$(jq -r '[.security_options[]? | select(startswith("name=rootless"))] | length' <<<"$projected")
    if [[ "$cgroup_version" != 2 && "$cgroup_version" != v2 ]]; then
        add_blocker "CGROUP_V2_REQUIRED" "$runtime" "docker does not report cgroup v2"
    fi
    if ((rootless > 0)); then
        add_blocker "DOCKER_NOT_ROOTFUL" "$runtime" "Compose 1.0 Docker lane requires rootful mode"
    fi
    if ((userns > 0)); then
        add_blocker "DOCKER_USERNS_REMAP_ENABLED" "$runtime" "Compose 1.0 excludes Docker userns-remap"
    fi
    if [[ -z "$root_path" || ! -e "$root_path" ]]; then
        add_blocker "DISK_BASELINE_UNKNOWN" "$runtime" "Docker root directory is unavailable to the preflight user"
        disk='{"available":false}'
    else
        disk=$(filesystem_snapshot "$root_path" docker-storage)
        check_filesystem_headroom "$disk" "$runtime"
    fi
    emit_event "runtime_snapshot" "PASS" "RUNTIME_BASELINE_RECORDED" "$runtime" "$(jq -cn --argjson info "$projected" --argjson filesystem "$disk" '{available:true,mode:"rootful",info:$info,filesystem:$filesystem}')"
}

check_podman() {
    local runtime=podman
    if ! command -v podman >/dev/null 2>&1; then
        add_blocker "RUNTIME_NOT_FOUND" "$runtime" "podman executable not found"
        emit_event "runtime_snapshot" "UNSUPPORTED" "RUNTIME_NOT_FOUND" "$runtime" '{"available":false}'
        return
    fi
    local raw_info
    if ! raw_info=$(timeout "${COMMAND_TIMEOUT_SECONDS}s" podman info --format json 2>/dev/null); then
        add_blocker "RUNTIME_INFO_UNAVAILABLE" "$runtime" "podman info unavailable"
        emit_event "runtime_snapshot" "INFRA_ERROR" "RUNTIME_INFO_UNAVAILABLE" "$runtime" '{"available":false}'
        return
    fi
    if ((${#raw_info} > MAX_RUNTIME_JSON_BYTES)) || ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$raw_info"; then
        add_blocker "RUNTIME_INFO_INVALID" "$runtime" "podman info exceeded bounds or was invalid JSON"
        emit_event "runtime_snapshot" "INFRA_ERROR" "RUNTIME_INFO_INVALID" "$runtime" '{"available":false}'
        return
    fi
    local projected root_path disk rootless cgroup_version free_locks required_locks
    projected=$(jq -c '{version:.version.Version,host:{architecture:.host.arch,cpus:.host.cpus,memory_free_bytes:.host.memFree,memory_total_bytes:.host.memTotal,cgroup_version:.host.cgroupVersion,cgroup_manager:.host.cgroupManager,free_locks:.host.freeLocks,rootless:.host.security.rootless,selinux_enabled:.host.security.selinuxEnabled,apparmor_enabled:.host.security.apparmorEnabled,seccomp_enabled:.host.security.seccompEnabled,oci_runtime:.host.ociRuntime.name},store:{graph_root:.store.graphRoot,run_root:.store.runRoot,driver:.store.graphDriverName},containers:.store.containerStore.number,images:.store.imageStore.number}' <<<"$raw_info")
    root_path=$(jq -r '.store.graph_root // empty' <<<"$projected")
    rootless=$(jq -r '.host.rootless // false' <<<"$projected")
    cgroup_version=$(jq -r '.host.cgroup_version // empty' <<<"$projected")
    free_locks=$(jq -r '.host.free_locks // empty' <<<"$projected")
    required_locks=$((TARGET_CONTAINERS + PODMAN_LOCK_RESERVE))
    if [[ "$rootless" != true ]]; then
        add_blocker "PODMAN_NOT_ROOTLESS" "$runtime" "Compose 1.0 Podman lane requires rootless mode"
    fi
    if [[ "$cgroup_version" != v2 && "$cgroup_version" != 2 ]]; then
        add_blocker "CGROUP_V2_REQUIRED" "$runtime" "Podman does not report cgroup v2"
    fi
    if [[ ! "$free_locks" =~ ^[0-9]+$ ]]; then
        add_blocker "PODMAN_FREE_LOCKS_UNKNOWN" "$runtime" "Podman host.freeLocks is absent or non-numeric"
        free_locks=0
    elif ((free_locks < required_locks)); then
        add_blocker "PODMAN_FREE_LOCKS_INSUFFICIENT" "$runtime" "Podman freeLocks is below target containers plus readiness reserve"
    fi
    if [[ -z "$root_path" || ! -e "$root_path" ]]; then
        add_blocker "DISK_BASELINE_UNKNOWN" "$runtime" "Podman graph root is unavailable"
        disk='{"available":false}'
    else
        disk=$(filesystem_snapshot "$root_path" podman-storage)
        check_filesystem_headroom "$disk" "$runtime"
    fi
    emit_event "runtime_snapshot" "PASS" "RUNTIME_BASELINE_RECORDED" "$runtime" "$(jq -cn --argjson info "$projected" --argjson filesystem "$disk" --argjson required_locks "$required_locks" --argjson free_locks "$free_locks" '{available:true,mode:"rootless",info:$info,filesystem:$filesystem,lock_readiness:{free_locks:$free_locks,required_target_plus_reserve:$required_locks,final_ceiling_evidence:false}}')"
}

case "$runtime_selection" in
    docker) check_docker ;;
    podman) check_podman ;;
    both)
        check_docker
        check_podman
        ;;
esac

# ---- Evidence-retention sizing (readiness estimate; not measured) -----------
# Model a retained run's sanitized-evidence bytes as a fixed overhead plus one
# bounded per-container terminal event, then project the whole scale ladder and
# check it fits under the evidence filesystem with the readiness disk reserve
# intact. These are conservative planning numbers, not measured evidence sizes.
representative_container_event=$(jq -cn \
    --arg schema "$SCHEMA_VERSION" --arg run_id "$run_id" --arg lane_id "$lane_id" \
    '{schema_version:$schema,run_id:$run_id,lane_id:$lane_id,seq:1000,event:"container_probe",status:"PASS",reason_code:"CONTAINER_PEERCRED_BOUND",runtime:"podman",test_id:"capacity.container.01000",data:{index:1000,pid:1234567,start_time_ticks:123456789,cgroup:"/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-0000000000000000000000000000000000000000000000000000000000000000.scope",peer:{pid:1234567,uid:1000,gid:1000},create_ms:42,inspect_ms:7,remove_ms:11}}')
per_container_event_bytes=$((${#representative_container_event} + 1))
representative_run_terminal=$(jq -cn \
    --arg schema "$SCHEMA_VERSION" --arg run_id "$run_id" --arg lane_id "$lane_id" \
    '{schema_version:$schema,run_id:$run_id,lane_id:$lane_id,seq:1,event:"run.start",status:"INCOMPLETE",reason_code:"RUN_PREPARED",test_id:"",data:{}}')
fixed_overhead_bytes=$(((${#representative_run_terminal} + 1) * 2 + MANIFEST_NOMINAL_BYTES + SNAPSHOT_NOMINAL_BYTES))

ladder_sum=0
ladder_steps=${#SCALE_LADDER[@]}
for _n in "${SCALE_LADDER[@]}"; do ladder_sum=$((ladder_sum + _n)); done
bytes_at_target_run=$((fixed_overhead_bytes + TARGET_CONTAINERS * per_container_event_bytes))
total_ladder_bytes=$((ladder_steps * fixed_overhead_bytes + ladder_sum * per_container_event_bytes))

evidence_available_bytes=0
evidence_total_bytes=0
if [[ $(jq -r '.available' <<<"$host_disk") == true ]]; then
    evidence_available_bytes=$(jq -r '.bytes_available' <<<"$host_disk")
    evidence_total_bytes=$(jq -r '.bytes_total' <<<"$host_disk")
fi
evidence_fits=true
evidence_headroom_after_ladder=0
if ((evidence_available_bytes > 0)); then
    evidence_headroom_after_ladder=$((evidence_available_bytes - total_ladder_bytes))
    if ((evidence_headroom_after_ladder < MIN_DISK_BYTES)); then
        evidence_fits=false
        add_blocker "EVIDENCE_RETENTION_INSUFFICIENT" "evidence" "projected ladder evidence would leave the evidence filesystem below the readiness disk reserve"
    fi
else
    add_warning "EVIDENCE_SIZING_UNKNOWN" "evidence" "evidence filesystem headroom could not be read; ladder retention not sized"
fi

evidence_projection=$(jq -cn \
    --argjson per_container "$per_container_event_bytes" \
    --argjson fixed "$fixed_overhead_bytes" \
    --argjson steps "$ladder_steps" \
    --argjson ladder "$scale_ladder_json" \
    --argjson at_target "$bytes_at_target_run" \
    --argjson total "$total_ladder_bytes" \
    --argjson available "$evidence_available_bytes" \
    --argjson fs_total "$evidence_total_bytes" \
    --argjson headroom "$evidence_headroom_after_ladder" \
    --argjson reserve "$MIN_DISK_BYTES" \
    --argjson fits "$evidence_fits" \
    '{model:"readiness estimate; per-run bytes = fixed overhead + containers * per-container terminal; NOT a measured evidence size",per_container_event_bytes:$per_container,fixed_overhead_bytes_per_run:$fixed,scale_ladder:$ladder,ladder_steps:$steps,bytes_at_target_run:$at_target,total_ladder_bytes:$total,evidence_bytes_available:$available,evidence_bytes_total:$fs_total,disk_reserve_bytes:$reserve,headroom_after_ladder_bytes:$headroom,retain_all_steps:true,fits:$fits}')

# ---- Safe scale-ladder stop conditions derived from measured facts ----------
# Concrete floors/ceilings at which a live 1,000-container ladder must abort.
memory_floor_bytes=$((mem_total_bytes / 10))
((memory_floor_bytes < 4 * 1024 * 1024 * 1024)) && memory_floor_bytes=$((4 * 1024 * 1024 * 1024))
memory_headroom_now=$((mem_available_bytes - memory_floor_bytes))

disk_floor_bytes=$MIN_DISK_BYTES
((evidence_total_bytes / 20 > disk_floor_bytes)) && disk_floor_bytes=$((evidence_total_bytes / 20))
disk_headroom_now=$((evidence_available_bytes - disk_floor_bytes))

fd_required=$((TARGET_CONTAINERS * FDS_PER_CONTAINER))
fd_process_headroom=0
[[ "$fd_soft" =~ ^[0-9]+$ ]] && fd_process_headroom=$((fd_soft - fd_required))

pid_required=$((TARGET_CONTAINERS * TASKS_PER_CONTAINER))
pid_headroom=0
if [[ "$pid_max" =~ ^[0-9]+$ ]]; then
    if [[ "$pids_current" =~ ^[0-9]+$ ]]; then
        pid_headroom=$((pid_max - pids_current - pid_required))
    else
        pid_headroom=$((pid_max - pid_required))
    fi
fi
if [[ "$pids_max" =~ ^[0-9]+$ && "$pids_current" =~ ^[0-9]+$ ]]; then
    cgroup_pid_headroom_json=$((pids_max - pids_current - pid_required))
else
    cgroup_pid_headroom_json='"unbounded"'
fi

derived_stop_thresholds=$(jq -cn \
    --arg classification "derived from measured host facts; abort the serial ladder when a live reading crosses these" \
    --argjson mem_floor "$memory_floor_bytes" \
    --argjson mem_headroom "$memory_headroom_now" \
    --argjson disk_floor "$disk_floor_bytes" \
    --argjson disk_headroom "$disk_headroom_now" \
    --argjson inode_floor "$MIN_FREE_INODES" \
    --argjson fds_per_container "$FDS_PER_CONTAINER" \
    --argjson fd_required "$fd_required" \
    --argjson fd_headroom "$fd_process_headroom" \
    --argjson tasks_per_container "$TASKS_PER_CONTAINER" \
    --argjson pid_required "$pid_required" \
    --argjson pid_headroom "$pid_headroom" \
    --argjson cgroup_pid_headroom "$cgroup_pid_headroom_json" \
    --argjson latency_ceiling_ms "$LADDER_STEP_LATENCY_CEILING_MS" \
    --argjson evidence_reserve "$MIN_DISK_BYTES" \
    '{classification:$classification,
      memory_floor_bytes:{stop_below:$mem_floor,current_headroom_bytes:$mem_headroom,basis:"max(4 GiB, 10% of MemTotal)",source:"measured"},
      disk_floor_bytes:{stop_below:$disk_floor,current_headroom_bytes:$disk_headroom,basis:"max(readiness disk reserve, 5% of evidence filesystem)",source:"measured"},
      inode_floor:{stop_below:$inode_floor,basis:"readiness-only inode reserve",source:"measured"},
      fd_soft_headroom:{containers_reserve:$fd_required,per_container_estimate:$fds_per_container,current_process_headroom:$fd_headroom,basis:"soft nofile minus containers times per-container estimate",source:"measured+estimate"},
      pid_headroom:{containers_reserve:$pid_required,per_container_estimate:$tasks_per_container,kernel_pid_headroom:$pid_headroom,effective_cgroup_pid_headroom:$cgroup_pid_headroom,basis:"pid_max and cgroup pids.max minus current minus containers times tasks",source:"measured+estimate"},
      per_step_latency_ceiling_ms:{stop_above:$latency_ceiling_ms,basis:"runbook stop rule; per-step wall-clock ceiling",source:"runbook-constant",measured:false},
      evidence_reserve_bytes:{keep_free:$evidence_reserve,basis:"leave the evidence filesystem above the readiness disk reserve after the ladder",source:"measured"}}')

projection_status=PASS
projection_reason=LADDER_CAPACITY_PROJECTED
if [[ $evidence_fits != true ]]; then
    projection_status=INCOMPLETE
    projection_reason=EVIDENCE_RETENTION_INSUFFICIENT
fi
emit_event "capacity_projection" "$projection_status" "$projection_reason" "" "$(jq -cn \
    --argjson evidence_projection "$evidence_projection" \
    --argjson derived_stop_thresholds "$derived_stop_thresholds" \
    '{evidence_projection:$evidence_projection,derived_stop_thresholds:$derived_stop_thresholds}')"

thresholds=$(jq -cn \
    --argjson min_cpus "$MIN_CPUS" \
    --argjson min_memory_bytes "$MIN_MEMORY_BYTES" \
    --argjson min_disk_bytes "$MIN_DISK_BYTES" \
    --argjson min_free_inodes "$MIN_FREE_INODES" \
    --argjson min_fd_soft "$MIN_FD_SOFT" \
    --argjson min_pid_max "$MIN_PID_MAX" \
    --argjson min_namespace_limit "$MIN_NAMESPACE_LIMIT" \
    --argjson podman_lock_reserve "$PODMAN_LOCK_RESERVE" \
    '{classification:"conservative readiness-only thresholds; not measured product ceilings",min_cpus:$min_cpus,min_memory_bytes:$min_memory_bytes,min_disk_bytes_per_checked_filesystem:$min_disk_bytes,min_free_inodes:$min_free_inodes,min_fd_soft:$min_fd_soft,min_pid_max:$min_pid_max,min_each_namespace_limit:$min_namespace_limit,podman_lock_reserve:$podman_lock_reserve}')
stop_conditions=$(jq -cn '[
    {code:"RUNTIME_ERRORS",stop_when:"any create/start/inspect/remove operation fails during the later ladder"},
    {code:"MEMORY_PRESSURE",stop_when:"available memory or effective cgroup headroom crosses the runbook threshold"},
    {code:"DISK_OR_INODE_PRESSURE",stop_when:"runtime/evidence storage reserve crosses the runbook threshold"},
    {code:"FD_PRESSURE",stop_when:"process or system descriptor use crosses the runbook threshold"},
    {code:"PID_OR_CGROUP_PRESSURE",stop_when:"PID or effective cgroup headroom crosses the runbook threshold"},
    {code:"LATENCY_REGRESSION",stop_when:"bounded operation deadlines or runbook latency stop rules are exceeded"},
    {code:"EVIDENCE_RETENTION_LIMIT",stop_when:"bounded evidence projection or retention cannot complete without truncating required facts"}
]')

blocker_count=$(jq 'length' <<<"$blockers")
if ((blocker_count == 0)); then
    ready=true
    final_status=PASS
    final_reason=READY_FOR_SCALE_LADDER
    exit_status=0
else
    ready=false
    final_status=INCOMPLETE
    final_reason=PREFLIGHT_BLOCKED
    exit_status=1
fi

summary=$(jq -cn \
    --argjson ready "$ready" \
    --argjson target "$TARGET_CONTAINERS" \
    --argjson blockers "$blockers" \
    --argjson warnings "$warnings" \
    --argjson thresholds "$thresholds" \
    --argjson stop_conditions "$stop_conditions" \
    --argjson evidence_projection "$evidence_projection" \
    --argjson derived_stop_thresholds "$derived_stop_thresholds" \
    '{ready:$ready,target_containers:$target,creates_containers:false,final_ceiling_evidence:false,thresholds:$thresholds,block_reasons:$blockers,warnings:$warnings,evidence_projection:$evidence_projection,derived_stop_thresholds:$derived_stop_thresholds,scale_ladder_stop_conditions:$stop_conditions,remaining_evidence:["run this preflight in the rootful-Docker AppArmor guest","run this preflight in the rootless-Podman SELinux guest","execute the later serial scale ladder before claiming any numeric ceiling"]}')
emit_event "end" "$final_status" "$final_reason" "" "$summary"
exit "$exit_status"
