#![no_std]
#![no_main]
#![allow(unsafe_op_in_unsafe_fn)]
//use aya_log_ebpf::info;
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]
mod vmlinux;

use crate::vmlinux::file;
const _: () = assert!(core::mem::offset_of!(vmlinux::file, __bindgen_anon_1) == 64);

use aya_ebpf::maps::{HashMap, PerCpuArray};

use argus_spike_common::{ExecEvent, FileEvent};
use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
    },
    macros::{lsm, map, tracepoint},
    maps::{
        Array, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{LsmContext, TracePointContext},
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static TRACKED: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);

#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static DENY_PATHS: LpmTrie<[u8; 256], u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

#[tracepoint]
pub fn argus_spike(_ctx: TracePointContext) -> u32 {
    let cgroup = unsafe { bpf_get_current_cgroup_id() };

    if unsafe { TRACKED.get(&cgroup) }.is_none() {
        return 0;
    }

    let ev = ExecEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        cgroup,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
    };
    if EVENTS.output::<ExecEvent>(&ev, 0).is_err() {
        if let Some(c) = DROPS.get_ptr_mut(0) {
            unsafe { *c += 1 };
        }
    }
    0
}

#[lsm(hook = "file_open")]
pub fn argus_file_open(ctx: LsmContext) -> i32 {
    let cg = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { TRACKED.get(&cg) }.is_none() {
        return 0;
    }

    let mut verdict: i32 = 0;

    if let Some(mut entry) = FILE_EVENTS.reserve::<FileEvent>(0) {
        let f: *const file = ctx.arg(0);
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            (*ev).uid = bpf_get_current_uid_gid() as u32;
            (*ev).cgroup = cg;
            (*ev).comm = bpf_get_current_comm().unwrap_or([0; 16]);
            (*ev).path_len = bpf_d_path(
                &(*f).__bindgen_anon_1 as *const _ as *mut _,
                (*ev).path.as_mut_ptr() as *mut _,
                256,
            ) as i32;

            let n = (*ev).path_len;
            let mut action = 0u32;
            if n > 0 {
                let key = Key::new(256 * 8, (*ev).path);
                if DENY_PATHS.get(&key).is_some() {
                    action = if CONFIG.get(0).copied().unwrap_or(0) == 1 {
                        2
                    } else {
                        1
                    };
                }
            }
            (*ev).action = action;

            if action == 2 {
                verdict = -1 // EPERM 
            };
        }
        entry.submit(0);
    }
    verdict
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
