#![no_std]
#![no_main]

//use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
//use aya_log_ebpf::info;

use aya_ebpf::maps::{HashMap, PerCpuArray};

use argus_spike_common::ExecEvent;
use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static TRACKED: HashMap<u64, u8> = HashMap::with_max_entries(64, 0);

#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
