use argus_spike_common::ExecEvent;
use aya::maps::{PerCpuArray, RingBuf};
use aya::programs::TracePoint;
#[rustfmt::skip]
use log::{debug, warn};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/argus-spike"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            // SAFETY: The logger owns its file descriptor, which stays open and unchanged
            // while the AsyncFd owns it. We only flush the logger, never replace it.
            let mut logger = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                )
            }?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut TracePoint = ebpf.program_mut("argus_spike").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let id: u64 = std::env::args()
        .nth(1)
        .expect("usage: argus-spike <cgroup-id>")
        .parse()?;
    {
        let mut tracked: aya::maps::HashMap<_, u64, u8> =
            aya::maps::HashMap::try_from(ebpf.map_mut("TRACKED").unwrap())?;
        tracked.insert(id, 1, 0)?;
    }

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut fd = AsyncFd::new(ring)?;

    let drops: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.take_map("DROPS").unwrap())?;

    tokio::spawn(async move {
        let mut last = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Ok(v) = drops.get(&0, 0) {
                let total: u64 = v.iter().sum();
                if total != last {
                    eprintln!("DROPS total={}", total);
                    last = total;
                }
            }
        }
    });

    tokio::spawn(async move {
        loop {
            let mut guard = fd.readable_mut().await.unwrap();
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let ev: ExecEvent =
                    unsafe { std::ptr::read_unaligned(item.as_ptr() as *const ExecEvent) };
                let comm = String::from_utf8_lossy(&ev.comm);
                println!(
                    "exec pid={} uid={} cgroup={} comm={}",
                    ev.pid,
                    ev.uid,
                    ev.cgroup,
                    comm.trim_end_matches('\0')
                );

                //tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            guard.clear_ready();
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
