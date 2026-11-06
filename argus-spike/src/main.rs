use argus_spike_common::{ExecEvent, FileEvent};
use aya::{
    Btf,
    maps::{
        Array, PerCpuArray, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{Lsm, TracePoint},
};
#[rustfmt::skip]
use log::{debug, warn};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::signal;

const USAGE: &str = "usage: argus-spike <cgroup-id> [observe|enforce] [absolute-deny-prefix...]";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let id: u64 = args.get(1).ok_or_else(|| anyhow::anyhow!(USAGE))?.parse()?;
    let mode = args.get(2).map(String::as_str).unwrap_or("observe");
    anyhow::ensure!(matches!(mode, "observe" | "enforce"), "{USAGE}");
    let prefixes: &[String] = args.get(3..).unwrap_or(&[]);
    for p in prefixes {
        anyhow::ensure!(
            p.starts_with('/'),
            "deny prefix must be an absolute, resolved path: {p}"
        );
        anyhow::ensure!(p.len() <= 256, "deny prefix too long: {p}");
    }

    // Bump the memlock rlimit for older kernels without memcg accounting.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/argus-spike"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            // S: the logger owns its file descriptor, which stays open and unchanged
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

    //fill maps
    {
        let mut tracked: aya::maps::HashMap<_, u64, u8> =
            aya::maps::HashMap::try_from(ebpf.map_mut("TRACKED").unwrap())?;
        tracked.insert(id, 1, 0)?;

        let mut cfg: Array<_, u32> = Array::try_from(ebpf.map_mut("CONFIG").unwrap())?;
        cfg.set(0, if mode == "enforce" { 1 } else { 0 }, 0)?;

        let mut deny: LpmTrie<_, [u8; 256], u8> =
            LpmTrie::try_from(ebpf.map_mut("DENY_PATHS").unwrap())?;
        for p in prefixes {
            let mut data = [0u8; 256];
            data[..p.len()].copy_from_slice(p.as_bytes());
            deny.insert(&Key::new((p.len() * 8) as u32, data), 1u8, 0)?;
        }
    }
    eprintln!("argus-spike: cgroup={id} mode={mode} deny={prefixes:?}");

    //attach programs
    let program: &mut TracePoint = ebpf.program_mut("argus_spike").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let btf = Btf::from_sys_fs()?;
    let prog: &mut Lsm = ebpf.program_mut("argus_file_open").unwrap().try_into()?;
    prog.load("file_open", &btf)?;
    prog.attach()?;

    //rings and counters
    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let file_ring = RingBuf::try_from(ebpf.take_map("FILE_EVENTS").unwrap())?;
    #[allow(deprecated)]
    let mut fd = AsyncFd::new(ring)?;
    #[allow(deprecated)]
    let mut file_fd = AsyncFd::new(file_ring)?;

    let drops: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.take_map("DROPS").unwrap())?;

    // drop reporter (stderr, only when a value changes)
    tokio::spawn(async move {
        let mut last = (0u64, 0u64);
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let sum =
                |i: u32| -> u64 { drops.get(&i, 0).map(|v| v.iter().sum::<u64>()).unwrap_or(0) };
            let now = (sum(0), sum(1));
            if now != last {
                eprintln!("DROPS exec={} file={}", now.0, now.1);
                last = now;
            }
        }
    });

    // exec events
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
            }
            guard.clear_ready();
        }
    });

    // file events
    tokio::spawn(async move {
        loop {
            let mut guard = file_fd.readable_mut().await.unwrap();
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                let ev: FileEvent =
                    unsafe { std::ptr::read_unaligned(item.as_ptr() as *const FileEvent) };
                let n = ev.path_len;
                let path = if n > 0 {
                    // bpf_d_path returns the length including the trailing NUL
                    let end = (n as usize - 1).min(ev.path.len());
                    String::from_utf8_lossy(&ev.path[..end]).into_owned()
                } else {
                    format!("<err {}>", n)
                };
                let label = match ev.action {
                    1 => " WOULD-BLOCK",
                    2 => " BLOCKED",
                    _ => "",
                };
                println!(
                    "file pid={} uid={} cgroup={} comm={} path={}{}",
                    ev.pid,
                    ev.uid,
                    ev.cgroup,
                    String::from_utf8_lossy(&ev.comm).trim_end_matches('\0'),
                    path,
                    label
                );
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
