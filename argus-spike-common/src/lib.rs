#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup: u64,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FileEvent {
    pub pid: u32,
    pub uid: u32,
    pub cgroup: u64,
    pub comm: [u8; 16],
    pub action: u32,
    pub path_len: i32,
    pub path: [u8; 256],
}

//pub action: u32 to FileEvent (0 = none, 1 = would block, 2 = block)
