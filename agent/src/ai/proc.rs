//! 子行程樹的生命週期：Windows 用 Job Object（KILL_ON_JOB_CLOSE，`cmd /C claude.cmd` 底下的 node 也一起收掉）；
//! Unix 用 process group（逾時時 kill 整組）。db-kit 缺這塊，這裡補上。

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    pub struct Job(HANDLE);

    // HANDLE 只在這個結構裡用，跨 await 搬移沒有問題。
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        pub fn new() -> Option<Job> {
            unsafe {
                let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if h.is_null() {
                    return None;
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    h,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 {
                    CloseHandle(h);
                    return None;
                }
                Some(Job(h))
            }
        }

        pub fn assign(&self, child: &tokio::process::Child) -> bool {
            match child.raw_handle() {
                Some(ph) => unsafe { AssignProcessToJobObject(self.0, ph as HANDLE) != 0 },
                None => false,
            }
        }

        pub fn kill(&self) {
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub struct Job(std::sync::atomic::AtomicI32);

    impl Job {
        pub fn new() -> Option<Job> {
            Some(Job(std::sync::atomic::AtomicI32::new(0)))
        }

        /// 子行程以 `process_group(0)` 啟動，pgid＝pid。
        pub fn assign(&self, child: &tokio::process::Child) -> bool {
            match child.id() {
                Some(pid) => {
                    self.0.store(pid as i32, std::sync::atomic::Ordering::Relaxed);
                    true
                }
                None => false,
            }
        }

        pub fn kill(&self) {
            let pg = self.0.load(std::sync::atomic::Ordering::Relaxed);
            if pg > 0 {
                unsafe {
                    libc::kill(-pg, libc::SIGKILL);
                }
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            self.kill();
        }
    }
}

pub use imp::Job;

/// 設定 Command：Windows 不開主控台視窗；Unix 開新的 process group。
pub fn prepare(cmd: &mut tokio::process::Command) {
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    cmd.kill_on_drop(true);
}
