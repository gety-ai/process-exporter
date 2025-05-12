use std::{mem::MaybeUninit, ops::Deref, ptr, time::Instant};

use once_cell::sync::OnceCell;
use widestring::{U16CStr, U16CString, u16cstr};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, FILETIME, GetLastError, HANDLE, HLOCAL, HMODULE, LocalFree, SUCCESS,
        },
        System::{
            Diagnostics::Debug::{
                FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_HMODULE,
                FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
            },
            LibraryLoader::LoadLibraryW,
            Performance::*,
            ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
    },
    core::{HRESULT, Owned, PCWSTR, PWSTR},
};

// ── PDH GPU helper ────────────────────────────────────────────
pub struct PdhGpu {
    query: PDH_HQUERY,
    ctrs: Vec<PDH_HCOUNTER>,
}

unsafe impl Send for PdhGpu {}
unsafe impl Sync for PdhGpu {}

fn format_phd_message(err_code: u32) -> Option<String> {
    let lib = unsafe {
        Owned::new(
            LoadLibraryW(windows::core::w!("pdh.dll"))
                .inspect_err(|e| log::warn!("Failed to load pdh.dll: {}", e))
                .ok()?,
        )
    };
    if lib.is_invalid() {
        log::warn!("Failed to load pdh.dll");
        return None;
    }
    let mut s = PWSTR::default();
    let _local = unsafe { Owned::new(HLOCAL(s.as_ptr() as *mut _)) };
    let size = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE
                | FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            Some(lib.0),
            err_code,
            0,
            PWSTR::from_raw(&mut s as *mut _ as *mut _),
            0,
            None,
        )
    };
    if size == 0 {
        log::warn!(
            "FormatMessageW failed: {}",
            windows::core::Error::from_win32()
        );
        return None;
    }
    let message = unsafe { s.to_string().ok()? };

    Some(message)
}

fn get_error_for_phd(err_code: u32) -> windows::core::Error {
    let msg = format_phd_message(err_code);
    match msg {
        Some(msg) => {
            let e = HRESULT::from_win32(err_code);
            windows::core::Error::new(e, msg)
        }
        None => HRESULT::from_win32(err_code).into(),
    }
}

impl PdhGpu {
    pub fn new(pid: u32) -> windows::core::Result<Self> {
        let mut query = PDH_HQUERY::default();

        let ret = unsafe { PdhOpenQueryW(None, 0, &mut query) };
        if ret != SUCCESS {
            return Err(get_error_for_phd(ret));
        }

        // Expand wildcard to enumerate all engine instances for the PID
        let templ = "\\GPU Engine(*)\\Utilization Percentage";
        let wide = U16CString::from_str(&templ).unwrap();
        let mut size = 0u32;
        let ret =
            unsafe { PdhExpandWildCardPathW(None, PCWSTR(wide.as_ptr()), None, &mut size, 0) };
        if ret != PDH_MORE_DATA && ret != SUCCESS {
            return Err(get_error_for_phd(ret));
        }
        let mut buf: Vec<u16> = vec![0; size as usize];
        let ret = unsafe {
            PdhExpandWildCardPathW(
                None,
                PCWSTR(wide.as_ptr()),
                Some(PWSTR::from_raw(buf.as_mut_ptr())),
                &mut size,
                0,
            )
        };
        if ret != SUCCESS {
            return Err(get_error_for_phd(ret));
        }

        let list = parse_multi_string(&buf);
        // eprintln!("list: {:#?}", list);

        let mut ctrs = Vec::new();
        let pid = format!("pid_{}", pid);
        for path in list.iter().filter(|s| !s.is_empty() && s.contains(&pid)) {
            log::debug!("adding counter: {}", path);
            let mut c = PDH_HCOUNTER::default();
            let wide = U16CString::from_str(path).unwrap();
            let ret = unsafe { PdhAddCounterW(query, PCWSTR(wide.as_ptr()), 0, &mut c) };
            if ret != SUCCESS {
                return Err(get_error_for_phd(ret));
            }
            if c.is_invalid() {
                panic!("PdhAddCounterW failed: {}", ret);
            }
            ctrs.push(c);
        }

        unsafe { PdhCollectQueryData(query) };
        Ok(Self { query, ctrs })
    }

    pub fn is_active(&self) -> bool {
        !self.ctrs.is_empty()
    }

    pub fn sample(&self) -> f64 {
        unsafe {
            let ret = PdhCollectQueryData(self.query);
            if ret != SUCCESS && ret != PDH_NO_DATA {
                let e = get_error_for_phd(ret);
                log::warn!("PdhCollectQueryData failed: {}", e);
                return 0.0;
            }
        }
        self.ctrs.iter().fold(0f64, |acc, &h| {
            let mut ty = 0u32;
            let mut v = PDH_FMT_COUNTERVALUE::default();
            let ret =
                unsafe { PdhGetFormattedCounterValue(h, PDH_FMT_DOUBLE, Some(&mut ty), &mut v) };
            if ret != SUCCESS {
                log::warn!(
                    "PdhGetFormattedCounterValue failed: {}",
                    get_error_for_phd(ret)
                );
                return acc;
            }
            acc + unsafe { v.Anonymous.doubleValue }
        })
    }
}

impl Drop for PdhGpu {
    fn drop(&mut self) {
        unsafe {
            PdhCloseQuery(self.query);
        }
    }
}

// ── CPU helper ────────────────────────────────────────────────
struct Cpu {
    handle: HANDLE,
    last_k: u64,
    last_u: u64,
    last_t: Instant,
}
impl Cpu {
    fn new(h: HANDLE) -> Self {
        Self {
            handle: h,
            last_k: 0,
            last_u: 0,
            last_t: Instant::now(),
        }
    }
    fn percent(&mut self) -> f64 {
        let (mut kt, mut ut) = (MaybeUninit::uninit(), MaybeUninit::uninit());
        if unsafe {
            GetProcessTimes(
                self.handle,
                ptr::null_mut(),
                ptr::null_mut(),
                kt.as_mut_ptr(),
                ut.as_mut_ptr(),
            )
            .is_ok()
        } {
            let k = unsafe { *(kt.as_ptr() as *const u64) };
            let u = unsafe { *(ut.as_ptr() as *const u64) };
            let dt = self.last_t.elapsed().as_secs_f64();
            let cpu = ((k - self.last_k + u - self.last_u) as f64 * 1e-7) / dt * 100.0;
            self.last_k = k;
            self.last_u = u;
            self.last_t = Instant::now();
            cpu
        } else {
            0.0
        }
    }
}

pub fn memory_bytes(h: HANDLE) -> u64 {
    let mut c = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();
    unsafe {
        if K32GetProcessMemoryInfo(
            h,
            c.as_mut_ptr(),
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .as_bool()
        {
            c.assume_init().WorkingSetSize as u64
        } else {
            0
        }
    }
}

pub fn open_process(pid: u32) -> Result<Owned<HANDLE>, windows::core::Error> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }?;

    Ok(unsafe { Owned::new(h) })
}

fn parse_multi_string(buffer: &[u16]) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &ch in buffer {
        if ch == 0 {
            if !current.is_empty() {
                let s = String::from_utf16_lossy(&current);
                if !s.is_empty() {
                    results.push(s);
                }
                current.clear();
            } else if !results.is_empty() {
                // 双零表示结束
                break;
            }
        } else {
            current.push(ch);
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;
    use widestring::widecstr;

    fn get_process_name_pid(name: &str) -> Option<u32> {
        let output = std::process::Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output()
            .expect("Failed to execute tasklist command");

        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let process_name = parts[0].trim_matches('"');
                let pid = parts[1].trim_matches('"');

                if process_name == name {
                    return Some(pid.parse::<u32>().unwrap());
                }
            }
        }
        None
    }

    pub fn get_dwm_pid() -> Option<u32> {
        get_process_name_pid("dwm.exe")
    }
    fn get_explorer_pid() -> Option<u32> {
        get_process_name_pid("explorer.exe")
    }

    #[test]
    fn print_pids() {
        let output = std::process::Command::new("tasklist")
            .args(&["/FO", "CSV", "/NH"])
            .output()
            .expect("Failed to execute tasklist command");

        let output_str = String::from_utf8_lossy(&output.stdout);

        println!("常见 Windows 进程的 PID:");
        for line in output_str.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let process_name = parts[0].trim_matches('"');
                let pid = parts[1].trim_matches('"');

                if [
                    "System",
                    "explorer.exe",
                    "svchost.exe",
                    "lsass.exe",
                    "csrss.exe",
                    "services.exe",
                    "winlogon.exe",
                    "wininit.exe",
                    "dwm.exe",
                ]
                .contains(&process_name)
                {
                    println!("{}: PID {}", process_name, pid);
                }
            }
        }
    }

    #[test]
    fn test_gpu_usage() {
        let pid = get_dwm_pid().expect("Failed to get explorer pid");
        let gpu = PdhGpu::new(pid).expect("Failed to create PdhGpu");
        std::thread::sleep(std::time::Duration::from_secs(2));
        println!("gpu: {}", gpu.sample());
    }

    #[test]
    fn enumerate_gpu_counters() {
        let mut buffer_size = 0u32;
        let mut item_count = 0u32;

        let name = widecstr!("GPU Engine");

        // 第一次调用获取所需缓冲区大小
        unsafe {
            let ret = PdhEnumObjectItemsW(
                None,
                None,
                PCWSTR::from_raw(name.as_ptr()),
                None,
                &mut buffer_size,
                None,
                &mut item_count,
                PERF_DETAIL_WIZARD,
                0,
            );
            eprintln!("{:#X}", ret);
            assert_eq!(ret, PDH_MORE_DATA);
        }

        eprintln!("buffer_size: {}", buffer_size);
        eprintln!("item_count: {}", item_count);

        // 分配缓冲区
        let mut counter_buffer = vec![0u16; buffer_size as usize];
        let mut instance_buffer = vec![0u16; item_count as usize];

        // 获取计数器和实例名称
        let ret = unsafe {
            PdhEnumObjectItemsW(
                None,
                None,
                PCWSTR::from_raw(name.as_ptr()),
                Some(PWSTR::from_raw(counter_buffer.as_mut_ptr())),
                &mut buffer_size,
                Some(PWSTR::from_raw(instance_buffer.as_mut_ptr())),
                &mut item_count,
                PERF_DETAIL_WIZARD,
                0,
            )
        };
        eprintln!("{:#x}", ret);

        assert_eq!(ret, SUCCESS);

        // 处理并打印结果
        let counters = parse_multi_string(&counter_buffer);
        let instances = parse_multi_string(&instance_buffer);

        println!("可用的 GPU 计数器:");
        for counter in counters {
            println!("  {}", counter);
        }

        println!("可用的 GPU 实例:");
        for instance in instances {
            println!("  {}", instance);
        }
    }
}
