#![windows_subsystem = "windows"]

use anyhow::{bail, Result};
use windows::{
    core::{Error, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, HINSTANCE, LPARAM, LRESULT, WAIT_FAILED, WPARAM},
        System::{
            Environment::GetCommandLineW,
            LibraryLoader::{
                GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            },
            Threading::{
                CreateProcessW, GetExitCodeProcess, GetStartupInfoW, WaitForInputIdle,
                WaitForSingleObject, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
                WAIT_OBJECT_0,
            },
            WindowsProgramming::INFINITE,
        },
        UI::WindowsAndMessaging::{
            SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, HOOKPROC, WH_GETMESSAGE, WINDOWS_HOOK_ID,
        },
    },
};

#[allow(dead_code)]
struct ProcessInformation {
    process_handle: HANDLE,
    thread_handle: HANDLE,
    pid: u32,
    tid: u32,
}

impl Drop for ProcessInformation {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_handle);
            CloseHandle(self.thread_handle);
        }
    }
}

struct WindowsHook {
    hook: HHOOK,
}

impl WindowsHook {
    unsafe fn set(
        id: WINDOWS_HOOK_ID,
        function: HOOKPROC,
        module: HINSTANCE,
        thread_id: u32,
    ) -> Result<Self> {
        let hook = SetWindowsHookExW(id, function, module, thread_id);
        if hook.0 == 0 {
            bail!(Error::from_win32());
        }
        Ok(Self { hook })
    }
}

impl Drop for WindowsHook {
    fn drop(&mut self) {
        unsafe {
            UnhookWindowsHookEx(self.hook);
        }
    }
}

fn main() -> Result<()> {
    std::process::exit(actual_main()? as i32);
}

fn actual_main() -> Result<u32> {
    let process_info = create_notepad_process()?;

    wait_for_input_idle(process_info.process_handle)?;

    let hook_module = get_image_base_from_address(get_message_hook as usize)?;

    let _hook = unsafe {
        WindowsHook::set(
            WH_GETMESSAGE,
            Some(get_message_hook),
            hook_module,
            process_info.tid,
        )?
    };

    wait_for_single_object(process_info.process_handle)?;

    let exit_code = unsafe {
        let mut exit_code = 0;
        GetExitCodeProcess(process_info.process_handle, &mut exit_code).ok()?;
        exit_code
    };

    Ok(exit_code)
}

fn create_notepad_process() -> Result<ProcessInformation> {
    unsafe {
        let command_line = GetCommandLineW();

        let mut startup_info = STARTUPINFOW::default();
        GetStartupInfoW(&mut startup_info);

        let mut process_info = PROCESS_INFORMATION::default();

        CreateProcessW(
            "C:\\Windows\\System32\\notepad.exe",
            command_line,
            std::ptr::null(),
            std::ptr::null(),
            true,
            PROCESS_CREATION_FLAGS(0),
            std::ptr::null(),
            None,
            &startup_info,
            &mut process_info,
        )
        .ok()?;

        Ok(ProcessInformation {
            process_handle: process_info.hProcess,
            thread_handle: process_info.hThread,
            pid: process_info.dwProcessId,
            tid: process_info.dwThreadId,
        })
    }
}

fn wait_for_input_idle(process: HANDLE) -> Result<()> {
    let wait_result = unsafe { WaitForInputIdle(process, INFINITE) };
    if wait_result == WAIT_FAILED.0 {
        bail!(Error::from_win32());
    }
    if wait_result != 0 {
        bail!("WaitForInputIdle failed");
    }
    Ok(())
}

fn get_image_base_from_address(address: usize) -> Result<HINSTANCE> {
    unsafe {
        let mut module = HINSTANCE(0);
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(address as _),
            &mut module,
        )
        .ok()?;
        Ok(module)
    }
}

fn wait_for_single_object(object: HANDLE) -> Result<()> {
    let wait_result = unsafe { WaitForSingleObject(object, INFINITE) };
    if wait_result == WAIT_FAILED.0 {
        bail!(Error::from_win32())
    }
    if wait_result != WAIT_OBJECT_0 {
        bail!("WaitForSingleObject failed");
    }
    Ok(())
}

#[link(name = "nitepad_hook.dll")]
extern "system" {
    fn get_message_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT;
}
