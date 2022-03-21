use std::{
    os::windows::prelude::AsRawHandle,
    panic::catch_unwind,
    process::{Child, Command},
};

use anyhow::{bail, Result};
use windows::{
    core::{Error, PCWSTR},
    Win32::{
        Foundation::{BOOL, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WAIT_FAILED, WPARAM},
        System::{
            LibraryLoader::{
                GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            },
            Threading::WaitForInputIdle,
            WindowsProgramming::INFINITE,
        },
        UI::WindowsAndMessaging::{
            EnumWindows, GetClassNameW, GetWindowThreadProcessId, SetWindowsHookExW,
            UnhookWindowsHookEx, HHOOK, HOOKPROC, WH_GETMESSAGE, WINDOWS_HOOK_ID,
        },
    },
};

fn main() -> Result<()> {
    let mut process = Command::new("C:\\Windows\\System32\\notepad.exe")
        .args(std::env::args_os().skip(1))
        .spawn()?;

    wait_for_input_idle(&process)?;

    let notepad_thread_id = find_notepad_thread(process.id())?;

    let hook_module = get_image_base_from_function(get_message_hook as usize)?;

    let _hook = unsafe {
        WindowsHook::set(
            WH_GETMESSAGE,
            Some(get_message_hook),
            hook_module,
            notepad_thread_id,
        )?
    };

    if !process.wait()?.success() {
        bail!("Notepad returned error status");
    }

    Ok(())
}

fn wait_for_input_idle(process: &Child) -> Result<()> {
    let wait_result =
        unsafe { WaitForInputIdle(HANDLE(process.as_raw_handle() as isize), INFINITE) };
    if wait_result == WAIT_FAILED.0 {
        bail!(Error::from_win32());
    }
    if wait_result != 0 {
        bail!("WaitForInputIdle failed");
    }
    Ok(())
}

fn find_notepad_thread(target_pid: u32) -> Result<u32> {
    struct NotepadFindContext {
        target_pid: u32,
        found_tid: u32,
    }

    extern "system" fn find_notepad_thread_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let result = catch_unwind(|| unsafe {
            let context = lparam.0 as *mut NotepadFindContext;
            let context = context.as_mut().unwrap();

            // The maximum length for lpszClassName is 256.
            // https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassexw
            let mut class_name = [0u16; 256 + 1];
            let returned = GetClassNameW(hwnd, &mut class_name);
            if returned == 0 {
                return true;
            }
            let class_name = String::from_utf16(&class_name[..returned as usize]).unwrap();

            if class_name != "Notepad" {
                return true;
            }

            let mut process_id = 0;
            let thread_id = GetWindowThreadProcessId(hwnd, &mut process_id);
            if process_id == 0 || thread_id == 0 {
                return true;
            }

            if process_id != context.target_pid {
                return true;
            }

            context.found_tid = thread_id;
            return false;
        });
        match result {
            Ok(should_continue) => should_continue.into(),
            Err(_) => false.into(),
        }
    }

    unsafe {
        let mut find_context = NotepadFindContext {
            target_pid,
            found_tid: 0,
        };
        EnumWindows(
            Some(find_notepad_thread_callback),
            LPARAM(&mut find_context as *mut NotepadFindContext as isize),
        );
        if find_context.found_tid == 0 {
            bail!("Target window not found");
        }
        Ok(find_context.found_tid)
    }
}

fn get_image_base_from_function(function: usize) -> Result<HINSTANCE> {
    unsafe {
        let mut module = HINSTANCE(0);
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(function as _),
            &mut module,
        )
        .ok()?;
        Ok(module)
    }
}

#[derive(Debug)]
pub struct WindowsHook {
    hook: HHOOK,
}

impl WindowsHook {
    pub unsafe fn set(
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

#[link(name = "hook.dll")]
extern "system" {
    fn get_message_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT;
}
