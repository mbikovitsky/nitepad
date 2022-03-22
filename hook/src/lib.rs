use std::panic::catch_unwind;

use windows::Win32::{
    Foundation::{GetLastError, SetLastError, BOOL, ERROR_SUCCESS, HWND, LPARAM, LRESULT, WPARAM},
    Graphics::Gdi::{
        GetStockObject, RedrawWindow, SetBkColor, SetTextColor, BLACK_BRUSH, HDC, RDW_ALLCHILDREN,
        RDW_ERASE, RDW_FRAME, RDW_INTERNALPAINT, RDW_INVALIDATE, RDW_UPDATENOW,
    },
    System::Threading::GetCurrentThreadId,
    UI::WindowsAndMessaging::{
        CallNextHookEx, CallWindowProcW, DefWindowProcW, EnumThreadWindows, GetClassNameW,
        SetWindowLongPtrW, GWLP_WNDPROC, WM_CTLCOLOREDIT, WNDPROC,
    },
};

static mut ORIGINAL_WNDPROC: WNDPROC = None;

#[no_mangle]
pub extern "system" fn get_message_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let _result = catch_unwind(|| {
        if code < 0 {
            return;
        }

        unsafe {
            if ORIGINAL_WNDPROC.is_some() {
                return;
            }

            EnumThreadWindows(GetCurrentThreadId(), Some(hook_window_proc_callback), None);
        }
    });

    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

extern "system" fn hook_window_proc_callback(hwnd: HWND, _: LPARAM) -> BOOL {
    let result = catch_unwind(|| {
        // The maximum length for lpszClassName is 256.
        // https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassexw
        let mut class_name = [0u16; 256 + 1];
        let returned = unsafe { GetClassNameW(hwnd, &mut class_name) };
        if returned == 0 {
            return true;
        }
        let class_name = String::from_utf16_lossy(&class_name[..returned as usize]);

        if class_name != "Notepad" {
            return true;
        }

        unsafe {
            SetLastError(ERROR_SUCCESS);
            let result = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, window_proc as isize);
            if result == 0 && GetLastError() != ERROR_SUCCESS {
                return true;
            }
            ORIGINAL_WNDPROC = Some(std::mem::transmute(result));
        }

        unsafe {
            RedrawWindow(
                hwnd,
                std::ptr::null(),
                None,
                RDW_ERASE
                    | RDW_FRAME
                    | RDW_INTERNALPAINT
                    | RDW_INVALIDATE
                    | RDW_UPDATENOW
                    | RDW_ALLCHILDREN,
            );
        }

        false
    });
    match result {
        Ok(should_continue) => should_continue.into(),
        Err(_) => false.into(),
    }
}

extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let result = catch_unwind(|| {
        if message == WM_CTLCOLOREDIT {
            unsafe {
                // https://forums.codeguru.com/showthread.php?303852-Practical-use-of-WM_CTLCOLOREDIT
                let dc = HDC(wparam.0 as isize);
                SetTextColor(dc, 0x00FFFFFF);
                SetBkColor(dc, 0x00000000);
                return LRESULT(GetStockObject(BLACK_BRUSH).0);
            }
        }

        unsafe { CallWindowProcW(ORIGINAL_WNDPROC, hwnd, message, wparam, lparam) }
    });
    match result {
        Ok(status) => status,
        Err(_) => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}
