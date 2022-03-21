use std::{
    panic::catch_unwind,
    sync::atomic::{AtomicIsize, Ordering},
};

use windows::Win32::{
    Foundation::{GetLastError, SetLastError, ERROR_SUCCESS, HWND, LPARAM, LRESULT, WPARAM},
    Graphics::Gdi::{GetStockObject, SetBkColor, SetTextColor, BLACK_BRUSH, HDC},
    UI::WindowsAndMessaging::{
        CallNextHookEx, CallWindowProcW, DefWindowProcW, GetClassNameW, SetWindowLongPtrW,
        GWLP_WNDPROC, MSG, WM_CTLCOLOREDIT,
    },
};

static ORIGINAL_WNDPROC: AtomicIsize = AtomicIsize::new(0);

#[no_mangle]
pub extern "system" fn get_message_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let _result = catch_unwind(|| {
        if code < 0 {
            return;
        }

        if ORIGINAL_WNDPROC.load(Ordering::SeqCst) != 0 {
            return;
        }

        let message = unsafe { (lparam.0 as *const MSG).as_ref().unwrap() };

        // The maximum length for lpszClassName is 256.
        // https://docs.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassexw
        let mut class_name = [0u16; 256 + 1];
        let returned = unsafe { GetClassNameW(message.hwnd, &mut class_name) };
        if returned == 0 {
            return;
        }
        let class_name = String::from_utf16(&class_name[..returned as usize]).unwrap();

        if class_name != "Notepad" {
            return;
        }

        let original_wndproc = unsafe {
            SetLastError(ERROR_SUCCESS);
            let result = SetWindowLongPtrW(message.hwnd, GWLP_WNDPROC, window_proc as isize);
            if result == 0 && GetLastError() != ERROR_SUCCESS {
                return;
            }
            result
        };
        ORIGINAL_WNDPROC.store(original_wndproc, Ordering::SeqCst);
    });

    unsafe { CallNextHookEx(None, code, wparam, lparam) }
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

        unsafe {
            CallWindowProcW(
                Some(std::mem::transmute(ORIGINAL_WNDPROC.load(Ordering::SeqCst))),
                hwnd,
                message,
                wparam,
                lparam,
            )
        }
    });
    match result {
        Ok(status) => status,
        Err(_) => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}
