

#![windows_subsystem = "windows"]

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontW, FONT_CHARSET, FONT_CLIP_PRECISION, FONT_OUTPUT_PRECISION, FONT_QUALITY,
    FW_BOLD, FW_NORMAL, HBRUSH,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{InitCommonControlsEx, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, HMENU, MessageBoxW,
    PostQuitMessage, RegisterClassW, SendMessageW, SetWindowTextW, ShowWindow, BS_DEFPUSHBUTTON,
    BS_PUSHBUTTON, MB_ICONERROR, MB_OK, MSG, SW_SHOW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_COMMAND,
    WM_CREATE, WM_DESTROY, WM_SETFONT, WNDCLASSW, WS_CHILD, WS_MAXIMIZEBOX, WS_OVERLAPPEDWINDOW,
    WS_TABSTOP, WS_THICKFRAME, WS_VISIBLE,
};

const IDC_START_BTN: usize = 201;
const IDC_STOP_BTN: usize = 202;
const IDC_STATUS_LABEL: usize = 203;
const IDC_INFO_LABEL: usize = 204;

static RUNNING_SERVER: Mutex<Option<Child>> = Mutex::new(None);
static UI_HANDLES: Mutex<Option<ServerUiHandles>> = Mutex::new(None);

#[derive(Clone, Copy)]
struct ServerUiHandles {
    btn_start: usize,
    btn_stop: usize,
    status_label: usize,
}

impl ServerUiHandles {
    fn start_hwnd(self) -> HWND {
        HWND(self.btn_start as *mut _)
    }
    fn stop_hwnd(self) -> HWND {
        HWND(self.btn_stop as *mut _)
    }
    fn status_hwnd(self) -> HWND {
        HWND(self.status_label as *mut _)
    }
}

fn find_server_binary() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let candidates = [
        exe_dir.join("server.exe"),
        exe_dir.join(r"APP\release\server.exe"),
        exe_dir.join(r"APP\debug\server.exe"),
        exe_dir.join(r"..\APP\release\server.exe"),
        exe_dir.join(r"..\APP\debug\server.exe"),
        exe_dir.join(r"..\..\APP\release\server.exe"),
        exe_dir.join(r"target\release\server.exe"),
        exe_dir.join(r"target\debug\server.exe"),
        exe_dir.join(r"..\target\release\server.exe"),
        exe_dir.join(r"..\target\debug\server.exe"),
        exe_dir.join(r"..\..\target\release\server.exe"),
    ];

    candidates.into_iter().find(|p| p.exists())
}

fn start_server(hwnd: HWND) -> anyhow::Result<()> {
    let mut lock = RUNNING_SERVER.lock().unwrap();
    if lock.is_some() {
        return Ok(());
    }

    let server_bin = if let Some(bin) = find_server_binary() {
        Command::new(bin).spawn()?
    } else {
        Command::new("cargo")
            .args(["run", "-p", "server", "--release"])
            .spawn()?
    };

    *lock = Some(server_bin);

    if let Some(ui) = UI_HANDLES.lock().unwrap().as_ref() {
        unsafe {
            let _ = SetWindowTextW(
                ui.status_hwnd(),
                w!("Durum: Sunucu Açık (Auth: 8000 | Entry: 2270 | Lobby: 2271 Dinleniyor)"),
            );
            let _ = EnableWindow(ui.start_hwnd(), false);
            let _ = EnableWindow(ui.stop_hwnd(), true);
        }
    }

    Ok(())
}

fn stop_server() {
    let mut lock = RUNNING_SERVER.lock().unwrap();
    if let Some(mut child) = lock.take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    if let Some(ui) = UI_HANDLES.lock().unwrap().as_ref() {
        unsafe {
            let _ = SetWindowTextW(ui.status_hwnd(), w!("Durum: Sunucu Kapalı"));
            let _ = EnableWindow(ui.start_hwnd(), true);
            let _ = EnableWindow(ui.stop_hwnd(), false);
        }
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            let font = CreateFontW(
                16, 0, 0, 0, FW_NORMAL.0 as i32, 0, 0, 0,
                FONT_CHARSET(1),
                FONT_OUTPUT_PRECISION(0),
                FONT_CLIP_PRECISION(0),
                FONT_QUALITY(0),
                0,
                w!("Segoe UI"),
            );
            let font_bold = CreateFontW(
                16, 0, 0, 0, FW_BOLD.0 as i32, 0, 0, 0,
                FONT_CHARSET(1),
                FONT_OUTPUT_PRECISION(0),
                FONT_CLIP_PRECISION(0),
                FONT_QUALITY(0),
                0,
                w!("Segoe UI"),
            );

let info = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("STATIC"),
                w!("Goley Server Emulator — Auth, Entry & Lobby Hizmetleri"),
                WS_CHILD | WS_VISIBLE,
                20, 15, 440, 20,
                Some(hwnd),
                Some(HMENU(IDC_INFO_LABEL as *mut _)),
                None, None,
            ).unwrap();
            SendMessageW(info, WM_SETFONT, Some(WPARAM(font_bold.0 as usize)), Some(LPARAM(1)));

let btn_start = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("BUTTON"),
                w!("SUNUCUYU BAŞLAT"),
                WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_DEFPUSHBUTTON as u32),
                20, 45, 210, 45,
                Some(hwnd),
                Some(HMENU(IDC_START_BTN as *mut _)),
                None, None,
            ).unwrap();
            SendMessageW(btn_start, WM_SETFONT, Some(WPARAM(font_bold.0 as usize)), Some(LPARAM(1)));

let btn_stop = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("BUTTON"),
                w!("SUNUCUYU DURDUR"),
                WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32),
                240, 45, 210, 45,
                Some(hwnd),
                Some(HMENU(IDC_STOP_BTN as *mut _)),
                None, None,
            ).unwrap();
            SendMessageW(btn_stop, WM_SETFONT, Some(WPARAM(font_bold.0 as usize)), Some(LPARAM(1)));
            let _ = EnableWindow(btn_stop, false);

let status = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("STATIC"),
                w!("Durum: Sunucu Kapalı"),
                WS_CHILD | WS_VISIBLE,
                20, 105, 440, 40,
                Some(hwnd),
                Some(HMENU(IDC_STATUS_LABEL as *mut _)),
                None, None,
            ).unwrap();
            SendMessageW(status, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));

            *UI_HANDLES.lock().unwrap() = Some(ServerUiHandles {
                btn_start: btn_start.0 as usize,
                btn_stop: btn_stop.0 as usize,
                status_label: status.0 as usize,
            });

            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as usize;
            match id {
                IDC_START_BTN => {
                    if let Err(e) = start_server(hwnd) {
                        let err_msg = format!("Sunucu Başlatılamadı:\n{}", e);
                        let err_wide: Vec<u16> = err_msg.encode_utf16().chain(Some(0)).collect();
                        MessageBoxW(
                            Some(hwnd),
                            PCWSTR(err_wide.as_ptr()),
                            w!("Hata"),
                            MB_OK | MB_ICONERROR,
                        );
                    }
                }
                IDC_STOP_BTN => {
                    stop_server();
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            stop_server();
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn main() -> anyhow::Result<()> {
    unsafe {
        let mut icce = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES,
        };
        let _ = InitCommonControlsEx(&mut icce);

        let instance = GetModuleHandleW(None).unwrap();
        let class_name = w!("GoleyServerLauncherWindowClass");

        let wc = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: HINSTANCE(instance.0),
            lpszClassName: class_name,
            hbrBackground: HBRUSH(15 as *mut _),
            ..Default::default()
        };

        RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            w!("Goley Server Launcher"),
            WINDOW_STYLE(
                (WS_OVERLAPPEDWINDOW.0 & !WS_THICKFRAME.0 & !WS_MAXIMIZEBOX.0)
                    | WS_VISIBLE.0,
            ),
            120, 120, 490, 190,
            None, None, Some(HINSTANCE(instance.0)), None,
        ).unwrap();

        let _ = ShowWindow(hwnd, SW_SHOW);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = DispatchMessageW(&msg);
        }
    }

    Ok(())
}
