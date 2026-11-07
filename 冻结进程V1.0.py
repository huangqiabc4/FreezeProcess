#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
冻结进程2.py —— 完全冻结 + 窗口雪藏（不触发"应用程序失去响应，现将关闭"）

和 冻结进程.py 的区别：
    冻结进程.py   保留窗口线程，窗口还能应答消息，所以不会"未响应"
                  —— 但对游戏无效：游戏的主线程会在等一个被挂起的工作线程（渲染/资源流送），
                     自己也会卡死，窗口照样不回消息，于是 Windows 弹"应用程序失去响应"。
    冻结进程2.py  反过来：先把窗口藏起来、从任务栏和 Alt+Tab 摘掉，再把进程**整个**冻结。
                  Windows 只能对"看得见的卡死窗口"弹对话框；窗口都不在了，
                  Explorer 根本没有对象可以标记未响应，也就不会弹那个框。

用法：
        python 冻结进程2.py               # 第一次 = 雪藏，再运行一次 = 解冻
        python 冻结进程2.py --list        # 只看状态
        python 冻结进程2.py --no-hide     # 只完全冻结，不藏窗口（会重新出现未响应提示）
        python 冻结进程2.py --keep-ui     # 用旧版策略：保留窗口线程
"""

import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import tempfile
import time

# ============================================================
#  配置
# ============================================================
TARGET = "PBZ.exe"

HIDE_WINDOW = True       # 雪藏：隐藏窗口 + 摘掉任务栏按钮（关键，别关）
FULL_SUSPEND = True      # True = 整个进程冻结；False = 走旧版保留窗口线程
ELEVATE = True           # 需要时自动提权
# ============================================================

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
ole32 = ctypes.WinDLL("ole32")

PROCESS_SUSPEND_RESUME = 0x0800
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPPROCESS = 0x00000002
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

SW_HIDE = 0
SW_SHOWNORMAL = 1
SW_SHOWMINIMIZED = 2
SW_SHOWMAXIMIZED = 3
SW_SHOW = 5
SW_MINIMIZE = 6
SW_SHOWNA = 8
SW_RESTORE = 9

GWL_EXSTYLE = -20
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_APPWINDOW = 0x00040000

kWNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ThreadID", wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wt.DWORD),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class POINT(ctypes.Structure):
    _fields_ = [("x", wt.LONG), ("y", wt.LONG)]


class RECT(ctypes.Structure):
    _fields_ = [("left", wt.LONG), ("top", wt.LONG), ("right", wt.LONG), ("bottom", wt.LONG)]


class WINDOWPLACEMENT(ctypes.Structure):
    _fields_ = [
        ("length", wt.UINT),
        ("flags", wt.UINT),
        ("showCmd", wt.UINT),
        ("ptMinPosition", POINT),
        ("ptMaxPosition", POINT),
        ("rcNormalPosition", RECT),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wt.DWORD),
        ("Data2", wt.WORD),
        ("Data3", wt.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


CLSID_TaskbarList = GUID(0x56FDF344, 0xFD6D, 0x11D0,
                         (ctypes.c_ubyte * 8)(0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90))
IID_ITaskbarList = GUID(0x56FDF342, 0xFD6D, 0x11D0,
                        (ctypes.c_ubyte * 8)(0x95, 0x8A, 0x00, 0x60, 0x97, 0xC9, 0xA0, 0x90))

# ---------------- API 原型（64 位下必须声明，否则句柄会被截断）----------------

k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Process32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.Process32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.Thread32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.Thread32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.OpenThread.restype = wt.HANDLE
k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.CloseHandle.argtypes = [wt.HANDLE]

user32.EnumWindows.argtypes = [kWNDENUMPROC, wt.LPARAM]
user32.EnumWindows.restype = wt.BOOL
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
user32.GetWindowThreadProcessId.restype = wt.DWORD
user32.IsWindow.argtypes = [wt.HWND]
user32.IsWindow.restype = wt.BOOL
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.IsWindowVisible.restype = wt.BOOL
user32.IsIconic.argtypes = [wt.HWND]
user32.IsIconic.restype = wt.BOOL
user32.GetWindowTextLengthW.argtypes = [wt.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
user32.ShowWindow.restype = wt.BOOL
user32.GetWindowPlacement.argtypes = [wt.HWND, ctypes.POINTER(WINDOWPLACEMENT)]
user32.GetWindowPlacement.restype = wt.BOOL
user32.GetWindowLongPtrW.argtypes = [wt.HWND, ctypes.c_int]
user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
user32.SetWindowLongPtrW.argtypes = [wt.HWND, ctypes.c_int, ctypes.c_ssize_t]
user32.SetWindowLongPtrW.restype = ctypes.c_ssize_t

ntdll.NtSuspendProcess.argtypes = [wt.HANDLE]
ntdll.NtSuspendProcess.restype = ctypes.c_long
ntdll.NtResumeProcess.argtypes = [wt.HANDLE]
ntdll.NtResumeProcess.restype = ctypes.c_long


# ---------------- 权限 ----------------

def enable_debug_privilege():
    """打开 SeDebugPrivilege，才能操作别的用户/更高权限的进程。"""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    token = wt.HANDLE()
    if not advapi.OpenProcessToken(
        k32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return False
    try:
        luid = LUID()
        if not advapi.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        return bool(advapi.AdjustTokenPrivileges(
            token, False, ctypes.byref(tp), 0, None, None))
    finally:
        k32.CloseHandle(token)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate():
    """以管理员身份重新启动自己。"""
    params = " ".join(sys.argv[1:]) + " --elevated"
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{os.path.abspath(__file__)}" {params.strip()}', None, 1
    )
    return rc > 32


# ---------------- 进程 / 线程枚举 ----------------

def find_pids(name):
    """按映像名找进程（name 不带 .exe 也能匹配）。支持多实例。"""
    if not name.lower().endswith(".exe"):
        name = name + ".exe"
    pids = []
    h = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260),
        ]

    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(pe)
    ok = k32.Process32First(h, ctypes.byref(pe))
    while ok:
        if pe.szExeFile.decode("mbcs", "ignore").lower() == name.lower():
            pids.append(pe.th32ProcessID)
        ok = k32.Process32Next(h, ctypes.byref(pe))
    k32.CloseHandle(h)
    return pids


def thread_ids(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == wt.HANDLE(-1).value:
        return []
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    ids = []
    ok = k32.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid:
            ids.append(te.th32ThreadID)
        ok = k32.Thread32Next(snap, ctypes.byref(te))
    k32.CloseHandle(snap)
    return ids


# ---------------- 窗口 ----------------

def windows_of(pid, visible_only=False):
    out = []

    def cb(hwnd, _):
        p = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid and (not visible_only or user32.IsWindowVisible(hwnd)):
            out.append(int(hwnd))
        return True

    user32.EnumWindows(kWNDENUMPROC(cb), 0)
    return out


def window_title(hwnd):
    n = user32.GetWindowTextLengthW(hwnd)
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def main_window(pid):
    """挑一个有标题的顶层窗口作为主窗口。"""
    best, best_len = 0, -1
    for hwnd in windows_of(pid, visible_only=True):
        n = user32.GetWindowTextLengthW(hwnd)
        if n > best_len:
            best, best_len = hwnd, n
    if best:
        return best
    ws = windows_of(pid, visible_only=True)
    return ws[0] if ws else 0


def ui_threads(pid):
    """所有顶层窗口的窗口线程（保留窗口线程模式用）。"""
    tids = set()
    for hwnd in windows_of(pid):
        p = wt.DWORD()
        tids.add(user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p)))
    tids.discard(0)
    return tids


# ---------------- 任务栏按钮（ITaskbarList）----------------

_taskbar = [None]


def _taskbar_obj():
    """懒加载 ITaskbarList；失败返回 None（藏窗口仍然可用，只是任务栏按钮可能残留）。"""
    if _taskbar[0] is not None:
        return _taskbar[0] or None
    ole32.CoInitialize(None)

    class _Vtbl(ctypes.Structure):
        pass

    p = ctypes.c_void_p()
    hr = ole32.CoCreateInstance(
        ctypes.byref(CLSID_TaskbarList), None, 1,
        ctypes.byref(IID_ITaskbarList), ctypes.byref(p))
    if hr != 0 or not p:
        _taskbar[0] = False
        return None
    vtbl = ctypes.cast(p, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    hr_init = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)(vtbl[3])
    if hr_init(p) != 0:
        _taskbar[0] = False
        return None
    _taskbar[0] = (p, vtbl)
    return _taskbar[0]


def _tab_call(index, hwnd):
    obj = _taskbar_obj()
    if not obj:
        return False
    p, vtbl = obj
    fn = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wt.HWND)(vtbl[index])
    fn(p, hwnd)
    return True


def delete_tab(hwnd):
    """从任务栏摘掉按钮（指数 5）。"""
    return _tab_call(5, hwnd)


def add_tab(hwnd):
    """把按钮挂回任务栏（指数 4）。"""
    return _tab_call(4, hwnd)


# ---------------- 雪藏 / 还原窗口 ----------------

def _record_path(pid):
    return os.path.join(tempfile.gettempdir(), f"freeze2_{pid}.json")


def save_records(pid, recs):
    try:
        with open(_record_path(pid), "w", encoding="utf-8") as f:
            json.dump(recs, f)
    except Exception:
        pass


def load_records(pid):
    try:
        with open(_record_path(pid), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def drop_records(pid):
    try:
        os.remove(_record_path(pid))
    except Exception:
        pass


def hide_windows(pid):
    """藏起进程的所有可见顶层窗口，并从任务栏 / Alt+Tab 摘掉。

    返回记录列表，解冻时按记录原样还原（含窗口样式与最小化/最大化状态）。
    """
    recs = []
    for hwnd in windows_of(pid):
        if not user32.IsWindowVisible(hwnd):
            continue
        ex = user32.GetWindowLongPtrW(hwnd, GWL_EXSTYLE)
        wp = WINDOWPLACEMENT()
        wp.length = ctypes.sizeof(wp)
        has_wp = bool(user32.GetWindowPlacement(hwnd, ctypes.byref(wp)))

        delete_tab(hwnd)
        # WS_EX_TOOLWINDOW：从 Alt+Tab 里也消失；WS_EX_APPWINDOW：原本强制显示在任务栏
        user32.SetWindowLongPtrW(
            hwnd, GWL_EXSTYLE,
            (int(ex) | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW)
        user32.ShowWindow(hwnd, SW_HIDE)

        recs.append({
            "hwnd": int(hwnd),
            "ex": int(ex),
            "show": int(wp.showCmd) if has_wp else SW_SHOWNORMAL,
        })
    return recs


def show_windows(pid, recs=None):
    """按记录还原窗口；recs 为空则从临时文件读（脚本崩过一次也能恢复）。"""
    if recs is None:
        recs = load_records(pid)
    by_hwnd = {int(r["hwnd"]): r for r in recs}

    hwnds = set(by_hwnd)
    hwnds.update(windows_of(pid))

    restored = 0
    for hwnd in hwnds:
        if not user32.IsWindow(hwnd):
            continue
        r = by_hwnd.get(hwnd)
        if r:
            user32.SetWindowLongPtrW(hwnd, GWL_EXSTYLE, int(r["ex"]))
            cmd = int(r.get("show") or SW_SHOWNORMAL)
            if cmd not in (SW_SHOWNORMAL, SW_SHOWMINIMIZED, SW_SHOWMAXIMIZED):
                cmd = SW_SHOW
            user32.ShowWindow(hwnd, cmd)
            restored += 1
        if user32.IsWindowVisible(hwnd):
            add_tab(hwnd)
    drop_records(pid)
    return restored


# ---------------- 挂起 / 恢复 ----------------

def suspend_count(tid):
    """NtQueryInformationThread(ThreadSuspendCount=35) -> 该线程累计挂起次数。"""
    h = k32.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
    if not h:
        return None
    try:
        cnt = wt.ULONG(0)
        ret = wt.ULONG(0)
        st = ntdll.NtQueryInformationThread(
            h, 35, ctypes.byref(cnt), ctypes.sizeof(cnt), ctypes.byref(ret))
        return cnt.value if st == 0 else None
    finally:
        k32.CloseHandle(h)


def thread_suspend(tid):
    h = k32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        return False
    try:
        k32.SuspendThread(h)
        return True
    finally:
        k32.CloseHandle(h)


def thread_resume(tid):
    h = k32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not h:
        return False
    try:
        k32.ResumeThread(h)
        return True
    finally:
        k32.CloseHandle(h)


def full_suspend(pid):
    h = k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not h:
        return False, k32.GetLastError()
    try:
        return ntdll.NtSuspendProcess(h) == 0, 0
    finally:
        k32.CloseHandle(h)


def full_resume(pid):
    h = k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not h:
        return False, k32.GetLastError()
    try:
        return ntdll.NtResumeProcess(h) == 0, 0
    finally:
        k32.CloseHandle(h)


def keepui_suspend(pid):
    """挂起除窗口线程以外的所有线程（旧版策略，游戏上大概率无效）。"""
    alive = ui_threads(pid)
    done = 0
    for tid in thread_ids(pid):
        if tid in alive:
            continue
        if thread_suspend(tid):
            done += 1
    return done


def keepui_resume(pid):
    """把挂起次数 >0 的线程按次数归零。"""
    done = 0
    for tid in thread_ids(pid):
        n = suspend_count(tid) or 0
        for _ in range(n):
            if not thread_resume(tid):
                break
        if n:
            done += 1
    return done


# ---------------- 状态判定 ----------------

def state_of(pid, keep_ui=False):
    """返回 (running|suspended|partial|gone, 总线程数, 已挂起线程数)"""
    tids = thread_ids(pid)
    if not tids:
        return "gone", 0, 0
    alive = ui_threads(pid) if keep_ui else set()
    considered = [t for t in tids if t not in alive] or tids
    susp = 0
    for tid in considered:
        n = suspend_count(tid)
        if n is not None and n > 0:
            susp += 1
    if susp == 0:
        return "running", len(considered), 0
    if susp == len(considered):
        return "suspended", len(considered), susp
    return "partial", len(considered), susp


# ---------------- 主流程 ----------------

def parse_args(argv):
    cfg = {
        "target": TARGET,
        "hide": HIDE_WINDOW,
        "full": FULL_SUSPEND,
        "list": False,
        "elevated": False,
        "pids": [],
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--target" and i + 1 < len(argv):
            cfg["target"] = argv[i + 1]
            i += 1
        elif a == "--pid" and i + 1 < len(argv):
            cfg["pids"].append(int(argv[i + 1]))
            i += 1
        elif a == "--no-hide":
            cfg["hide"] = False
        elif a == "--keep-ui":
            cfg["full"] = False
        elif a == "--list":
            cfg["list"] = True
        elif a == "--elevated":
            cfg["elevated"] = True
        i += 1
    return cfg


def do_suspend(pid, cfg):
    """执行冻结；失败则立即把藏起来的窗口还原，避免用户面对一个消失的程序。"""
    recs = []
    if cfg["hide"]:
        recs = hide_windows(pid)
        save_records(pid, recs)
        if recs:
            time.sleep(0.15)   # 等任务栏按钮真的消失，再冻结

    if cfg["full"]:
        ok, err = full_suspend(pid)
    else:
        n = keepui_suspend(pid)
        ok, err = (n > 0), 0

    if not ok:
        show_windows(pid, recs)
        return False, err, len(recs)
    return True, 0, len(recs)


def do_resume(pid, cfg):
    if cfg["full"]:
        full_resume(pid)
    else:
        keepui_resume(pid)
    time.sleep(0.15)
    n = show_windows(pid)
    return n


def main():
    cfg = parse_args(sys.argv[1:])
    target = cfg["target"]

    if not target:
        print("[错误] 请先设置 TARGET 进程名。")
        return 1

    if ELEVATE and not is_admin() and not cfg["elevated"]:
        print("需要管理员权限，正在提权……")
        if elevate():
            return 0
        print("[警告] 提权失败或取消，继续以当前权限运行。")

    enable_debug_privilege()

    admin = is_admin()
    print(f"目标：{target}   权限：{'管理员' if admin else '普通用户'}")
    pids = list(cfg["pids"]) if cfg["pids"] else find_pids(target)
    if not pids:
        print(f"[未找到] 没有正在运行的 {target} 进程。")
        return 1

    print(f"找到 {len(pids)} 个实例：{', '.join(map(str, pids))}")

    if cfg["list"]:
        for pid in pids:
            st, total, susp = state_of(pid, not cfg["full"])
            wins = windows_of(pid, visible_only=True)
            hwnd = main_window(pid)
            title = window_title(hwnd) if hwnd else ""
            print(f"  PID {pid}: {st}  线程 {susp}/{total} 已挂起  "
                  f"可见窗口 {len(wins)} 个  \"{title}\"")
        return 0

    states = [state_of(pid, not cfg["full"])[0] for pid in pids]
    if all(s == "gone" for s in states):
        print("[未找到] 进程都退出了。")
        return 1

    # ---- 恢复 ----
    if all(s == "suspended" for s in states):
        print("状态：已雪藏 —— 正在解冻……")
        for pid in pids:
            n = do_resume(pid, cfg)
            print(f"  PID {pid}: 已恢复，窗口还原 {n} 个")
        print("[OK] 已恢复运行。")
        return 0

    # ---- 统一冻结 ----
    if not all(s == "running" for s in states):
        print("状态：部分挂起 —— 先全部恢复再统一冻结（避免计数叠加）。")
        for pid in pids:
            do_resume(pid, cfg)
        time.sleep(0.3)

    print("正在雪藏……" if cfg["hide"] else "正在冻结……")
    failed = 0
    for pid in pids:
        ok, err, hidden = do_suspend(pid, cfg)
        if ok:
            tag = f"隐藏 {hidden} 个窗口，" if cfg["hide"] else ""
            print(f"  PID {pid}: 已完全冻结（{tag}已从任务栏摘除）")
        else:
            failed += 1
            print(f"  PID {pid}: 失败(errno={err})，窗口已还原")

    if failed == len(pids):
        return 1
    print("[OK] 已完成。再运行一次本脚本即可解冻还原。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
