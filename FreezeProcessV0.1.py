#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FreezeProcessV0.1.py —— 进程挂起 / 恢复开关（纯 ctypes 实现，不依赖 pssuspend）

这是旧版：只冻结业务线程、保留窗口线程。普通程序可用，
但冻结游戏时会因为主线程等待被挂起的工作线程而弹"应用程序失去响应"。
冻结游戏请用 FreezeProcessV1.0.py。

用法：
    改下面的 TARGET 为进程名，然后运行：
        python FreezeProcessV0.1.py
    第一次运行 -> 挂起
    再运行一次 -> 恢复

命令行覆盖：
    python FreezeProcessV0.1.py --target notepad.exe
    python FreezeProcessV0.1.py --no-minimize      # 挂起前不最小化
    python FreezeProcessV0.1.py --list             # 只看状态不动手
"""

import ctypes
import ctypes.wintypes as wt
import os
import sys
import time

# ============================================================
#  唯一需要改的地方
# ============================================================
TARGET = "PBZ.exe"

MINIMIZE_FIRST = True      # 挂起前先最小化
KEEP_UI_THREAD = True      # True = 保留窗口线程，任务栏点击不会变红（推荐）
ELEVATE = True             # 需要时自动提权
# ============================================================

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

PROCESS_SUSPEND_RESUME = 0x0800
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPPROCESS = 0x00000002
SW_MINIMIZE = 6
SW_RESTORE = 9
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002

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


k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Process32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.Process32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]


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


k32.Thread32First.argtypes = [wt.HANDLE, ctypes.c_void_p]
k32.Thread32Next.argtypes = [wt.HANDLE, ctypes.c_void_p]

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
    """所有顶层窗口的窗口线程（这些线程必须活着，窗口才不会"未响应"）。"""
    tids = set()
    for hwnd in windows_of(pid):
        p = wt.DWORD()
        tids.add(user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p)))
    tids.discard(0)
    return tids


def minimize(hwnd):
    return bool(user32.ShowWindow(hwnd, SW_MINIMIZE))


def restore(hwnd):
    return bool(user32.ShowWindow(hwnd, SW_RESTORE))


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
    """挂起除窗口线程以外的所有线程：进程逻辑冻住，窗口仍能应答系统消息。"""
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
    """返回 (running|suspended|partial, 总线程数, 已挂起线程数)

    keep_ui=True 时，窗口线程本来就该保持运行，判定"已挂起"时要把它排除掉，
    否则 keep-ui 模式永远会被判成 partial。
    """
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
        "minimize": MINIMIZE_FIRST,
        "keep_ui": KEEP_UI_THREAD,
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
        elif a == "--no-minimize":
            cfg["minimize"] = False
        elif a == "--keep-ui":
            cfg["keep_ui"] = True
        elif a == "--list":
            cfg["list"] = True
        elif a == "--elevated":
            cfg["elevated"] = True
        i += 1
    return cfg


def main():
    cfg = parse_args(sys.argv[1:])
    target = cfg["target"]

    if not target:
        print("[错误] 请先设置 TARGET 进程名。")
        return 1

    # 提权
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
            st, total, susp = state_of(pid, cfg["keep_ui"])
            hwnd = main_window(pid)
            print(f"  PID {pid}: {st}  线程 {susp}/{total} 已挂起  hwnd={hwnd:#x}")
        return 0

    states = [state_of(pid, cfg["keep_ui"])[0] for pid in pids]
    if all(s == "gone" for s in states):
        print("[未找到] 进程都退出了。")
        return 1
    if all(s == "suspended" for s in states):
        action = "resume"
    elif all(s == "running" for s in states):
        action = "suspend"
    else:
        action = "normalize"

    # ---- 恢复 ----
    if action == "resume":
        print("状态：已挂起 —— 正在恢复……")
        if cfg["keep_ui"]:
            for pid in pids:
                n = keepui_resume(pid)
                print(f"  PID {pid}: 恢复 {n} 个线程")
        else:
            for pid in pids:
                ok, err = full_resume(pid)
                print(f"  PID {pid}: {'已恢复' if ok else f'失败(errno={err})'}")
        time.sleep(0.2)
        for pid in pids:
            hwnd = main_window(pid)
            if hwnd and user32.IsIconic(hwnd):
                restore(hwnd)   # 恢复后顺手还原窗口
        print("[OK] 已恢复运行。")
        return 0

    # ---- 统一挂起 ----
    if action == "normalize":
        print("状态：部分挂起 —— 先全部恢复再统一挂起（避免计数叠加）。")
        for pid in pids:
            if cfg["keep_ui"]:
                keepui_resume(pid)
            else:
                full_resume(pid)
        time.sleep(0.3)

    # 最小化：必须在挂起之前做，否则窗口线程已停，最小化会卡住
    if cfg["minimize"]:
        for pid in pids:
            hwnd = main_window(pid)
            if hwnd:
                minimize(hwnd)
        time.sleep(0.35)
        print("已最小化窗口。")

    print("正在挂起……")
    if cfg["keep_ui"]:
        for pid in pids:
            n = keepui_suspend(pid)
            print(f"  PID {pid}: 挂起 {n} 个线程，保留窗口线程（不会闪红）")
    else:
        for pid in pids:
            ok, err = full_suspend(pid)
            print(f"  PID {pid}: {'已挂起' if ok else f'失败(errno={err})'}")

    print("[OK] 已挂起。再运行一次本脚本即可恢复。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
