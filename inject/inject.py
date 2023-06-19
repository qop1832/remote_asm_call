import ctypes
from ctypes.wintypes import *
import pefile
import psutil
import pymem


class OPENFILENAMEA(ctypes.Structure):
    _fields_ = [
        ('lStructSize', DWORD),
        ('hwndOwner', HWND),
        ('hInstance', HINSTANCE),
        ('lpstrFilter', LPCSTR),
        ('lpstrCustomFilter', LPSTR),
        ('nMaxCustFilter', DWORD),
        ('nFilterIndex', DWORD),
        ('lpstrFile', LPSTR),
        ('nMaxFile', DWORD),
        ('lpstrFileTitle', LPSTR),
        ('nMaxFileTitle', DWORD),
        ('lpstrInitialDir', LPCSTR),
        ('lpstrTitle', LPCSTR),
        ('Flags', DWORD),
        ('nFileOffset', WORD),
        ('nFileExtension', WORD),
        ('lpstrDefExt', LPCSTR),
        ('lCustData', LPARAM),
        ('lpfnHook', ctypes.c_void_p),
        ('lpTemplateName', LPCSTR),
        ('pvReserved', ctypes.c_void_p),
        ('dwReserved', DWORD),
        ('FlagsEx', DWORD)
    ]


def is_process_64bit():
    """检查当前进程是否为64位"""
    return ctypes.sizeof(ctypes.c_voidp) * 8 == 64


def is_dll_64bit(dll_path):
    """检查DLL文件是否为64位"""
    try:
        pe = pefile.PE(dll_path)
        return pe.FILE_HEADER.Machine == 0x8664  # 0x8664 表示 x64 架构
    except pefile.PEFormatError:
        return False


def get_target_arch(pid):
    """获取目标进程的架构"""
    if not psutil.pid_exists(pid):
        raise RuntimeError("进程不存在")
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    process_handle = kernel32.OpenProcess(0x1000 | 0x400, False, pid)
    if not process_handle:
        raise RuntimeError("打开进程失败")

    is_wow64 = ctypes.c_bool()
    if kernel32.IsWow64Process(process_handle, ctypes.byref(is_wow64)):
        return "x86" if is_wow64.value else "x64"
    else:
        raise RuntimeError("无法确定目标架构")


def check_dll_process_architecture(pid, dll_path):
    """检查DLL文件位数与目标进程架构是否匹配"""
    target_arch = get_target_arch(pid)
    is_architecture_match = False

    if target_arch == "x64" and is_process_64bit() and is_dll_64bit(dll_path):
        is_architecture_match = True
    elif target_arch == "x86" and not is_process_64bit() and not is_dll_64bit(dll_path):
        is_architecture_match = True

    if target_arch == "x64":
        if is_process_64bit():
            if is_dll_64bit(dll_path):
                is_architecture_match = True
        else:
            raise RuntimeError("目标进程为x64架构，请使用64解释器运行此程序。")
    elif target_arch == "x86":
        if not is_process_64bit():
            if not is_dll_64bit(dll_path):
                is_architecture_match = True
        else:
            raise RuntimeError("目标进程为x86架构，请使用32解释器运行此程序。")

    return is_architecture_match


def is_module_loaded(pid, module_name):
    """检查目标进程是否加载了指定模块"""
    try:
        process = psutil.Process(pid)
        modules = process.memory_maps()
        for module in modules:
            if module.path and module_name.lower().decode() in module.path.lower():
                return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return False


def InjectDLL(target_pid, filename_dll):
    if is_module_loaded(target_pid, filename_dll):
        print("目标进程已注入指定的模块，请勿重复注入！")
        return
    if not check_dll_process_architecture(target_pid, filename_dll):
        raise RuntimeError("无效的 DLL 架构")
    print("正在注入 PID %d, process at %s" % (target_pid, filepath))
    # 打开目标进程的句柄，并设置权限
    target_handle = ctypes.windll.kernel32.OpenProcess(0x0002 | 0x0008 | 0x0010 | 0x0020, False, target_pid)
    # 在目标进程中分配一块内存，用于存放DLL路径
    dll_path_addr = ctypes.windll.kernel32.VirtualAllocEx(target_handle, None, len(filename_dll),
                                                          0x00001000 | 0x00002000, 0x04)
    # 将DLL路径写入目标进程的内存中
    ctypes.windll.kernel32.WriteProcessMemory(target_handle, dll_path_addr, filename_dll, len(filename_dll), None)
    # 获取Kernel32.dll的句柄，并获取LoadLibraryA函数的地址
    module_handle = ctypes.windll.kernel32.GetModuleHandleA(b"Kernel32")
    target_LoadLibraryA = ctypes.windll.kernel32.GetProcAddress(module_handle, b"LoadLibraryA")
    # 创建远程线程，用于调用LoadLibraryA函数加载DLL
    thread_handle = ctypes.windll.kernel32.CreateRemoteThread(target_handle, None, 0, ctypes.cast(target_LoadLibraryA,
                                                                                                  ctypes.CFUNCTYPE(
                                                                                                      DWORD, LPVOID)),
                                                              dll_path_addr, 0, None)
    # 等待远程线程结束
    ctypes.windll.kernel32.WaitForSingleObject(thread_handle, ctypes.c_uint(-1))
    # 获取远程线程的退出码
    exit_code = DWORD()
    ctypes.windll.kernel32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code))
    # 关闭句柄并释放内存
    try:
        ctypes.windll.kernel32.CloseHandle(thread_handle)
        ctypes.windll.kernel32.VirtualFreeEx(thread_handle, dll_path_addr, 0, 0x8000)
        ctypes.windll.kernel32.CloseHandle(target_handle)
    except OSError:
        # 如果发生错误，则返回错误信息
        raise RuntimeError("无法将 DLL 注入进程。")
    print("成功注入 PID %d, process at %s" % (target_pid, filename_dll))


def open_file_dialog():
    dll_path = ctypes.create_string_buffer(MAX_PATH)
    openfilename = OPENFILENAMEA()
    openfilename.lStructSize = ctypes.sizeof(OPENFILENAMEA)
    openfilename.hwndOwner = None
    openfilename.lpstrFile = ctypes.cast(dll_path, ctypes.c_char_p)
    openfilename.nMaxFile = ctypes.sizeof(dll_path)
    openfilename.lpstrFilter = b"All Files (*.*)\0*.*\0Dynamically Linked Library (*.dll)\0*.DLL\0"
    openfilename.nFilterIndex = 2
    openfilename.lpstrFileTitle = None
    openfilename.nMaxFileTitle = 0
    openfilename.lpstrInitialDir = None
    openfilename.Flags = 0x00000800 | 0x00001000
    result = ctypes.windll.comdlg32.GetOpenFileNameA(ctypes.byref(openfilename))
    if not result:
        print("CommDlgExtendedError: ", ctypes.windll.comdlg32.CommDlgExtendedError())
        return ctypes.windll.comdlg32.CommDlgExtendedError()
    else:
        LPARAM(ctypes.cast(dll_path, ctypes.c_void_p).value)
        print(dll_path.value)
        return dll_path.value


if __name__ == '__main__':
    target_pid = pymem.Pymem('WeChat.exe').process_id
    filepath = open_file_dialog()
    if filepath != 0:
        InjectDLL(target_pid, filepath)
