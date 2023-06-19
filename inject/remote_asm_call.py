import ctypes
from keystone import *


# pip install keystone-engine

def get_bytecode(asm_str, arch_mode="x86", bit=32):
    # 根据架构和位数选择适当的 Keystone 模式
    if arch_mode == "x86":
        ks_arch = KS_ARCH_X86
        if bit == 32:
            ks_mode = KS_MODE_32
        elif bit == 64:
            ks_mode = KS_MODE_64
        else:
            raise ValueError("Invalid bit value")
    else:
        raise ValueError("Invalid arch_mode")

    # 创建 Keystone 引擎实例
    ks = Ks(ks_arch, ks_mode)

    # 验证汇编代码的合法性
    try:
        ks.asm(asm_str)
    except KsError as e:
        raise ValueError(f"Invalid asm_str: {e}")

    # 汇编指令
    encoding, _ = ks.asm(asm_str)

    # 返回机器码
    return bytes(encoding)


class RemoteAsmCall:
    def __init__(self, process_id):
        self.process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, process_id)

    def __del__(self):
        if self.process_handle:
            self.close_process()

    def close_process(self):
        if self.process_handle:
            ctypes.windll.kernel32.CloseHandle(self.process_handle)
            self.process_handle = None

    def call(self, asm_code, wait_for_exit=True):
        asm_bytes = get_bytecode(asm_code)

        # 远程进程中申请内存;
        remote_mem = self._allocate_memory(len(asm_bytes))
        if not remote_mem:
            return False

        # 将注入代码写入到申请的内存中;
        if ctypes.windll.kernel32.WriteProcessMemory(self.process_handle, remote_mem, asm_bytes, len(asm_bytes),
                                                     None) == 0:
            return False
        # 远程内存地址转换为一个函数指针;
        remote_function = ctypes.CFUNCTYPE(ctypes.c_void_p)(remote_mem)

        # 创建远程线程执行注入代码;
        thread_handle = ctypes.windll.kernel32.CreateRemoteThread(self.process_handle, None, 0,
                                                                  ctypes.cast(remote_function, ctypes.c_void_p), None,
                                                                  0, None)
        if not thread_handle:
            return False
        # 等待线程执行完成;
        if wait_for_exit:
            ctypes.windll.kernel32.WaitForSingleObject(thread_handle, -1)

        # 释放申请的内存;
        self._free_memory(remote_mem)
        # 关闭线程和句柄;
        ctypes.windll.kernel32.CloseHandle(thread_handle)
        ctypes.windll.kernel32.CloseHandle(self.process_handle)

        return True

    def _allocate_memory(self, size):
        return ctypes.windll.kernel32.VirtualAllocEx(self.process_handle, None, size, 0x1000 | 0x2000, 0x40)

    def _free_memory(self, address):
        ctypes.windll.kernel32.VirtualFreeEx(self.process_handle, address, 0, 0x8000)


if __name__ == '__main__':
    asm_code = (f'''
    push {buffer}
    push 0
    push 1
    push {eax}
    push {content_addr}
    mov edx,{id_addr}
    mov ecx,{buffer}
    mov ebx,{call_entry}
    call ebx
    add esp,20
    ret
    ''')

    pid = 12345

    asm_call = RemoteAsmCall(pid)
    call_ret = asm_call.call(asm_code)
    asm_call.close_process()
