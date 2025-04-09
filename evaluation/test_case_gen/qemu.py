import random
import tempfile
import time
import psutil
from util import attach
# from pwnlib.gdb import Gdb
from pwnlib import gdb
from util import Gdb_background
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib import atexit
from pwnlib.tubes.tube import tube
from pwnlib.tubes.ssh import ssh
from pwnlib.util.proc import name
from pwnlib.ui import pause

import os
import signal
import subprocess
import pty
from functools import wraps


log = getLogger("pwnlib.custom.qemu")

class ptytube(tube):
    def __init__(self, command, timeout=10000, level=None, *a, **kw):
        super().__init__(timeout, level, *a, **kw)
        self.cmd = command
        master, slave = pty.openpty()
        p = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
        log.debug(f"PID {p.pid} Setup {command}")
        self.pid = p.pid
        self.process = p

        def kill():
            try:
                os.kill(p.pid, signal.SIGTERM)
            except OSError:
                print("kill error")
        
        self._exit_item = atexit.register(kill)
        self.close_fn = kill
        self.master = master
        self.slave = slave
        # self._newline = b"\r\r\n"
        
        with log.waitfor("Waiting qemu setup") as l:
            with context.local(log_level='info'):
                while True:
                    line = self.recvline(timeout=1)
                    if b"Booting the kernel" in line:
                        break
                    l.status(f"{line.strip()!r}")

                while True:
                    line = self.recvline(timeout=1)
                    # print(line)
                    if b"Debian GNU/Linux 11 syzkaller ttyS0" in line:
                        break
                    # tmp = line.strip().replace(b'\r\r\n', b'').replace(b'\r\n', b'').replace(b'\r', b'').decode()
                    tmp = line.strip().decode()
                    l.status(tmp)
                l.success()
        

    def send_raw(self, data):
        # return super().send_raw(data)
        return os.write(self.master, data)
    
    def recv_raw(self, numb):
        return os.read(self.master, numb)
    
    def close(self):
        while True:
            try:
                self.close_fn()
                self.process.wait()
                name(self.pid)
                time.sleep(0.5)
            except psutil.NoSuchProcess:
                log.debug(f"PID {self.pid} closed.")
                break
        atexit.unregister(self._exit_item)
        
AIPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
def getRandom(k=5):
    return "".join(random.choices(AIPHABET, k=k))

class Qemu:

    def __init__(self, qemu_path, argv: list, image_key_file: str) -> None:
        self.cmd = [qemu_path] + argv + ['-gdb','tcp:localhost:1234']
        self.qemu: ptytube = None
        self.key_file = image_key_file
        self.ssh: ssh = None
        self.gdb_pid = -1
        self.gdb: Gdb_background = None

        # self.qemu = ptytube(argv)

    
    @staticmethod
    def use_ssh(func):
        @wraps(func)
        def inner(self, *args, **kwargs):
            if not self.ssh:
                self.get_ssh()
            return func(self, *args, **kwargs)

        return inner
    
    @use_ssh
    def mktemp_name(self):
        return os.path.join(self.ssh.cwd, f"tmp.{getRandom(6)}")

    @staticmethod
    def check_pid_dead(pid: int):
        try:
            name(pid)
            return False
        except psutil.NoSuchProcess:
            return True

    def __enter__(self):
        self.qemu = ptytube(self.cmd)
        return self

    def __exit__(self, *argv):
        if self.ssh:
            self.ssh.close()
        if self.gdb:
            self.gdb.kill()
        self.qemu.close_fn()

    def get_ssh(self) -> ssh:
        if self.ssh:
            return self.ssh
        self.ssh = ssh("root", "127.0.0.1", 10021, keyfile=self.key_file)
        self.ssh.timeout = 2.0
        return self.ssh

    
    def get_gdb(self, gdbscript) -> Gdb_background:
        self.gdb_pid, self.gdb = attach(("localhost", 1234), 
                                        exe=self.cmd[0], 
                                        api=True,
                                        gdbscript=gdbscript)
        log.debug(f"GDB start in PID {self.gdb_pid}")
        return self.gdb
    
  

    @use_ssh
    def upload(self, src, dest):
        self.ssh.upload(src, dest)

    @use_ssh
    def _compile(self, src, dest, target):
        log.debug(f"Compile {src!r} => {dest!r} => {target!r}")
        self.upload(src, dest)
        # result, err = self.run_to_end(['gcc', dest, '-o', target])
        result, err = self.run_to_end(f"gcc {dest} -o {target} 2>&1")
        if err == 0:
            return (target, err)
        return (result, err)
    
    @use_ssh
    def compile(self, src): 
        filename = os.path.basename(src)
        dest_path = os.path.join(self.ssh.cwd, filename)
        target_path = os.path.join(self.ssh.cwd, filename.rstrip(".c"))
        return self._compile(src, dest_path, target_path)
    
    def compile_code(self, code: bytes): 
        with tempfile.NamedTemporaryFile(delete=True, suffix='.c') as fp:
            fp.write(code)
            fp.flush()
            return self.compile(fp.name)
        
    @use_ssh
    def run_to_end(self, process, tty = False, cwd = None, env = None, wd = None):
        return self.ssh.run_to_end(process, tty, cwd, env, wd)
    
    @use_ssh
    def change_workdir(self, wd):
        self.ssh.set_working_directory(wd)
    


    



# print(name(12345))
# os.system("kill -9 `pgrep qemu`")
# qemu = ptytube(["./start.sh"])
# qs = qemu.get_ssh()

# qs.upload("./tmp.c", "/root/tmp.c")

# io = qs.run_to_end(['gcc', '/root/tmp.c', '-o', '/root/tmp'])
# print(io)

# io = qs.system("/bin/bash", "/root")

# io.interactive()

# io.sendline(b"root")
# # io.sendlineafter(b"Debian GNU/Linux 11 syzkaller ttyS0", b"root")
# log.success(f"login success")
# context.log_level = 'debug'
# io.recvuntil(b"root@syzkaller")
# io.sendlineafter(b"#", b"ls /")
# # io.interactive()

# io.interactive()
# 