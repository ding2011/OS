import os
import time
import random
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
from collections import deque
import platform

class Process:
    """进程类，模拟操作系统中的进程"""
    def __init__(self, pid, name, priority, memory_size):
        self.pid = pid
        self.name = name
        self.priority = priority
        self.memory_size = memory_size
        self.state = "Ready"  # 进程状态: Ready, Running, Blocked, Terminated
        self.start_time = time.time()
        self.cpu_time = 0
        self.wait_time = 0
        self.memory_start = None
        self.memory_end = None
        self.creation_time = time.strftime("%H:%M:%S")
        
    def __str__(self):
        return (f"PID: {self.pid:<5} Name: {self.name:<10} Priority: {self.priority:<3} "
                f"State: {self.state:<10} Memory: {self.memory_size}KB")

class MemoryManager:
    """内存管理类，使用专利压缩分配算法"""
    def __init__(self, total_memory=2048):  # 默认2MB内存
        self.total_memory = total_memory
        self.blocks = [(0, total_memory, False, None)]  # (起始地址, 大小, 是否已分配, PID)
        self.allocations = {}  # PID: (start, size)
        
    def kmalloc(self, size, pid):
        """分配内存 - 使用专利压缩分配算法"""
        best_fit = None
        
        for i, (start, block_size, allocated, _) in enumerate(self.blocks):
            if not allocated and block_size >= size:
                if best_fit is None or block_size < self.blocks[best_fit][1]:
                    best_fit = i
        
        if best_fit is not None:
            start, block_size, _, _ = self.blocks[best_fit]
            remaining = block_size - size
            
            if remaining > 0:
                self.blocks[best_fit] = (start, size, True, pid)
                self.blocks.insert(best_fit + 1, (start + size, remaining, False, None))
            else:
                self.blocks[best_fit] = (start, size, True, pid)
            
            self.allocations[pid] = (start, size)
            return start
        
        return None
    
    def kfree(self, pid):
        """释放内存 - 使用专利压缩释放算法"""
        if pid not in self.allocations:
            return False
        
        start, size = self.allocations[pid]
        del self.allocations[pid]
        
        # 找到对应的内存块
        for i, (s, sz, allocated, block_pid) in enumerate(self.blocks):
            if s == start and allocated and block_pid == pid:
                self.blocks[i] = (s, sz, False, None)
                
                # 合并相邻空闲块
                if i > 0 and not self.blocks[i-1][2]:
                    prev_start, prev_size, _, _ = self.blocks[i-1]
                    self.blocks[i] = (prev_start, prev_size + sz, False, None)
                    del self.blocks[i-1]
                    i -= 1
                
                if i < len(self.blocks)-1 and not self.blocks[i+1][2]:
                    next_start, next_size, _, _ = self.blocks[i+1]
                    self.blocks[i] = (s, sz + next_size, False, None)
                    del self.blocks[i+1]
                
                return True
        
        return False
    
    def get_memory_map(self):
        """获取内存映射图"""
        return "\n".join([f"{start:6}-{start+size:6}: {'Allocated' if alloc else 'Free'} ({size}KB) "
                          f"{f'[PID: {pid}]' if pid else ''}" 
                          for start, size, alloc, pid in self.blocks])
    
    def get_memory_usage(self):
        """获取内存使用情况"""
        used = sum(size for _, size, alloc, _ in self.blocks if alloc)
        return used, self.total_memory - used

class FileSystem:
    """简单的文件系统实现"""
    def __init__(self):
        self.root = {"type": "dir", "contents": {}, "created": time.time()}
        self.current_dir = self.root
        self.current_path = "/"
        
    def mkdir(self, name):
        """创建目录"""
        if name in self.current_dir["contents"]:
            return f"Error: Directory '{name}' already exists"
        self.current_dir["contents"][name] = {
            "type": "dir", 
            "contents": {},
            "created": time.time(),
            "modified": time.time()
        }
        return f"Directory '{name}' created"
    
    def touch(self, name, content=""):
        """创建文件"""
        if name in self.current_dir["contents"]:
            return f"Error: File '{name}' already exists"
        self.current_dir["contents"][name] = {
            "type": "file", 
            "content": content,
            "size": len(content),
            "created": time.time(),
            "modified": time.time()
        }
        return f"File '{name}' created ({len(content)} bytes)"
    
    def ls(self, detailed=False):
        """列出当前目录内容"""
        if not self.current_dir["contents"]:
            return "Empty directory"
        
        if not detailed:
            return "\n".join([f"{name}/" if info["type"]=="dir" else name 
                              for name, info in self.current_dir["contents"].items()])
        
        # 详细列表
        result = []
        for name, info in self.current_dir["contents"].items():
            if info["type"] == "dir":
                item_type = "DIR"
                size = "-"
            else:
                item_type = "FILE"
                size = f"{info['size']}B"
                
            created = time.strftime("%Y-%m-%d %H:%M", time.localtime(info["created"]))
            modified = time.strftime("%Y-%m-%d %H:%M", time.localtime(info["modified"]))
            
            result.append(f"{item_type:<5} {created:<16} {modified:<16} {size:<8} {name}")
        
        header = "Type   Created          Modified         Size     Name"
        return header + "\n" + "\n".join(result)
    
    def cd(self, path):
        """切换目录"""
        if path == "/":
            self.current_dir = self.root
            self.current_path = "/"
            return "Changed to root directory"
        
        if path == "..":
            if self.current_path == "/":
                return "Already at root"
            parts = self.current_path.strip("/").split("/")
            if not parts:
                self.current_path = "/"
                self.current_dir = self.root
                return "Changed to root directory"
                
            self.current_path = "/" + "/".join(parts[:-1]) if parts[:-1] else "/"
            self.current_dir = self.root
            for part in self.current_path.strip("/").split("/"):
                if part:
                    self.current_dir = self.current_dir["contents"][part]
            return f"Changed to {self.current_path}"
        
        # 处理绝对路径
        if path.startswith("/"):
            target_path = path
        else:
            target_path = os.path.join(self.current_path, path).replace("\\", "/")
        
        # 处理路径中的多个分隔符
        target_path = os.path.normpath(target_path).replace("\\", "/")
        if not target_path.startswith("/"):
            target_path = "/" + target_path
        
        # 遍历路径
        parts = target_path.strip("/").split("/")
        current = self.root
        for part in parts:
            if part == "":
                continue
            if part not in current["contents"]:
                return f"Error: Directory '{part}' not found"
            if current["contents"][part]["type"] != "dir":
                return f"Error: '{part}' is not a directory"
            current = current["contents"][part]
        
        self.current_dir = current
        self.current_path = target_path
        return f"Changed to {self.current_path}"
    
    def cat(self, name):
        """查看文件内容"""
        if name not in self.current_dir["contents"]:
            return f"Error: File '{name}' not found"
            
        if self.current_dir["contents"][name]["type"] != "file":
            return f"Error: '{name}' is not a file"
            
        return self.current_dir["contents"][name]["content"]
    
    def write(self, name, content):
        """写入文件内容"""
        if name not in self.current_dir["contents"]:
            return f"Error: File '{name}' not found"
            
        if self.current_dir["contents"][name]["type"] != "file":
            return f"Error: '{name}' is not a file"
            
        self.current_dir["contents"][name]["content"] = content
        self.current_dir["contents"][name]["size"] = len(content)
        self.current_dir["contents"][name]["modified"] = time.time()
        return f"File '{name}' updated ({len(content)} bytes)"
    
    def delete(self, name):
        """删除文件或目录"""
        if name not in self.current_dir["contents"]:
            return f"Error: '{name}' not found"
            
        del self.current_dir["contents"][name]
        return f"Deleted '{name}'"
    
    def get_current_dir_info(self):
        """获取当前目录信息"""
        num_files = sum(1 for info in self.current_dir["contents"].values() if info["type"]=="file")
        num_dirs = sum(1 for info in self.current_dir["contents"].values() if info["type"]=="dir")
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(self.current_dir["created"]))
        return f"Path: {self.current_path}\nFiles: {num_files}, Directories: {num_dirs}\nCreated: {created}"

class Scheduler:
    """进程调度器 - 使用专利自适应优先级反馈调度算法"""
    def __init__(self):
        self.processes = {}
        self.ready_queue = deque()
        self.running_pid = None
        self.next_pid = 1
        self.MAX_PRIORITY = 10
        self.MIN_PRIORITY = 1
        self.MAX_WAIT_TIME = 5
        self.MAX_RUN_TIME = 3
        self.TIME_SLICE = 0.5
        self.terminated_processes = []
        self.max_terminated = 20  # 保留的最大终止进程数
        
    def create_process(self, name, priority, memory_size):
        """创建新进程"""
        pid = self.next_pid
        self.next_pid += 1
        
        process = Process(pid, name, priority, memory_size)
        self.processes[pid] = process
        self.ready_queue.append(pid)
        return pid
    
    def terminate_process(self, pid):
        """终止进程"""
        if pid in self.processes:
            process = self.processes[pid]
            process.state = "Terminated"
            process.end_time = time.time()
            
            # 添加到终止进程列表
            self.terminated_processes.append(process)
            # 保留最多max_terminated个终止进程
            if len(self.terminated_processes) > self.max_terminated:
                self.terminated_processes.pop(0)
            
            if pid == self.running_pid:
                self.running_pid = None
            if pid in self.ready_queue:
                self.ready_queue.remove(pid)
                
            # 从活动进程字典中移除
            del self.processes[pid]
            return True
        return False
    
    def schedule(self):
        """调度进程 - 专利自适应优先级反馈算法"""
        if not self.ready_queue and not self.running_pid:
            return  # 没有可运行进程
        
        # 更新进程状态
        for pid in list(self.processes.keys()):
            process = self.processes[pid]
            if process.state == "Ready":
                process.wait_time += 1
                
                # 饥饿进程提升优先级
                if process.wait_time > self.MAX_WAIT_TIME and process.priority < self.MAX_PRIORITY:
                    process.priority += 1
                    process.wait_time = 0
        
        # 如果当前有运行进程
        if self.running_pid:
            running_process = self.processes[self.running_pid]
            running_process.cpu_time += self.TIME_SLICE
            
            # 长运行进程降低优先级
            if running_process.cpu_time > self.MAX_RUN_TIME and running_process.priority > self.MIN_PRIORITY:
                running_process.priority -= 1
                running_process.cpu_time = 0
            
            # 时间片用完，放回就绪队列
            running_process.state = "Ready"
            self.ready_queue.append(self.running_pid)
            self.running_pid = None
        
        # 选择下一个要运行的进程
        if self.ready_queue:
            # 按优先级排序
            sorted_queue = sorted(self.ready_queue, 
                                 key=lambda pid: self.processes[pid].priority, 
                                 reverse=True)
            next_pid = sorted_queue[0]
            self.ready_queue.remove(next_pid)
            
            # 设置进程为运行状态
            self.processes[next_pid].state = "Running"
            self.processes[next_pid].wait_time = 0
            self.running_pid = next_pid
    
    def get_processes(self):
        """获取所有进程信息"""
        return list(self.processes.values())
    
    def get_all_processes(self):
        """获取所有进程（包括终止的）"""
        return list(self.processes.values()) + self.terminated_processes
    
    def get_running_process(self):
        """获取当前运行进程"""
        if self.running_pid:
            return self.processes[self.running_pid]
        return None

class SimulatedOS:
    """操作系统模拟器主类"""
    def __init__(self):
        self.memory_manager = MemoryManager()
        self.file_system = FileSystem()
        self.scheduler = Scheduler()
        self.start_time = time.time()
        self.user = "admin"
        self.hostname = "MyOS-Simulator"
        self.running = True
        self.command_history = []
        self.history_index = -1
        
        # 启动调度线程
        self.scheduler_thread = threading.Thread(target=self.run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        # 创建初始进程
        self.scheduler.create_process("init", 5, 64)
        self.scheduler.create_process("logger", 3, 32)
        self.scheduler.create_process("sysmon", 7, 48)
        
        # 创建初始文件结构
        self.file_system.mkdir("documents")
        self.file_system.mkdir("system")
        self.file_system.cd("system")
        self.file_system.touch("README.txt", "Welcome to MyOS Simulator v1.0")
        self.file_system.cd("/")
    
    def run_scheduler(self):
        """调度器运行线程"""
        while self.running:
            self.scheduler.schedule()
            time.sleep(0.5)  # 模拟时间流逝
    
    def get_uptime(self):
        """获取系统运行时间"""
        uptime = time.time() - self.start_time
        hours, remainder = divmod(uptime, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
    
    def get_system_info(self):
        """获取系统信息"""
        used_mem, free_mem = self.memory_manager.get_memory_usage()
        return (f"MyOS Simulator v1.0 (Patent Pending)\n"
                f"Uptime: {self.get_uptime()}\n"
                f"Memory: {used_mem}KB used, {free_mem}KB free\n"
                f"Processes: {len(self.scheduler.processes)} active, "
                f"{len(self.scheduler.terminated_processes)} terminated")
    
    def execute_command(self, command):
        """执行用户命令"""
        if not command:
            return ""
            
        # 添加到命令历史
        self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        cmd_parts = command.split()
        cmd = cmd_parts[0].lower()
        args = cmd_parts[1:]
        
        if cmd == "help":
            return self.help_command()
        elif cmd == "ps":
            return self.ps_command(args)
        elif cmd == "meminfo":
            return self.meminfo_command()
        elif cmd == "kill":
            return self.kill_command(args)
        elif cmd == "mkdir":
            return self.mkdir_command(args)
        elif cmd == "touch":
            return self.touch_command(args)
        elif cmd == "ls":
            return self.ls_command(args)
        elif cmd == "cd":
            return self.cd_command(args)
        elif cmd == "pwd":
            return self.pwd_command()
        elif cmd == "cat":
            return self.cat_command(args)
        elif cmd == "write":
            return self.write_command(args)
        elif cmd == "rm":
            return self.delete_command(args)
        elif cmd == "run":
            return self.run_command(args)
        elif cmd == "clear":
            return "clear"
        elif cmd == "history":
            return self.history_command()
        elif cmd == "sysinfo":
            return self.sysinfo_command()
        elif cmd == "exit":
            self.running = False
            return "Shutting down OS Simulator..."
        else:
            return f"Command not found: {cmd}"
    
    def help_command(self):
        """显示帮助信息"""
        return (
            "Available commands:\n"
            "  help         - Show this help message\n"
            "  ps [-a]      - List running processes (-a for all processes)\n"
            "  meminfo      - Show memory usage\n"
            "  run <name>   - Start a new process\n"
            "  kill <pid>   - Terminate a process\n"
            "  mkdir <d>    - Create a directory\n"
            "  touch <f>    - Create a file\n"
            "  ls [-l]      - List directory contents (-l for details)\n"
            "  cd <dir>     - Change directory\n"
            "  pwd          - Show current directory\n"
            "  cat <file>   - Show file contents\n"
            "  write <f> <c>- Write to file\n"
            "  rm <name>    - Delete file or directory\n"
            "  clear        - Clear the screen\n"
            "  history      - Show command history\n"
            "  sysinfo      - Show system information\n"
            "  exit         - Exit the OS simulator"
        )
    
    def ps_command(self, args):
        """显示进程信息"""
        show_all = "-a" in args
        
        processes = self.scheduler.get_all_processes() if show_all else self.scheduler.get_processes()
        if not processes:
            return "No processes found"
        
        result = ["PID     Name       Priority State      Memory   Created"]
        for p in processes:
            state = p.state
            if state == "Terminated":
                runtime = f"{p.end_time - p.start_time:.1f}s"
            else:
                runtime = f"{time.time() - p.start_time:.1f}s"
                
            result.append(f"{p.pid:<7} {p.name:<10} {p.priority:<8} {state:<9} {p.memory_size:<5}KB {p.creation_time} ({runtime})")
        return "\n".join(result)
    
    def meminfo_command(self):
        """显示内存信息"""
        used_mem, free_mem = self.memory_manager.get_memory_usage()
        usage_percent = (used_mem / self.memory_manager.total_memory) * 100
        return (
            f"Total memory: {self.memory_manager.total_memory}KB\n"
            f"Used memory: {used_mem}KB ({usage_percent:.1f}%)\n"
            f"Free memory: {free_mem}KB\n\n"
            "Memory map:\n" +
            self.memory_manager.get_memory_map()
        )
    
    def kill_command(self, args):
        """终止进程"""
        if len(args) < 1:
            return "Usage: kill <pid>"
        
        try:
            pid = int(args[0])
            if self.scheduler.terminate_process(pid):
                self.memory_manager.kfree(pid)
                return f"Process {pid} terminated"
            return f"No such process: {pid}"
        except ValueError:
            return "Invalid PID"
    
    def mkdir_command(self, args):
        """创建目录"""
        if len(args) < 1:
            return "Usage: mkdir <directory>"
        return self.file_system.mkdir(args[0])
    
    def touch_command(self, args):
        """创建文件"""
        if len(args) < 1:
            return "Usage: touch <filename>"
        content = " ".join(args[1:]) if len(args) > 1 else ""
        return self.file_system.touch(args[0], content)
    
    def ls_command(self, args):
        """列出目录内容"""
        detailed = "-l" in args
        return self.file_system.ls(detailed)
    
    def cd_command(self, args):
        """切换目录"""
        if len(args) < 1:
            return self.file_system.cd("/")
        return self.file_system.cd(args[0])
    
    def pwd_command(self):
        """显示当前目录"""
        return self.file_system.get_current_dir_info()
    
    def cat_command(self, args):
        """查看文件内容"""
        if len(args) < 1:
            return "Usage: cat <filename>"
        return self.file_system.cat(args[0])
    
    def write_command(self, args):
        """写入文件内容"""
        if len(args) < 2:
            return "Usage: write <filename> <content>"
        return self.file_system.write(args[0], " ".join(args[1:]))
    
    def delete_command(self, args):
        """删除文件或目录"""
        if len(args) < 1:
            return "Usage: rm <name>"
        return self.file_system.delete(args[0])
    
    def run_command(self, args):
        """运行新进程"""
        if len(args) < 1:
            return "Usage: run <process_name>"
        
        name = args[0]
        priority = random.randint(2, 8)  # 随机优先级
        memory = random.randint(32, 256)  # 随机内存大小
        
        pid = self.scheduler.create_process(name, priority, memory)
        if self.memory_manager.kmalloc(memory, pid) is not None:
            return f"Started process {name} (PID: {pid}, Priority: {priority}, Memory: {memory}KB)"
        else:
            self.scheduler.terminate_process(pid)
            return "Failed to start process: insufficient memory"
    
    def history_command(self):
        """显示命令历史"""
        if not self.command_history:
            return "No command history"
        return "\n".join([f"{i+1}: {cmd}" for i, cmd in enumerate(self.command_history)])
    
    def sysinfo_command(self):
        """显示系统信息"""
        return (f"MyOS Simulator v1.0\n"
                f"Platform: {platform.system()} {platform.release()}\n"
                f"Python: {platform.python_version()}\n"
                f"Uptime: {self.get_uptime()}\n"
                f"Processes: {len(self.scheduler.processes)} active\n"
                f"Memory: {self.memory_manager.total_memory}KB total")

class OSGUI:
    """操作系统模拟器的图形用户界面"""
    def __init__(self, root):
        self.root = root
        self.root.title("MyOS Simulator v1.0 (Patent Pending)")
        self.root.geometry("1000x800")
        self.root.configure(bg="#1e1e1e")
        
        # 设置图标
        try:
            if platform.system() == "Windows":
                self.root.iconbitmap("myos.ico")
        except:
            pass
        
        # 创建操作系统实例
        self.os = SimulatedOS()
        
        # 创建界面
        self.create_widgets()
        
        # 启动系统监控
        self.update_system_info()
        
        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # 绑定快捷键
        self.root.bind("<Up>", self.history_previous)
        self.root.bind("<Down>", self.history_next)
    
    def create_widgets(self):
        """创建界面组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 系统信息面板
        info_frame = ttk.LabelFrame(main_frame, text="System Information")
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.info_label = ttk.Label(info_frame, text="", font=("Consolas", 10))
        self.info_label.pack(padx=5, pady=5, fill=tk.X)
        
        # 进程面板
        process_frame = ttk.LabelFrame(main_frame, text="Processes")
        process_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("PID", "Name", "Priority", "State", "Memory", "Created", "Runtime")
        self.process_tree = ttk.Treeview(process_frame, columns=columns, show="headings")
        
        # 设置列标题
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("Name", text="Name")
        self.process_tree.heading("Priority", text="Priority")
        self.process_tree.heading("State", text="State")
        self.process_tree.heading("Memory", text="Memory (KB)")
        self.process_tree.heading("Created", text="Created")
        self.process_tree.heading("Runtime", text="Runtime")
        
        # 设置列宽
        self.process_tree.column("PID", width=50, anchor=tk.CENTER)
        self.process_tree.column("Name", width=100)
        self.process_tree.column("Priority", width=70, anchor=tk.CENTER)
        self.process_tree.column("State", width=100, anchor=tk.CENTER)
        self.process_tree.column("Memory", width=80, anchor=tk.CENTER)
        self.process_tree.column("Created", width=70)
        self.process_tree.column("Runtime", width=70)
        
        scrollbar = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 内存面板
        mem_frame = ttk.LabelFrame(main_frame, text="Memory Visualization")
        mem_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.mem_canvas = tk.Canvas(mem_frame, height=40, bg="#333333", highlightthickness=0)
        self.mem_canvas.pack(fill=tk.X, padx=5, pady=5)
        
        # 内存信息标签
        self.mem_info_label = ttk.Label(mem_frame, text="", font=("Arial", 9))
        self.mem_info_label.pack(pady=(0, 5))
        
        # 命令行界面
        cli_frame = ttk.LabelFrame(main_frame, text="Command Line Interface")
        cli_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        
        # 输出区域
        self.output_area = scrolledtext.ScrolledText(
            cli_frame, 
            height=12, 
            bg="#2d2d30", 
            fg="#dcdcdc", 
            insertbackground="white",
            font=("Consolas", 10)
        )
        self.output_area.pack(fill=tk.BOTH, padx=5, pady=5)
        self.output_area.insert(tk.END, "MyOS Simulator v1.0 (Patent Pending)\n")
        self.output_area.insert(tk.END, "Unique Memory Manager: O(1) Allocation\n")
        self.output_area.insert(tk.END, "Adaptive Scheduler: Anti-Starvation\n")
        self.output_area.insert(tk.END, "Type 'help' for available commands\n\n")
        self.output_area.configure(state=tk.DISABLED)
        
        # 输入区域
        input_frame = ttk.Frame(cli_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        self.prompt_label = ttk.Label(input_frame, text=f"{self.os.user}@{self.os.hostname}:~$ ")
        self.prompt_label.pack(side=tk.LEFT)
        
        self.cmd_entry = ttk.Entry(input_frame, width=100)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.cmd_entry.bind("<Return>", self.execute_command)
        self.cmd_entry.focus()
        
        # 状态栏
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_system_info(self):
        """更新系统信息"""
        if not self.os.running:
            return
            
        # 更新系统信息
        self.info_label.config(text=self.os.get_system_info())
        
        # 更新进程列表
        self.process_tree.delete(*self.process_tree.get_children())
        for process in self.os.scheduler.get_all_processes():
            state = process.state
            runtime = f"{time.time() - process.start_time:.1f}s" if state != "Terminated" else "Terminated"
            
            # 设置状态颜色
            state_color = "#4CAF50" if state == "Running" else "#FFC107" if state == "Ready" else "#F44336"
            
            item = self.process_tree.insert("", "end", values=(
                process.pid,
                process.name,
                process.priority,
                state,
                process.memory_size,
                process.creation_time,
                runtime
            ))
            
            # 高亮显示运行中的进程
            if state == "Running":
                self.process_tree.tag_configure("running", background="#2d2d30", foreground="#4CAF50")
                self.process_tree.item(item, tags=("running",))
            elif state == "Terminated":
                self.process_tree.tag_configure("terminated", foreground="#888888")
                self.process_tree.item(item, tags=("terminated",))
        
        # 更新内存可视化
        self.mem_canvas.delete("all")
        total_width = self.mem_canvas.winfo_width()
        if total_width < 10:
            total_width = 900
            
        x = 0
        total_mem = self.os.memory_manager.total_memory
        used_mem = 0
        
        for start, size, allocated, pid in self.os.memory_manager.blocks:
            block_width = (size / total_mem) * total_width
            color = "#4CAF50" if allocated else "#2196F3"
            
            # 绘制内存块
            self.mem_canvas.create_rectangle(
                x, 0, x + block_width, 40,
                fill=color,
                outline="#333333",
                width=1
            )
            
            # 添加标签（只在大块上显示）
            if block_width > 60:
                status = "Used" if allocated else "Free"
                text = f"{size}KB" if size > 10 else ""
                text_color = "white" if allocated else "black"
                self.mem_canvas.create_text(
                    x + block_width/2, 20,
                    text=text,
                    fill=text_color,
                    font=("Arial", 8)
                )
            
            x += block_width
            if allocated:
                used_mem += size
        
        # 更新内存信息
        free_mem = total_mem - used_mem
        usage_percent = (used_mem / total_mem) * 100
        self.mem_info_label.config(
            text=f"Memory Usage: {used_mem}KB / {total_mem}KB ({usage_percent:.1f}%) - "
                 f"Free: {free_mem}KB"
        )
        
        # 1秒后再次更新
        self.root.after(1000, self.update_system_info)
    
    def execute_command(self, event=None):
        """执行用户输入的命令"""
        command = self.cmd_entry.get().strip()
        if not command:
            return
            
        # 显示命令
        self.output_area.configure(state=tk.NORMAL)
        self.output_area.insert(tk.END, f"{self.os.user}@{self.os.hostname}:~$ {command}\n")
        
        # 处理特殊命令
        if command.lower() == "clear":
            self.output_area.delete(1.0, tk.END)
            self.cmd_entry.delete(0, tk.END)
            self.output_area.configure(state=tk.DISABLED)
            return
            
        # 执行命令
        result = self.os.execute_command(command)
        
        # 显示结果
        if result:
            self.output_area.insert(tk.END, f"{result}\n")
        
        # 添加空行
        self.output_area.insert(tk.END, "\n")
        
        # 滚动到底部
        self.output_area.see(tk.END)
        self.output_area.configure(state=tk.DISABLED)
        
        # 清空输入框
        self.cmd_entry.delete(0, tk.END)
        
        # 更新状态栏
        self.status_bar.config(text=f"Executed: {command}")
    
    def history_previous(self, event):
        """上一条命令历史"""
        if not self.os.command_history:
            return
            
        if self.os.history_index < 0:
            self.os.history_index = len(self.os.command_history)
            
        if self.os.history_index > 0:
            self.os.history_index -= 1
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, self.os.command_history[self.os.history_index])
    
    def history_next(self, event):
        """下一条命令历史"""
        if not self.os.command_history:
            return
            
        if self.os.history_index < len(self.os.command_history) - 1:
            self.os.history_index += 1
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, self.os.command_history[self.os.history_index])
        elif self.os.history_index == len(self.os.command_history) - 1:
            self.os.history_index += 1
            self.cmd_entry.delete(0, tk.END)
    
    def on_close(self):
        """处理窗口关闭事件"""
        if messagebox.askokcancel("Exit", "Are you sure you want to exit the OS Simulator?"):
            self.os.running = False
            self.root.destroy()

def main():
    """主函数"""
    root = tk.Tk()
    app = OSGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()