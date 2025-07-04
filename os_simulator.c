#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

// 定义常量
#define MAX_PROCESSES 32
#define MAX_MEMORY 2048 // 2MB
#define MAX_FILES 128
#define MAX_FILENAME 32
#define MAX_DIR_ENTRIES 32
#define MAX_PATH_LENGTH 256
#define MAX_COMMAND_LENGTH 256

// 进程状态枚举
typedef enum {
    READY,
    RUNNING,
    BLOCKED,
    TERMINATED
} ProcessState;

// 文件类型枚举
typedef enum {
    FILE_TYPE,
    DIR_TYPE
} FileType;

// 进程结构体
typedef struct {
    int pid;
    char name[32];
    int priority;
    int memory_size;
    ProcessState state;
    time_t start_time;
    time_t cpu_time;
    time_t wait_time;
    int memory_start;
    int memory_end;
} Process;

// 内存块结构体
typedef struct {
    int start;
    int size;
    bool allocated;
    int pid;
} MemoryBlock;

// 文件系统节点结构体
typedef struct FileNode {
    char name[MAX_FILENAME];
    FileType type;
    time_t created;
    time_t modified;
    union {
        struct {
            char *content;
            size_t size;
        } file;
        struct {
            struct FileNode *entries[MAX_DIR_ENTRIES];
            int count;
        } dir;
    } data;
    struct FileNode *parent;
} FileNode;

// 内存管理器结构体
typedef struct {
    MemoryBlock blocks[256]; // 最多256个内存块
    int block_count;
    int total_memory;
} MemoryManager;

// 文件系统结构体
typedef struct {
    FileNode *root;
    FileNode *current_dir;
    char current_path[MAX_PATH_LENGTH];
} FileSystem;

// 调度器结构体
typedef struct {
    Process processes[MAX_PROCESSES];
    int process_count;
    int next_pid;
    int running_pid;
} Scheduler;

// 操作系统模拟器结构体
typedef struct {
    MemoryManager mem_manager;
    FileSystem fs;
    Scheduler scheduler;
    time_t start_time;
    char command_history[100][MAX_COMMAND_LENGTH];
    int history_count;
    bool running;
} SimulatedOS;

// 函数声明
void init_os(SimulatedOS *os);
void init_memory_manager(MemoryManager *mm, int total_memory);
void init_file_system(FileSystem *fs);
void init_scheduler(Scheduler *scheduler);
int create_process(Scheduler *scheduler, const char *name, int priority, int memory_size);
bool terminate_process(Scheduler *scheduler, int pid);
void schedule(Scheduler *scheduler);
int kmalloc(MemoryManager *mm, int size, int pid);
bool kfree(MemoryManager *mm, int pid);
FileNode *create_file(FileSystem *fs, const char *name, const char *content);
FileNode *create_directory(FileSystem *fs, const char *name);
bool change_directory(FileSystem *fs, const char *path);
void list_directory(FileSystem *fs, bool detailed);
char *read_file(FileSystem *fs, const char *name);
bool write_file(FileSystem *fs, const char *name, const char *content);
bool delete_file(FileSystem *fs, const char *name);
void execute_command(SimulatedOS *os, const char *command);
void show_help();
void show_processes(Scheduler *scheduler, bool show_all);
void show_memory_info(MemoryManager *mm);
void run_cli(SimulatedOS *os);

// 初始化操作系统
void init_os(SimulatedOS *os) {
    time(&os->start_time);
    os->history_count = 0;
    os->running = true;
    
    init_memory_manager(&os->mem_manager, MAX_MEMORY);
    init_file_system(&os->fs);
    init_scheduler(&os->scheduler);
    
    // 创建初始进程
    create_process(&os->scheduler, "init", 5, 64);
    create_process(&os->scheduler, "logger", 3, 32);
    create_process(&os->scheduler, "sysmon", 7, 48);
    
    // 创建初始文件结构
    create_directory(&os->fs, "documents");
    create_directory(&os->fs, "system");
    change_directory(&os->fs, "system");
    create_file(&os->fs, "README.txt", "Welcome to MyOS Simulator v1.0");
    change_directory(&os->fs, "/");
}

// 初始化内存管理器
void init_memory_manager(MemoryManager *mm, int total_memory) {
    mm->total_memory = total_memory;
    mm->block_count = 1;
    mm->blocks[0].start = 0;
    mm->blocks[0].size = total_memory;
    mm->blocks[0].allocated = false;
    mm->blocks[0].pid = -1;
}

// 初始化文件系统
void init_file_system(FileSystem *fs) {
    fs->root = malloc(sizeof(FileNode));
    strcpy(fs->root->name, "/");
    fs->root->type = DIR_TYPE;
    time(&fs->root->created);
    fs->root->data.dir.count = 0;
    fs->root->parent = NULL;
    
    fs->current_dir = fs->root;
    strcpy(fs->current_path, "/");
}

// 初始化调度器
void init_scheduler(Scheduler *scheduler) {
    scheduler->process_count = 0;
    scheduler->next_pid = 1;
    scheduler->running_pid = -1;
}

// 创建进程
int create_process(Scheduler *scheduler, const char *name, int priority, int memory_size) {
    if (scheduler->process_count >= MAX_PROCESSES) {
        return -1; // 进程数已达上限
    }
    
    Process *p = &scheduler->processes[scheduler->process_count];
    p->pid = scheduler->next_pid++;
    strncpy(p->name, name, 31);
    p->name[31] = '\0';
    p->priority = priority;
    p->memory_size = memory_size;
    p->state = READY;
    time(&p->start_time);
    p->cpu_time = 0;
    p->wait_time = 0;
    p->memory_start = -1;
    p->memory_end = -1;
    
    scheduler->process_count++;
    return p->pid;
}

// 终止进程
bool terminate_process(Scheduler *scheduler, int pid) {
    for (int i = 0; i < scheduler->process_count; i++) {
        if (scheduler->processes[i].pid == pid) {
            scheduler->processes[i].state = TERMINATED;
            
            // 如果是当前运行进程
            if (scheduler->running_pid == pid) {
                scheduler->running_pid = -1;
            }
            
            // 将进程移到数组末尾
            Process temp = scheduler->processes[i];
            scheduler->processes[i] = scheduler->processes[scheduler->process_count - 1];
            scheduler->processes[scheduler->process_count - 1] = temp;
            
            scheduler->process_count--;
            return true;
        }
    }
    return false;
}

// 调度进程
void schedule(Scheduler *scheduler) {
    if (scheduler->running_pid != -1) {
        // 当前运行进程时间片用完，放回就绪队列
        for (int i = 0; i < scheduler->process_count; i++) {
            if (scheduler->processes[i].pid == scheduler->running_pid) {
                scheduler->processes[i].state = READY;
                break;
            }
        }
        scheduler->running_pid = -1;
    }
    
    // 选择优先级最高的就绪进程
    int highest_priority = -1;
    int selected_pid = -1;
    
    for (int i = 0; i < scheduler->process_count; i++) {
        if (scheduler->processes[i].state == READY && 
            scheduler->processes[i].priority > highest_priority) {
            highest_priority = scheduler->processes[i].priority;
            selected_pid = scheduler->processes[i].pid;
        }
    }
    
    if (selected_pid != -1) {
        scheduler->running_pid = selected_pid;
        for (int i = 0; i < scheduler->process_count; i++) {
            if (scheduler->processes[i].pid == selected_pid) {
                scheduler->processes[i].state = RUNNING;
                break;
            }
        }
    }
}

// 内存分配
int kmalloc(MemoryManager *mm, int size, int pid) {
    // 使用首次适应算法
    for (int i = 0; i < mm->block_count; i++) {
        if (!mm->blocks[i].allocated && mm->blocks[i].size >= size) {
            // 找到合适的内存块
            int remaining = mm->blocks[i].size - size;
            
            if (remaining > 0) {
                // 创建新块存放剩余空间
                if (mm->block_count < 255) {
                    // 移动后面的块
                    for (int j = mm->block_count; j > i + 1; j--) {
                        mm->blocks[j] = mm->blocks[j - 1];
                    }
                    
                    // 创建新块
                    mm->blocks[i + 1].start = mm->blocks[i].start + size;
                    mm->blocks[i + 1].size = remaining;
                    mm->blocks[i + 1].allocated = false;
                    mm->blocks[i + 1].pid = -1;
                    
                    mm->block_count++;
                }
            }
            
            // 设置当前块
            mm->blocks[i].size = size;
            mm->blocks[i].allocated = true;
            mm->blocks[i].pid = pid;
            
            return mm->blocks[i].start;
        }
    }
    return -1; // 分配失败
}

// 内存释放
bool kfree(MemoryManager *mm, int pid) {
    for (int i = 0; i < mm->block_count; i++) {
        if (mm->blocks[i].allocated && mm->blocks[i].pid == pid) {
            mm->blocks[i].allocated = false;
            mm->blocks[i].pid = -1;
            
            // 合并相邻的空闲块
            if (i > 0 && !mm->blocks[i - 1].allocated) {
                // 合并前一块
                mm->blocks[i - 1].size += mm->blocks[i].size;
                
                // 移除当前块
                for (int j = i; j < mm->block_count - 1; j++) {
                    mm->blocks[j] = mm->blocks[j + 1];
                }
                mm->block_count--;
                i--; // 检查合并后的块
            }
            
            if (i < mm->block_count - 1 && !mm->blocks[i + 1].allocated) {
                // 合并后一块
                mm->blocks[i].size += mm->blocks[i + 1].size;
                
                // 移除后一块
                for (int j = i + 1; j < mm->block_count - 1; j++) {
                    mm->blocks[j] = mm->blocks[j + 1];
                }
                mm->block_count--;
            }
            
            return true;
        }
    }
    return false;
}

// 创建文件
FileNode *create_file(FileSystem *fs, const char *name, const char *content) {
    if (fs->current_dir->data.dir.count >= MAX_DIR_ENTRIES) {
        return NULL;
    }
    
    FileNode *new_file = malloc(sizeof(FileNode));
    strncpy(new_file->name, name, MAX_FILENAME - 1);
    new_file->name[MAX_FILENAME - 1] = '\0';
    new_file->type = FILE_TYPE;
    time(&new_file->created);
    time(&new_file->modified);
    
    size_t content_len = strlen(content);
    new_file->data.file.content = malloc(content_len + 1);
    strcpy(new_file->data.file.content, content);
    new_file->data.file.size = content_len;
    
    new_file->parent = fs->current_dir;
    
    // 添加到当前目录
    fs->current_dir->data.dir.entries[fs->current_dir->data.dir.count] = new_file;
    fs->current_dir->data.dir.count++;
    
    return new_file;
}

// 创建目录
FileNode *create_directory(FileSystem *fs, const char *name) {
    if (fs->current_dir->data.dir.count >= MAX_DIR_ENTRIES) {
        return NULL;
    }
    
    FileNode *new_dir = malloc(sizeof(FileNode));
    strncpy(new_dir->name, name, MAX_FILENAME - 1);
    new_dir->name[MAX_FILENAME - 1] = '\0';
    new_dir->type = DIR_TYPE;
    time(&new_dir->created);
    new_dir->data.dir.count = 0;
    new_dir->parent = fs->current_dir;
    
    // 添加到当前目录
    fs->current_dir->data.dir.entries[fs->current_dir->data.dir.count] = new_dir;
    fs->current_dir->data.dir.count++;
    
    return new_dir;
}

// 切换目录
bool change_directory(FileSystem *fs, const char *path) {
    if (strcmp(path, "/") == 0) {
        fs->current_dir = fs->root;
        strcpy(fs->current_path, "/");
        return true;
    }
    
    if (strcmp(path, "..") == 0) {
        if (fs->current_dir->parent != NULL) {
            fs->current_dir = fs->current_dir->parent;
            
            // 更新路径
            if (fs->current_dir == fs->root) {
                strcpy(fs->current_path, "/");
            } else {
                // 找到父目录在祖父目录中的位置
                char temp_path[MAX_PATH_LENGTH] = "";
                FileNode *current = fs->current_dir;
                
                while (current != fs->root) {
                    char parent_path[MAX_PATH_LENGTH];
                    strcpy(parent_path, "/");
                    strcat(parent_path, current->name);
                    strcat(parent_path, temp_path);
                    strcpy(temp_path, parent_path);
                    current = current->parent;
                }
                
                strcpy(fs->current_path, temp_path);
            }
            return true;
        }
        return false;
    }
    
    // 在当前目录查找
    for (int i = 0; i < fs->current_dir->data.dir.count; i++) {
        FileNode *entry = fs->current_dir->data.dir.entries[i];
        if (strcmp(entry->name, path) == 0 && entry->type == DIR_TYPE) {
            fs->current_dir = entry;
            
            // 更新路径
            if (strcmp(fs->current_path, "/") != 0) {
                strcat(fs->current_path, "/");
            }
            strcat(fs->current_path, path);
            
            return true;
        }
    }
    return false;
}

// 列出目录内容
void list_directory(FileSystem *fs, bool detailed) {
    if (fs->current_dir->data.dir.count == 0) {
        printf("Empty directory\n");
        return;
    }
    
    if (!detailed) {
        for (int i = 0; i < fs->current_dir->data.dir.count; i++) {
            FileNode *entry = fs->current_dir->data.dir.entries[i];
            printf("%s%s\n", entry->name, entry->type == DIR_TYPE ? "/" : "");
        }
        return;
    }
    
    printf("Type   Created          Modified         Size     Name\n");
    for (int i = 0; i < fs->current_dir->data.dir.count; i++) {
        FileNode *entry = fs->current_dir->data.dir.entries[i];
        char created_str[20], modified_str[20];
        strftime(created_str, 20, "%Y-%m-%d %H:%M", localtime(&entry->created));
        strftime(modified_str, 20, "%Y-%m-%d %H:%M", localtime(&entry->modified));
        
        if (entry->type == DIR_TYPE) {
            printf("DIR    %-16s %-16s %-8s %s/\n", created_str, modified_str, "-", entry->name);
        } else {
            printf("FILE   %-16s %-16s %-8zu %s\n", 
                  created_str, modified_str, entry->data.file.size, entry->name);
        }
    }
}

// 读取文件内容
char *read_file(FileSystem *fs, const char *name) {
    for (int i = 0; i < fs->current_dir->data.dir.count; i++) {
        FileNode *entry = fs->current_dir->data.dir.entries[i];
        if (strcmp(entry->name, name) == 0 && entry->type == FILE_TYPE) {
            return entry->data.file.content;
        }
    }
    return NULL;
}

// 写入文件内容
bool write_file(FileSystem *fs, const char *name, const char *content) {
    for (int i = 0; i < fs->current_dir->data.dir.count; i++) {
        FileNode *entry = fs->current_dir->data.dir.entries[i];
        if (strcmp(entry->name, name) == 0 && entry->type == FILE_TYPE) {
            free(entry->data.file.content);
            
            size_t content_len = strlen(content);
            entry->data.file.content = malloc(content_len + 1);
            strcpy(entry->data.file.content, content);
            entry->data.file.size = content_len;
            
            time(&entry->modified);
            return true;
        }
    }
    return false;
}

// 删除文件或目录
bool delete_file(FileSystem *fs, const char *name) {
    for (int i = 0; i < fs->current_dir->data.dir.count; i++) {
        FileNode *entry = fs->current_dir->data.dir.entries[i];
        if (strcmp(entry->name, name) == 0) {
            // 释放内存
            if (entry->type == FILE_TYPE) {
                free(entry->data.file.content);
            } else {
                // 递归删除目录内容
                for (int j = 0; j < entry->data.dir.count; j++) {
                    delete_file(fs, entry->data.dir.entries[j]->name);
                }
            }
            
            free(entry);
            
            // 从目录中移除
            for (int j = i; j < fs->current_dir->data.dir.count - 1; j++) {
                fs->current_dir->data.dir.entries[j] = fs->current_dir->data.dir.entries[j + 1];
            }
            fs->current_dir->data.dir.count--;
            
            return true;
        }
    }
    return false;
}

// 执行命令
void execute_command(SimulatedOS *os, const char *command) {
    // 保存命令历史
    if (os->history_count < 100) {
        strncpy(os->command_history[os->history_count], command, MAX_COMMAND_LENGTH - 1);
        os->command_history[os->history_count][MAX_COMMAND_LENGTH - 1] = '\0';
        os->history_count++;
    }
    
    // 解析命令
    char cmd[32];
    char arg1[64];
    char arg2[256];
    
    int count = sscanf(command, "%31s %63s %255[^\n]", cmd, arg1, arg2);
    
    if (count == 0) {
        return;
    }
    
    // 处理命令
    if (strcmp(cmd, "help") == 0) {
        show_help();
    } 
    else if (strcmp(cmd, "ps") == 0) {
        show_processes(&os->scheduler, (count > 1 && strcmp(arg1, "-a") == 0));
    } 
    else if (strcmp(cmd, "meminfo") == 0) {
        show_memory_info(&os->mem_manager);
    } 
    else if (strcmp(cmd, "kill") == 0 && count > 1) {
        int pid = atoi(arg1);
        if (terminate_process(&os->scheduler, pid)) {
            kfree(&os->mem_manager, pid);
            printf("Process %d terminated\n", pid);
        } else {
            printf("No such process: %d\n", pid);
        }
    } 
    else if (strcmp(cmd, "mkdir") == 0 && count > 1) {
        if (create_directory(&os->fs, arg1)) {
            printf("Directory '%s' created\n", arg1);
        } else {
            printf("Error creating directory\n");
        }
    } 
    else if (strcmp(cmd, "touch") == 0 && count > 1) {
        const char *content = (count > 2) ? arg2 : "";
        if (create_file(&os->fs, arg1, content)) {
            printf("File '%s' created\n", arg1);
        } else {
            printf("Error creating file\n");
        }
    } 
    else if (strcmp(cmd, "ls") == 0) {
        bool detailed = (count > 1 && strcmp(arg1, "-l") == 0);
        list_directory(&os->fs, detailed);
    } 
    else if (strcmp(cmd, "cd") == 0) {
        const char *path = (count > 1) ? arg1 : "/";
        if (change_directory(&os->fs, path)) {
            printf("Changed to %s\n", os->fs.current_path);
        } else {
            printf("Directory not found: %s\n", path);
        }
    } 
    else if (strcmp(cmd, "pwd") == 0) {
        printf("%s\n", os->fs.current_path);
    } 
    else if (strcmp(cmd, "cat") == 0 && count > 1) {
        char *content = read_file(&os->fs, arg1);
        if (content) {
            printf("%s\n", content);
        } else {
            printf("File not found: %s\n", arg1);
        }
    } 
    else if (strcmp(cmd, "write") == 0 && count > 2) {
        if (write_file(&os->fs, arg1, arg2)) {
            printf("File '%s' updated\n", arg1);
        } else {
            printf("Error writing to file\n");
        }
    } 
    else if (strcmp(cmd, "rm") == 0 && count > 1) {
        if (delete_file(&os->fs, arg1)) {
            printf("Deleted '%s'\n", arg1);
        } else {
            printf("File not found: %s\n", arg1);
        }
    } 
    else if (strcmp(cmd, "run") == 0 && count > 1) {
        // 随机优先级和内存大小
        int priority = rand() % 7 + 2; // 2-8
        int memory = rand() % 225 + 32; // 32-256
        
        int pid = create_process(&os->scheduler, arg1, priority, memory);
        if (pid != -1) {
            if (kmalloc(&os->mem_manager, memory, pid) != -1) {
                printf("Started process %s (PID: %d, Priority: %d, Memory: %dKB)\n", 
                      arg1, pid, priority, memory);
            } else {
                terminate_process(&os->scheduler, pid);
                printf("Failed to start process: insufficient memory\n");
            }
        } else {
            printf("Failed to start process: too many processes\n");
        }
    } 
    else if (strcmp(cmd, "history") == 0) {
        for (int i = 0; i < os->history_count; i++) {
            printf("%d: %s\n", i + 1, os->command_history[i]);
        }
    } 
    else if (strcmp(cmd, "sysinfo") == 0) {
        time_t now;
        time(&now);
        double uptime = difftime(now, os->start_time);
        int hours = (int)(uptime / 3600);
        int minutes = (int)((uptime - hours * 3600) / 60);
        int seconds = (int)uptime % 60;
        
        printf("MyOS Simulator v1.0 (C Implementation)\n");
        printf("Uptime: %dh %dm %ds\n", hours, minutes, seconds);
        printf("Processes: %d active\n", os->scheduler.process_count);
        printf("Memory: %dKB total\n", MAX_MEMORY);
    } 
    else if (strcmp(cmd, "exit") == 0) {
        os->running = false;
        printf("Shutting down OS Simulator...\n");
    } 
    else {
        printf("Command not found: %s\n", cmd);
    }
    
    // 执行调度
    schedule(&os->scheduler);
}

// 显示帮助信息
void show_help() {
    printf("Available commands:\n");
    printf("  help         - Show this help message\n");
    printf("  ps [-a]      - List running processes (-a for all processes)\n");
    printf("  meminfo      - Show memory usage\n");
    printf("  run <name>   - Start a new process\n");
    printf("  kill <pid>   - Terminate a process\n");
    printf("  mkdir <d>    - Create a directory\n");
    printf("  touch <f>    - Create a file\n");
    printf("  ls [-l]      - List directory contents (-l for details)\n");
    printf("  cd <dir>     - Change directory\n");
    printf("  pwd          - Show current directory\n");
    printf("  cat <file>   - Show file contents\n");
    printf("  write <f> <c>- Write to file\n");
    printf("  rm <name>    - Delete file or directory\n");
    printf("  history      - Show command history\n");
    printf("  sysinfo      - Show system information\n");
    printf("  exit         - Exit the OS simulator\n");
}

// 显示进程信息
void show_processes(Scheduler *scheduler, bool show_all) {
    if (scheduler->process_count == 0) {
        printf("No processes found\n");
        return;
    }
    
    printf("PID     Name       Priority State      Memory   Created\n");
    
    time_t now;
    time(&now);
    
    for (int i = 0; i < scheduler->process_count; i++) {
        Process *p = &scheduler->processes[i];
        
        if (!show_all && p->state == TERMINATED) {
            continue;
        }
        
        char state_str[16];
        switch (p->state) {
            case READY: strcpy(state_str, "Ready"); break;
            case RUNNING: strcpy(state_str, "Running"); break;
            case BLOCKED: strcpy(state_str, "Blocked"); break;
            case TERMINATED: strcpy(state_str, "Terminated"); break;
        }
        
        double runtime = difftime(now, p->start_time);
        int hours = (int)(runtime / 3600);
        int minutes = (int)((runtime - hours * 3600) / 60);
        int seconds = (int)runtime % 60;
        
        printf("%-7d %-10s %-8d %-10s %-5dKB %02d:%02d:%02d\n", 
              p->pid, p->name, p->priority, state_str, 
              p->memory_size, hours, minutes, seconds);
    }
}

// 显示内存信息
void show_memory_info(MemoryManager *mm) {
    int used = 0;
    for (int i = 0; i < mm->block_count; i++) {
        if (mm->blocks[i].allocated) {
            used += mm->blocks[i].size;
        }
    }
    
    int free_mem = mm->total_memory - used;
    float usage_percent = (float)used / mm->total_memory * 100;
    
    printf("Total memory: %dKB\n", mm->total_memory);
    printf("Used memory: %dKB (%.1f%%)\n", used, usage_percent);
    printf("Free memory: %dKB\n\n", free_mem);
    printf("Memory map:\n");
    
    for (int i = 0; i < mm->block_count; i++) {
        MemoryBlock *b = &mm->blocks[i];
        printf("%6d-%6d: %s (%dKB) %s\n", 
              b->start, b->start + b->size,
              b->allocated ? "Allocated" : "Free",
              b->size,
              b->allocated ? "[PID: " : "");
    }
}

// 运行命令行界面
void run_cli(SimulatedOS *os) {
    char command[MAX_COMMAND_LENGTH];
    
    printf("MyOS Simulator v1.0 (C Implementation)\n");
    printf("Type 'help' for available commands\n\n");
    
    while (os->running) {
        printf("%s $ ", os->fs.current_path);
        fgets(command, MAX_COMMAND_LENGTH, stdin);
        
        // 移除换行符
        size_t len = strlen(command);
        if (len > 0 && command[len - 1] == '\n') {
            command[len - 1] = '\0';
        }
        
        // 忽略空命令
        if (strlen(command) == 0) {
            continue;
        }
        
        execute_command(os, command);
    }
}

// 主函数
int main() {
    srand(time(NULL)); // 初始化随机数生成器
    
    SimulatedOS os;
    init_os(&os);
    
    run_cli(&os);
    
    // 清理资源
    // 在实际系统中需要更复杂的清理，这里简化处理
    
    return 0;
}
