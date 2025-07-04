# OS Simulator (C Implementation)

## Overview

This OS Simulator is a C-based implementation that demonstrates core operating system concepts including process management, memory allocation, and file system operations. The simulator provides an interactive command-line interface where users can experiment with OS functionalities in a controlled environment.

## Features

### Process Management
- Process creation and termination
- Priority-based scheduling (non-preemptive)
- Process states (Ready, Running, Blocked, Terminated)
- Process attributes (PID, name, priority, memory usage)

### Memory Management
- First-fit allocation algorithm
- Memory block management (2048KB total)
- Memory fragmentation handling
- Visual memory map display

### File System
- Hierarchical directory structure
- File and directory operations
- File content reading/writing
- Metadata tracking (creation/modification times)
- Path navigation (absolute and relative)

### Command Line Interface
- 15+ built-in commands
- Command history
- Detailed system information
- Interactive prompt with current directory display

## Building and Running

### Requirements
- GCC compiler
- Linux/macOS environment (Windows requires WSL or MinGW)
- Standard C library

### Compilation
```bash
gcc os_simulator.c -o os_simulator
```

### Execution
```bash
./os_simulator
```

## Usage Guide

### Basic Commands
| Command          | Description                            | Example                     |
|------------------|----------------------------------------|-----------------------------|
| `help`           | Show available commands                | `help`                      |
| `run <name>`     | Start a new process                    | `run browser`               |
| `ps [-a]`        | List processes (-a shows all)          | `ps -a`                     |
| `kill <pid>`     | Terminate a process                    | `kill 5`                    |
| `meminfo`        | Show memory usage information          | `meminfo`                   |
| `sysinfo`        | Display system information             | `sysinfo`                   |
| `history`        | Show command history                   | `history`                   |
| `exit`           | Exit the simulator                     | `exit`                      |

### File System Commands
| Command          | Description                            | Example                     |
|------------------|----------------------------------------|-----------------------------|
| `mkdir <dir>`    | Create a directory                     | `mkdir documents`           |
| `touch <file>`   | Create a file                          | `touch notes.txt`           |
| `ls [-l]`        | List directory (-l for details)        | `ls -l`                     |
| `cd <dir>`       | Change directory                       | `cd system`                 |
| `pwd`            | Show current directory                 | `pwd`                       |
| `cat <file>`     | Display file contents                  | `cat README.txt`            |
| `write <f> <c>`  | Write content to a file                | `write log.txt "new entry"` |
| `rm <name>`      | Delete file/directory                  | `rm temp.txt`               |

## Project Structure

The simulator is implemented in a single C file (`os_simulator.c`) with the following key components:

1. **Data Structures**
   - `Process`: Tracks process attributes and state
   - `MemoryBlock`: Manages memory allocation units
   - `FileNode`: Represents files and directories
   - `SimulatedOS`: Main OS container structure

2. **Core Systems**
   - **Scheduler**: Priority-based process scheduling
   - **Memory Manager**: First-fit allocation with coalescing
   - **File System**: Hierarchical tree structure with metadata

3. **CLI Engine**
   - Command parsing and execution
   - History tracking
   - Interactive prompt

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes
4. Push to the branch
5. Open a pull request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
