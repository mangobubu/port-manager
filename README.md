# Port Manager

Tauri + Rust + React + Ant Design 6.5 本机端口管理工具。

## 功能

- 展示本机 TCP / UDP 端口
- 展示协议、本地地址、本地端口、远端地址、状态、PID、进程名称、进程路径
- 支持结束指定 PID
- 启动后自动尝试提升权限：
  - Windows: UAC runas
  - macOS: osascript administrator prompt
  - Linux: pkexec，并尽量保留 DISPLAY / Wayland / DBus 环境

## 开发

    npm install
    npm run tauri:dev

## 构建

    npm run tauri:build

当前实现已按平台分支处理端口枚举：

- Windows: netstat -a -n -o + Win32 进程 API
- macOS: lsof -nP -iTCP -iUDP + proc_pidpath
- Linux: /proc/net/{tcp,tcp6,udp,udp6} + /proc/*/fd socket inode 映射
