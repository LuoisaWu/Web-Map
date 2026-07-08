@echo off
echo 正在停止 WebMap 服务...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING') do (
    echo 发现运行在端口 8000 的进程 PID: %%a，正在终止...
    taskkill /F /PID %%a
)
echo WebMap 服务已停止。
pause
