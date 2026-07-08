@echo off
title WebMap Server
echo ===================================================
echo             启动 WebMap 资产测绘系统
echo ===================================================

cd /d "%~dp0\backend"

echo [1/2] 正在检查依赖...
python -c "import fastapi, uvicorn, torch, transformers" >nul 2>&1
if %errorlevel% neq 0 (
    echo 未检测到必要的依赖，尝试自动安装...
    pip install -r requirements.txt
)

echo [2/2] 启动后端服务及前端界面...
echo 服务启动后，请在浏览器中访问 http://127.0.0.1:8000/
echo 按 Ctrl+C 可以停止服务。
echo.

python api_server.py
pause
