# WebMap 资产测绘系统

这是一个将大语言模型与小模型知识蒸馏结合的网站语义打标及资产测绘拓扑展示系统。本目录提取了最终运行所需的全部文件，无需再进行复杂的模型训练即可直接运行演示。

## 目录结构

```text
WebMap/
├── frontend/          # 前端页面文件（HTML/JS/CSS，无需编译）
├── backend/           # 后端服务程序
│   ├── custom-web-check-py/   # 网站探针工具
│   ├── pipeline/              # 包含模型配置与已训练好的最佳模型(best_student_model)
│   ├── api_server.py          # FastAPI 主服务脚本
│   └── requirements.txt       # 后端运行依赖
├── database/          # 数据库相关
│   └── init.sql               # SQLite 数据库表结构初始化参考脚本
├── start.bat          # Windows 一键启动脚本
├── stop.bat           # Windows 一键停止脚本
└── README.md          # 本说明文档
```

## 运行环境

- **操作系统**: Windows
- **Python**: Python 3.8 ~ 3.10（建议）
- **依赖库**: FastAPI, Uvicorn, PyTorch, Transformers, Scikit-learn 等

## 如何启动

1. 双击运行 `start.bat`。
2. 脚本会自动检查依赖，若缺少会自动通过 `pip install -r backend\requirements.txt` 安装。
3. 启动成功后，浏览器会自动提示 API 地址。
4. 在浏览器中访问：[http://127.0.0.1:8000/](http://127.0.0.1:8000/) 即可查看可视化拓扑界面。

正常启动成功如下图所示：

![](/演示图片.png)

## 如何停止

- 在运行 `start.bat` 的命令行窗口中按下 `Ctrl+C` 即可停止。
- 或者双击运行 `stop.bat`，它会自动检测并强制结束占用 8000 端口的进程。

## 注意事项

- 系统初次运行时，如果没有找到 `database/assets_topology.db`，后端会自动创建该 SQLite 数据库并插入一部分演示数据（该逻辑位于 `api_server.py` 内）。`database/init.sql` 仅作为表结构的参考。
- 探测功能依赖网络连通性，若遇到解析错误或连接超时，探针会自动记录失败状态以防止前端陷入死循环轮询。
- 本系统为演示版本，不设置用户认证机制。启动完成后，用户可直接通过浏览器访问系统首页并使用全部功能，无需注册或登录。
- 若需进行大规模资产测绘或模型重新训练，建议使用具备 GPU 环境的设备运行相关模块。