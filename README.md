# FinalShell 密码解密 GUI

一个用于解析 FinalShell 连接配置中 Base64 密文并批量解密展示的桌面程序。界面基于 `tkinter/ttk`，在可用时优先使用 `ttkbootstrap` 提供更一致的亮色主题。

## 特性
- 解密单个 Base64 密文，立即显示明文密码。
- 扫描并解析 `conn` 目录下的多个连接 `.json` 文件，批量解密并列表展示。
- 支持筛选、复制选中行/选中密码/全部内容、导出 CSV、打开所在目录。
- 自动检测常见的 FinalShell 安装/数据目录位置（Windows）。

## 环境要求
- 操作系统：Windows（自动目录检测依赖 `winreg`）
- Python：3.10+（推荐 3.11/3.12）
- 依赖：`pycryptodome`（DES 解密），`ttkbootstrap`（可选，提供主题与样式）

## 快速开始
1. 克隆代码或下载压缩包。
2. 创建并激活虚拟环境（推荐）：
   - PowerShell：
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
3. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
4. 运行桌面 GUI：
   ```bash
   python -m finalshell_decoder
   ```

## 使用说明
- 解密单个密文：复制 `.json` 中的 `password` 字段（Base64），粘贴到页面顶部文本框，点击“解密”。
- 扫描 `conn` 目录：
  - 可在输入框中填写路径并点击“手动选择并扫描”。
  - 或点击“自动检测并扫描”，程序会尝试在常见位置寻找 `conn` 目录。
- 常见路径（Windows）：
  - `C:\Users\<用户名>\AppData\Roaming\FinalShell\conn`
  - `C:\Users\<用户名>\AppData\Local\FinalShell\conn`
  - `C:\Program Files\FinalShell\conn` 或 `C:\Program Files (x86)\FinalShell\conn`
  - 有时也可能在 `C:\FinalShell\conn`
- 图标资源位于 `finalshell_decoder/assets/`，更换图标替换 `icon.ico`（Windows 优先）或 `icon.png` 即可。

## 项目结构
```
└── finalshell_decoder/        # 桌面程序包
    ├── __init__.py            # 包初始化
    ├── __main__.py            # 入口：python -m finalshell_decoder
    ├── assets/                # 包内资源
    │   ├── icon.ico           # Windows 原生图标（优先）
    │   └── icon.png           # 兼容图标（回退）
    ├── gui.py                 # GUI 主程序
    └── decrypt.py             # 解密逻辑（DES/ECB/PKCS5）
```

## 常见问题
- 解密报错 `Crypto library (pycryptodome) is not installed`：
  - 说明未安装 `pycryptodome`，请执行 `pip install -r requirements.txt` 或单独安装 `pip install pycryptodome`。
- 主题样式无亮色、界面风格偏旧：
  - 说明未安装 `ttkbootstrap`，功能不受影响；如需统一主题，安装 `pip install ttkbootstrap` 即可。
- 未找到 `conn` 目录：
  - 建议先关闭 FinalShell，确保配置写入；然后使用“自动检测并扫描”或在设置中查看“数据目录”。

## 贡献
- 欢迎提交 Issue 与 Pull Request。详情见 `CONTRIBUTING.md`。
- 建议遵循规范的提交信息与代码风格，保持变更聚焦与可读。

## 打包/编译（Windows EXE）
- 安装打包工具：`pip install pyinstaller`
- 生成单文件 GUI 可执行程序（含图标与资源）：
  ```powershell
  pyinstaller --noconfirm --clean --onefile --windowed \
    --name FinalShellDecoder \
    --icon finalshell_decoder/assets/icon.ico \
    --add-data "finalshell_decoder/assets;finalshell_decoder/assets" \
    finalshell_decoder/__main__.py
  ```
- 输出文件：`dist/FinalShellDecoder.exe`
- 可选：确保主题与依赖收集完整
  - 包含 `ttkbootstrap` 主题：添加 `--hidden-import ttkbootstrap`
  - 如遇 `Crypto` 资源缺失：添加 `--collect-all Crypto` 或 `--collect-submodules Crypto`
- 调试模式：去掉 `--windowed` 可显示控制台日志

## 变更日志
- 请见 `CHANGELOG.md`。