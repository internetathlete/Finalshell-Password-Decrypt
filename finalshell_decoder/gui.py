import os
import json
import threading
import csv
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
# 资源路径（包内）
try:
    from importlib.resources import files, as_file
except Exception:
    files = None
    as_file = None
# 优先使用 ttkbootstrap 以统一主题（不可用时降级）
try:
    import ttkbootstrap as tb
except Exception:
    tb = None
from .decrypt import decode_pass
# 尝试导入注册表模块（仅Windows）
try:
    import winreg
except Exception:
    winreg = None


class FinalShellGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('FinalShell 密码解密')
        self.root.geometry('1000x700')
        # 优化：统一主题与样式、初始化状态
        self._setup_style()
        self._setup_icon()
        self.var_filter = tk.StringVar()
        self.items = []
        self._sort_states = {}
        self._build_ui()

    def _setup_style(self):
        # 若可用则采用 ttkbootstrap 主题；否则使用系统主题
        if tb is not None:
            try:
                style = tb.Style('minty')  # 亮色主题，可改为 'flatly' 或 'darkly'
            except Exception:
                style = ttk.Style()
                style.theme_use('clam')
        else:
            style = ttk.Style()
            themes = style.theme_names()
            theme = 'vista' if 'vista' in themes else 'clam'
            style.theme_use(theme)
        # 统一字体与表格行高
        style.configure('TLabel', font=('Segoe UI', 10))
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('Treeview', font=('Consolas', 10), rowheight=24)
        style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#e6f2ff')], foreground=[('selected', '#000')])

    def _setup_icon(self):
        # 从包内 assets 加载图标（优先 .ico，兼容 .png）
        if files is None:
            return
        try:
            ico_res = files(__package__).joinpath('assets/icon.ico')
            png_res = files(__package__).joinpath('assets/icon.png')
            if as_file is not None:
                # 提供真实路径以兼容压缩包环境
                try:
                    with as_file(ico_res) as p:
                        self.root.iconbitmap(str(p))
                except Exception:
                    pass
                try:
                    with as_file(png_res) as p:
                        img = tk.PhotoImage(file=str(p))
                        self.root.iconphoto(True, img)
                except Exception:
                    pass
            else:
                try:
                    self.root.iconbitmap(str(ico_res))
                except Exception:
                    pass
                try:
                    img = tk.PhotoImage(file=str(png_res))
                    self.root.iconphoto(True, img)
                except Exception:
                    pass
        except Exception:
            # 图标加载失败不影响功能
            pass

    def _build_ui(self):
        # 主容器
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill=tk.BOTH, expand=True)

        # 区块：解密单个密码
        frm_decode = ttk.LabelFrame(container, text='解密单个密码（Base64密文）')
        frm_decode.pack(fill=tk.X, expand=False, padx=4, pady=6)

        ttk.Label(frm_decode, text='密码密文：').grid(row=0, column=0, sticky='w', padx=4, pady=4)
        self.txt_pwd = tk.Text(frm_decode, height=4)
        self.txt_pwd.grid(row=1, column=0, columnspan=6, sticky='we', padx=4, pady=4)
        frm_decode.columnconfigure(0, weight=1)

        btn_decode = ttk.Button(frm_decode, text='解密', command=self.on_decode)
        btn_decode.grid(row=2, column=0, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                btn_decode.configure(style='primary.TButton')
            except Exception:
                pass
        self.lbl_decode_result = ttk.Label(frm_decode, text='')
        self.lbl_decode_result.grid(row=2, column=1, sticky='w', padx=4, pady=4)
        # 友好提示与帮助

        lbl_hint_pwd = ttk.Label(
            frm_decode,
            text='提示：在 FinalShell 安装目录下的 conn 文件夹中，每个连接对应一个 .json 文件，其中 password 字段为 Base64 密文。打开文件复制该字段，粘贴到上方文本框进行解密。',
            justify='left', wraplength=900
        )
        if tb is not None:
            try:
                lbl_hint_pwd.configure(style='secondary.TLabel')
            except Exception:
                pass
        lbl_hint_pwd.grid(row=3, column=0, columnspan=6, sticky='we', padx=4, pady=(0, 6))

        # 区块：扫描 conn 目录
        frm_scan = ttk.LabelFrame(container, text='扫描 FinalShell conn 目录')
        frm_scan.pack(fill=tk.BOTH, expand=True, padx=4, pady=6)

        ttk.Label(frm_scan, text='conn 目录路径：').grid(row=0, column=0, sticky='w', padx=4, pady=4)
        self.entry_conn = ttk.Entry(frm_scan)
        self.entry_conn.grid(row=0, column=1, sticky='we', padx=4, pady=4)
        self.btn_browse = ttk.Button(frm_scan, text='手动选择并扫描', command=self.on_browse)
        self.btn_browse.grid(row=0, column=2, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                self.btn_browse.configure(style='primary.TButton')
            except Exception:
                pass
        self.btn_auto = ttk.Button(frm_scan, text='自动检测并扫描', command=self.on_auto_scan)
        self.btn_auto.grid(row=0, column=3, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                self.btn_auto.configure(style='success.TButton')
            except Exception:
                pass
        self.lbl_scan_status = ttk.Label(frm_scan, text='')
        self.lbl_scan_status.grid(row=0, column=4, sticky='w', padx=4, pady=4)

        frm_scan.columnconfigure(1, weight=1)

        # 过滤输入
        ttk.Label(frm_scan, text='过滤：').grid(row=1, column=0, sticky='w', padx=4, pady=4)
        self.entry_filter = ttk.Entry(frm_scan, textvariable=self.var_filter)
        self.entry_filter.grid(row=1, column=1, sticky='we', padx=4, pady=4)
        btn_clear = ttk.Button(frm_scan, text='清空', command=self._clear_filter)
        btn_clear.grid(row=1, column=2, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                btn_clear.configure(style='warning.TButton')
            except Exception:
                pass
        self.entry_filter.bind('<KeyRelease>', lambda e: self.on_filter())

        # 表格
        columns = ('name', 'host', 'port', 'password', 'file')
        self.tree = ttk.Treeview(frm_scan, columns=columns, show='headings')
        self.tree.heading('name', text='名称')
        self.tree.heading('host', text='主机')
        self.tree.heading('port', text='端口')
        self.tree.heading('password', text='解密密码')
        self.tree.heading('file', text='文件')
        # 列点击排序
        self.tree.heading('name', command=lambda: self._sort_by('name'))
        self.tree.heading('host', command=lambda: self._sort_by('host'))
        self.tree.heading('port', command=lambda: self._sort_by('port'))
        self.tree.heading('password', command=lambda: self._sort_by('password'))
        self.tree.heading('file', command=lambda: self._sort_by('file'))

        self.tree.column('name', width=180, anchor='w')
        self.tree.column('host', width=180, anchor='w')
        self.tree.column('port', width=90, anchor='w')
        self.tree.column('password', width=200, anchor='w')
        self.tree.column('file', width=360, anchor='w')
        # 错误行高亮
        self.tree.tag_configure('error', background='#ffecec')

        vsb = ttk.Scrollbar(frm_scan, orient='vertical', command=self.tree.yview)
        hsb = ttk.Scrollbar(frm_scan, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.tree.grid(row=2, column=0, columnspan=6, sticky='nsew', padx=4, pady=4)
        vsb.grid(row=2, column=6, sticky='ns', padx=(0,4), pady=4)
        hsb.grid(row=3, column=0, columnspan=7, sticky='ew', padx=4, pady=(0,4))
        # 右键菜单与事件绑定
        self.tree.bind('<Button-3>', self._on_tree_right_click)
        self._setup_tree_context_menu()

        frm_scan.rowconfigure(2, weight=1)
        frm_scan.columnconfigure(0, weight=0)
        frm_scan.columnconfigure(1, weight=1)
        frm_scan.columnconfigure(2, weight=0)
        frm_scan.columnconfigure(3, weight=0)
        frm_scan.columnconfigure(4, weight=0)
        frm_scan.columnconfigure(5, weight=0)
        frm_scan.columnconfigure(6, weight=0)

        # 操作区：复制、导出、打开目录
        btn_copy = ttk.Button(frm_scan, text='复制选中行到剪贴板', command=self.on_copy_selected)
        btn_copy.grid(row=4, column=0, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                btn_copy.configure(style='success.TButton')
            except Exception:
                pass
        btn_copy_pwd = ttk.Button(frm_scan, text='复制选中密码', command=self.on_copy_selected_password)
        btn_copy_pwd.grid(row=4, column=1, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                btn_copy_pwd.configure(style='info.TButton')
            except Exception:
                pass
        btn_copy_all = ttk.Button(frm_scan, text='复制全部', command=self.on_copy_all)
        btn_copy_all.grid(row=4, column=2, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                btn_copy_all.configure(style='primary.TButton')
            except Exception:
                pass
        btn_export = ttk.Button(frm_scan, text='导出CSV', command=self.on_export_csv)
        btn_export.grid(row=4, column=3, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                btn_export.configure(style='warning.TButton')
            except Exception:
                pass
        btn_open_dir = ttk.Button(frm_scan, text='打开所在目录', command=self.on_open_selected_dir)
        btn_open_dir.grid(row=4, column=4, sticky='w', padx=4, pady=4)
        if tb is not None:
            try:
                btn_open_dir.configure(style='info.TButton')
            except Exception:
                pass

        # 友好提示：conn 目录位置
        lbl_hint_conn = ttk.Label(
            frm_scan,
            text='提示：conn 目录常见位置：\n1) C:\\Users\\<用户名>\\AppData\\Roaming\\FinalShell\\conn\n2) C:\\Users\\<用户名>\\AppData\\Local\\FinalShell\\conn\n3) C:\\Program Files\\FinalShell\\conn 或 C:\\Program Files (x86)\\FinalShell\\conn\n也可在 FinalShell 设置中查看“数据目录”。',
            justify='left', wraplength=900
        )
        if tb is not None:
            try:
                lbl_hint_conn.configure(style='secondary.TLabel')
            except Exception:
                pass
        lbl_hint_conn.grid(row=5, column=0, columnspan=7, sticky='we', padx=4, pady=(0, 4))

    def on_decode(self):
        b64pwd = self.txt_pwd.get('1.0', tk.END).strip()
        if not b64pwd:
            messagebox.showwarning('提示', '请粘贴 Base64 密文（password 字段）')
            return
        try:
            plain = decode_pass(b64pwd)
            self.lbl_decode_result.configure(text=f'明文密码：{plain}')
        except Exception as e:
            self.lbl_decode_result.configure(text=f'解密失败：{e}')

    def on_browse(self):
        path = filedialog.askdirectory(title='选择 FinalShell conn 目录')
        if path:
            self.entry_conn.delete(0, tk.END)
            self.entry_conn.insert(0, path)
            self.on_scan()

    def on_scan(self):
        path = self.entry_conn.get().strip()
        if not path:
            messagebox.showwarning('提示', '请输入 conn 目录路径')
            return
        if not os.path.isdir(path):
            messagebox.showerror('错误', '目录不存在或不可访问')
            return
        # 开始扫描（后台线程），完成后更新UI
        self.btn_auto.configure(state=tk.DISABLED)
        self.btn_browse.configure(state=tk.DISABLED)
        self.lbl_scan_status.configure(text='扫描中...')
        threading.Thread(target=self._scan_worker, args=(path,), daemon=True).start()

    def on_auto_scan(self):
        # 自动检测 conn 目录并扫描
        paths = self._detect_conn_paths()
        if not paths:
            messagebox.showwarning('提示', '未检测到 FinalShell 默认安装或配置目录，请手动选择')
            return
        if len(paths) == 1:
            path = paths[0]
        else:
            path = self._choose_from_candidates(paths)
            if not path:
                return
        self.entry_conn.delete(0, tk.END)
        self.entry_conn.insert(0, path)
        self.on_scan()

    def _safe_json_read(self, p):
        try:
            with open(p, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            try:
                with open(p, 'r', encoding='gbk', errors='ignore') as f:
                    return json.load(f)
            except Exception:
                return None

    def _extract_fields(self, obj):
        pwd_b64 = obj.get('password') or obj.get('pass') or obj.get('pwd')
        host = obj.get('host') or obj.get('ip') or obj.get('hostname')
        port = obj.get('port') or obj.get('sshPort') or obj.get('tcp_port')
        user = obj.get('user') or obj.get('username') or obj.get('loginName')
        name_in_json = obj.get('name') or obj.get('remark') or obj.get('alias')
        return pwd_b64, host, port, user, name_in_json

    def _scan_worker(self, path):
        items = []
        for name in os.listdir(path):
            if not name.lower().endswith('.json'):
                continue
            p = os.path.join(path, name)
            obj = self._safe_json_read(p)
            if not isinstance(obj, dict):
                continue
            pwd_b64, host, port, user, name_in_json = self._extract_fields(obj)
            decoded = None
            error = None
            if isinstance(pwd_b64, str):
                try:
                    decoded = decode_pass(pwd_b64)
                except Exception as e:
                    error = str(e)
            items.append({
                'file': p,
                'name': name_in_json,
                'host': host,
                'port': port,
                'password': decoded,
                'error': error,
            })
        # 回到主线程更新UI
        def update_ui():
            self.items = items
            self._apply_filter_and_refresh()
            self.lbl_scan_status.configure(text=f'共 {len(items)} 条记录')
            self.btn_auto.configure(state=tk.NORMAL)
            self.btn_browse.configure(state=tk.NORMAL)
        self.root.after(0, update_ui)

    def _apply_filter_and_refresh(self):
        # 根据过滤文本刷新表格显示
        f = (self.var_filter.get() or '').strip().lower()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for item in self.items:
            if f:
                text_blob = ' '.join([
                    str(item.get('name') or ''),
                    str(item.get('host') or ''),
                    str(item.get('file') or '')
                ]).lower()
                if f not in text_blob:
                    continue
            values = [
                item.get('name') or '',
                item.get('host') or '',
                str(item.get('port') or ''),
                item.get('password') or '',
                item.get('file') or '',
            ]
            tags = ()
            if not item.get('password') and item.get('error'):
                tags = ('error',)
            self.tree.insert('', tk.END, values=values, tags=tags)

    def on_filter(self):
        self._apply_filter_and_refresh()

    def _clear_filter(self):
        self.var_filter.set('')
        self._apply_filter_and_refresh()

    def _sort_by(self, col):
        # 列排序，端口按数字，其余按字符串
        reverse = self._sort_states.get(col, False)
        def key_func(it):
            v = it.get(col)
            if col == 'port':
                try:
                    return int(v) if v is not None and v != '' else -1
                except Exception:
                    return -1
            return str(v or '')
        self.items.sort(key=key_func, reverse=reverse)
        self._sort_states[col] = not reverse
        self._apply_filter_and_refresh()

    def on_copy_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('提示', '请先选择一行')
            return
        item_id = sel[0]
        values = self.tree.item(item_id, 'values')
        # 复制：名称\t主机\t端口\t密码\t文件
        text = '\t'.join(str(v) for v in values)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo('提示', '已复制选中行到剪贴板')

    def on_copy_selected_password(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('提示', '请先选择一行')
            return
        values = self.tree.item(sel[0], 'values')
        pwd = values[3] if len(values) >= 4 else ''
        if not pwd:
            messagebox.showinfo('提示', '该行没有解密密码或为空')
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(str(pwd))
        messagebox.showinfo('提示', '已复制密码到剪贴板')

    def on_copy_all(self):
        rows = self._get_current_rows()
        lines = ['\t'.join(str(v) for v in r) for r in rows]
        text = '\n'.join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo('提示', '已复制全部行到剪贴板')

    def _get_current_rows(self):
        rows = []
        for iid in self.tree.get_children():
            rows.append(self.tree.item(iid, 'values'))
        return rows

    def on_export_csv(self):
        rows = self._get_current_rows()
        if not rows:
            messagebox.showinfo('提示', '当前列表为空，无法导出')
            return
        fp = filedialog.asksaveasfilename(
            title='导出为 CSV',
            defaultextension='.csv',
            filetypes=[('CSV 文件', '*.csv')]
        )
        if not fp:
            return
        try:
            with open(fp, 'w', encoding='utf-8-sig', newline='') as f:
                w = csv.writer(f)
                w.writerow(['名称', '主机', '端口', '解密密码', '文件'])
                for r in rows:
                    w.writerow(list(r))
            messagebox.showinfo('提示', f'已导出到：{fp}')
        except Exception as e:
            messagebox.showerror('错误', f'导出失败：{e}')

    def on_open_selected_dir(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('提示', '请先选择一行')
            return
        values = self.tree.item(sel[0], 'values')
        fp = values[-1]
        if not fp or not os.path.isfile(fp):
            messagebox.showwarning('提示', '无法定位文件路径')
            return
        try:
            # 在 Windows 资源管理器中选中文件
            if os.name == 'nt':
                subprocess.run(['explorer', '/select,', fp])
            else:
                # 非 Windows 环境回退为打开目录
                folder = os.path.dirname(fp)
                try:
                    import webbrowser
                    webbrowser.open(folder)
                except Exception:
                    pass
        except Exception as e:
            messagebox.showerror('错误', f'打开目录失败：{e}')

    def _setup_tree_context_menu(self):
        self._tree_menu = tk.Menu(self.root, tearoff=0)
        self._tree_menu.add_command(label='复制选中密码', command=self.on_copy_selected_password)
        self._tree_menu.add_command(label='复制选中整行', command=self.on_copy_selected)
        self._tree_menu.add_separator()
        self._tree_menu.add_command(label='打开所在目录', command=self.on_open_selected_dir)

    def _on_tree_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.tree.focus(iid)
        try:
            self._tree_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._tree_menu.grab_release()

    # 自动检测 conn 目录候选路径
    def _detect_conn_paths(self):
        candidates = []
        # 1) 从注册表读取安装路径
        if winreg is not None:
            candidates.extend(self._detect_from_registry())
        # 2) 常见安装目录（Program Files）
        pf = os.environ.get('ProgramFiles')
        pfx86 = os.environ.get('ProgramFiles(x86)')
        if pf:
            candidates.append(os.path.join(pf, 'FinalShell', 'conn'))
        if pfx86:
            candidates.append(os.path.join(pfx86, 'FinalShell', 'conn'))
        candidates.append(os.path.join('C:\\', 'Program Files', 'FinalShell', 'conn'))
        candidates.append(os.path.join('C:\\', 'Program Files (x86)', 'FinalShell', 'conn'))
        # 3) 用户配置目录（Roaming / Local）
        appdata = os.environ.get('APPDATA')  # C:\\Users\\<user>\\AppData\\Roaming
        localapp = os.environ.get('LOCALAPPDATA')  # C:\\Users\\<user>\\AppData\\Local
        if appdata:
            candidates.append(os.path.join(appdata, 'FinalShell', 'conn'))
        if localapp:
            candidates.append(os.path.join(localapp, 'FinalShell', 'conn'))
        # 4) 直接安装到根目录的情况
        candidates.append(os.path.join('C:\\', 'FinalShell', 'conn'))
        # 去重并过滤存在的目录
        uniq = []
        seen = set()
        for p in candidates:
            if not p:
                continue
            if p in seen:
                continue
            seen.add(p)
            if os.path.isdir(p):
                # 至少包含一个 json 文件才算有效
                try:
                    has_json = any(name.lower().endswith('.json') for name in os.listdir(p))
                except Exception:
                    has_json = False
                if has_json:
                    uniq.append(p)
        return uniq

    def _choose_from_candidates(self, paths):
        # 简单对话框选择候选路径
        top = tk.Toplevel(self.root)
        top.title('选择 conn 目录')
        top.geometry('600x300')
        ttk.Label(top, text='检测到多个候选路径，请选择：').pack(anchor='w', padx=12, pady=8)
        frame = ttk.Frame(top)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        lb = tk.Listbox(frame)
        lb.pack(fill=tk.BOTH, expand=True)
        for p in paths:
            lb.insert(tk.END, p)
        result = {'path': None}
        def on_ok():
            sel = lb.curselection()
            if sel:
                result['path'] = lb.get(sel[0])
            top.destroy()
        def on_cancel():
            top.destroy()
        btns = ttk.Frame(top)
        btns.pack(fill=tk.X, padx=12, pady=8)
        ttk.Button(btns, text='选择', command=on_ok).pack(side=tk.LEFT)
        ttk.Button(btns, text='取消', command=on_cancel).pack(side=tk.LEFT, padx=8)
        top.grab_set()
        self.root.wait_window(top)
        return result['path']

    def _detect_from_registry(self):
        results = []
        roots = [
            (getattr(winreg, 'HKEY_LOCAL_MACHINE'), r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'),
            (getattr(winreg, 'HKEY_LOCAL_MACHINE'), r'SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'),
            (getattr(winreg, 'HKEY_CURRENT_USER'), r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'),
        ]
        for root, subkey in roots:
            try:
                with winreg.OpenKey(root, subkey) as hk:
                    i = 0
                    while True:
                        try:
                            name = winreg.EnumKey(hk, i)
                            i += 1
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(hk, name) as sk:
                                display_name = self._reg_get_str(sk, 'DisplayName')
                                if display_name and 'FinalShell' in display_name:
                                    install_location = self._reg_get_str(sk, 'InstallLocation')
                                    display_icon = self._reg_get_str(sk, 'DisplayIcon')
                                    uninstall_str = self._reg_get_str(sk, 'UninstallString')
                                    # 推断安装根路径
                                    base_dirs = []
                                    if install_location:
                                        base_dirs.append(install_location)
                                    if display_icon:
                                        base_dirs.append(os.path.dirname(self._strip_quotes(display_icon)))
                                    if uninstall_str:
                                        base_dirs.append(os.path.dirname(self._strip_quotes(uninstall_str).split()[0]))
                                    for b in base_dirs:
                                        if b and os.path.isdir(b):
                                            conn = os.path.join(b, 'conn')
                                            if os.path.isdir(conn):
                                                results.append(conn)
                        except OSError:
                            continue
            except OSError:
                continue
        return results

    def _reg_get_str(self, key, name):
        try:
            val, typ = winreg.QueryValueEx(key, name)
            if isinstance(val, str):
                return val
        except Exception:
            return None
        return None

    def _strip_quotes(self, s: str) -> str:
        s = s.strip()
        if s.startswith('"') and '"' in s[1:]:
            # 去掉前后引号
            s = s.strip('"')
        return s

    def _show_help_password(self):
        top = tk.Toplevel(self.root)
        top.title('如何获取加密密码（Base64 密文）')
        top.geometry('640x420')
        text = (
            '获取加密密码（Base64 密文）步骤：\\n\\n'
            '1. 打开 FinalShell 并关闭应用以确保配置已保存。\\n'
            '2. 找到 conn 目录（可点击“自动检测并扫描”，或查看下方 conn 目录位置说明）。\\n'
            '3. 在 conn 目录中，每个连接对应一个 .json 文件，打开目标文件。\\n'
            '4. 查找 "password" 字段，其值即为 Base64 密文；部分版本字段可能为 "pass" 或 "pwd"。\\n'
            '5. 将该值复制并粘贴到上方文本框，点击“解密”。'
        )
        lbl = ttk.Label(top, text=text, justify='left', wraplength=600)
        lbl.pack(fill='both', expand=True, padx=12, pady=12)
        ttk.Button(top, text='知道了', command=top.destroy).pack(pady=8)
        top.grab_set()

    def _show_help_conn_dir(self):
        top = tk.Toplevel(self.root)
        top.title('conn 目录位置')
        top.geometry('640x480')
        text = (
            'conn 目录常见位置：\\n\\n'
            '• Windows（Roaming）：C:\\\\Users\\\\<用户名>\\\\AppData\\\\Roaming\\\\FinalShell\\\\conn\n'
            '• Windows（Local）：C:\\\\Users\\\\<用户名>\\\\AppData\\\\Local\\\\FinalShell\\\\conn\n'
            '• Windows（安装目录）：C:\\\\Program Files\\\\FinalShell\\\\conn 或 C:\\\\Program Files (x86)\\\\FinalShell\\\\conn\n'
            '• 有时也可能在：C:\\\\FinalShell\\\\conn\\n\\n'
            '快速定位方法：\\n'
            '1. 点击窗口中的“自动检测并扫描”尝试自动定位。\\n'
            '2. 在 FinalShell 的设置/选项中查看“数据目录”。\\n'
            '3. 手动搜索：在资源管理器搜索 *.json 并筛选包含 "host"/"password" 的文件。\\n\\n'
            '找到后，将目录路径填入上方输入框，或直接使用“手动选择并扫描”。'
        )
        lbl = ttk.Label(top, text=text, justify='left', wraplength=600)
        lbl.pack(fill='both', expand=True, padx=12, pady=12)
        ttk.Button(top, text='知道了', command=top.destroy).pack(pady=8)
        top.grab_set()


if __name__ == '__main__':
    # 使用 ttkbootstrap 的 Window 以统一主题（不可用时降级）
    if tb is not None:
        try:
            root = tb.Window(themename='minty')
        except Exception:
            root = tk.Tk()
    else:
        root = tk.Tk()
    app = FinalShellGUI(root)
    root.mainloop()