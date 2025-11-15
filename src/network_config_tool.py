#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows一键网络配置工具
功能：图形化界面管理网络配置，支持管理员权限自提权、历史记录、异常处理
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import re
import json
import logging
from collections import deque
import ctypes
import sys
import os
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_config.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

class NetworkConfigTool:
    """网络配置工具主类"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("网络配置工具 v1.0")
        self.root.geometry("400x300")
        
        # 窗口居中
        self.center_window()
        
        # 网络接口名称
        self.interface_name = "WLAN"  # 根据实际网络接口修改
        
        # 历史记录
        self.history_file = "config.json"
        self.max_history = 5
        self.history = self.load_history()
        self.history_window = None  # 初始化历史记录窗口引用
        
        # 创建GUI
        self.create_gui()
        
        self.get_current_config()

        # 初始化状态
        self.update_status("就绪")
        
    def center_window(self):
        """窗口居中显示"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def create_gui(self):
        """创建图形界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # 输入框标签和默认值
        fields = [
            ("IP地址:", "192.168.1.100"),
            ("子网掩码:", "255.255.255.0"),
            ("网关:", "192.168.1.1"),
            ("DNS服务器:", "8.8.8.8")
        ]
        
        self.entries = {}
        for i, (label, default) in enumerate(fields):
            # 标签
            ttk.Label(main_frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=5)
            
            # 输入框
            entry = ttk.Entry(main_frame)
            entry.insert(0, default)
            entry.grid(row=i, column=1, sticky=(tk.W, tk.E), pady=5)
            self.entries[label.strip(':')] = entry
        
        # 网络速度显示
        self.speed_var = tk.StringVar()
        self.speed_var.set("握手速度: 未知")
        speed_label = ttk.Label(main_frame, textvariable=self.speed_var, font=('Arial', 9, 'bold'), foreground='blue')
        speed_label.grid(row=len(fields), column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=len(fields)+1, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="确定", command=self.apply_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="获取", command=self.get_current_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="历史", command=self.show_history).pack(side=tk.LEFT, padx=5)
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=len(fields)+2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
    def update_status(self, message):
        """更新状态栏"""
        self.status_var.set(message)
        self.root.update()
        
    def validate_ip(self, ip):
        """验证IP地址格式"""
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        if not match:
            return False
        
        for part in match.groups():
            if not (0 <= int(part) <= 255):
                return False
        return True
        
    def validate_inputs(self):
        """验证所有输入"""
        ip = self.entries["IP地址"].get().strip()
        mask = self.entries["子网掩码"].get().strip()
        gateway = self.entries["网关"].get().strip()
        dns = self.entries["DNS服务器"].get().strip()
        
        if not self.validate_ip(ip):
            messagebox.showerror("错误", "请输入有效的IP地址")
            return False
            
        if not self.validate_ip(mask):
            messagebox.showerror("错误", "请输入有效的子网掩码")
            return False
            
        if not self.validate_ip(gateway):
            messagebox.showerror("错误", "请输入有效的网关地址")
            return False
            
        if dns and not self.validate_ip(dns):
            messagebox.showerror("错误", "请输入有效的DNS服务器地址")
            return False
            
        return True
        
    def run_netsh(self, command):
        """执行netsh命令"""
        try:
            # 隐藏控制台窗口
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                shell=True,
                startupinfo=startupinfo
            )
            logging.info(f"命令执行成功: {command}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"命令执行失败: {command}\n错误: {e.stderr}")
            raise Exception(f"netsh命令失败: {e.stderr}")
            
    def apply_config(self):
        """应用网络配置"""
        if not self.validate_inputs():
            return
            
        ip = self.entries["IP地址"].get().strip()
        mask = self.entries["子网掩码"].get().strip()
        gateway = self.entries["网关"].get().strip()
        dns = self.entries["DNS服务器"].get().strip()
        
        try:
            self.update_status("正在应用配置...")
            
            # 设置IP地址、子网掩码和网关
            command1 = f'netsh interface ip set address name="{self.interface_name}" static {ip} {mask} {gateway}'
            self.run_netsh(command1)
            
            # 设置DNS服务器
            if dns:
                command2 = f'netsh interface ip set dns name="{self.interface_name}" static {dns}'
                self.run_netsh(command2)
            
            # 保存到历史记录
            self.save_to_history(ip, mask, gateway, dns)
            
            self.update_status("配置应用成功")
            messagebox.showinfo("成功", "网络配置已成功应用")
            logging.info(f"成功应用配置: IP={ip}, Mask={mask}, Gateway={gateway}, DNS={dns}")
            
        except Exception as e:
            self.update_status("配置失败")
            messagebox.showerror("错误", f"配置失败:\n{str(e)}")
            logging.error(f"配置失败: {str(e)}")
            
    def get_network_speed(self):
        """获取WIFI或LAN网络接口的握手速度"""
        try:
            # 使用PowerShell获取所有网络接口的速度
            ps_command = 'Get-NetAdapter | Select-Object Name, LinkSpeed'
            command = f'powershell -NoProfile -NonInteractive -WindowStyle Hidden -Command "{ps_command}"'
            output = self.run_netsh(command)
            
            logging.debug(f"PowerShell输出:\n{output}")
            
            # 解析速度信息，查找WLAN或以太网
            lines = output.strip().split('\n')
            for i, line in enumerate(lines):
                line = line.strip()
                # 查找包含WLAN或以太网的行
                if 'WLAN' in line or '以太网' in line:
                    # 查找速度值（数字+单位）
                    speed_match = re.search(r'(\d+(?:\.\d+)?)\s*(Mbps|Gbps|bps)', line)
                    if speed_match:
                        speed = speed_match.group(0)
                        logging.info(f"网络接口握手速度: {speed}")
                        return speed
            
            logging.warning("未能获取WIFI或LAN的握手速度")
            return "未知"
                
        except Exception as e:
            logging.error(f"获取网络速度失败: {str(e)}")
            return "未知"
            
    def get_current_config(self):
        """获取当前网络配置"""
        try:
            self.update_status("正在获取当前配置...")
            
            # 获取网络速度
            speed = self.get_network_speed()
            self.speed_var.set(f"握手速度: {speed}")
            
            command = f'netsh interface ip show config name="{self.interface_name}"'
            output = self.run_netsh(command)
            
            # 调试：记录原始输出
            logging.debug(f"netsh命令输出:\n{output}")
            
            # 解析输出 - 支持DHCP和静态配置两种格式
            ip_pattern = r'IP Address:\s+([\d\.]+)'
            mask_pattern = r'Subnet Prefix:\s+[\d\.]+/\d+\s+\(mask ([\d\.]+)\)'
            gateway_pattern = r'Default Gateway:\s+([\d\.]+)'
            dns_pattern = r'DNS servers configured through DHCP:\s+([\d\.]+)'
            
            # 如果没有找到DHCP的DNS，尝试查找静态DNS
            if not re.search(dns_pattern, output):
                dns_pattern = r'Statically Configured DNS Servers:\s+([\d\.]+)'
            
            ip_match = re.search(ip_pattern, output)
            mask_match = re.search(mask_pattern, output)
            gateway_match = re.search(gateway_pattern, output)
            dns_match = re.search(dns_pattern, output)
            
            # 调试：记录匹配结果
            logging.debug(f"IP匹配: {ip_match.group(1) if ip_match else '未找到'}")
            logging.debug(f"掩码匹配: {mask_match.group(1) if mask_match else '未找到'}")
            logging.debug(f"网关匹配: {gateway_match.group(1) if gateway_match else '未找到'}")
            logging.debug(f"DNS匹配: {dns_match.group(1) if dns_match else '未找到'}")
            
            updated = False
            
            if ip_match:
                self.entries["IP地址"].delete(0, tk.END)
                self.entries["IP地址"].insert(0, ip_match.group(1))
                updated = True
                
            if mask_match:
                self.entries["子网掩码"].delete(0, tk.END)
                self.entries["子网掩码"].insert(0, mask_match.group(1))
                updated = True
                
            if gateway_match:
                self.entries["网关"].delete(0, tk.END)
                self.entries["网关"].insert(0, gateway_match.group(1))
                updated = True
                
            if dns_match:
                self.entries["DNS服务器"].delete(0, tk.END)
                self.entries["DNS服务器"].insert(0, dns_match.group(1))
                updated = True
            
            if updated:
                self.update_status("配置获取成功")
                logging.info("成功获取当前网络配置")
            else:
                self.update_status("未找到配置信息")
                logging.warning("未从netsh输出中找到配置信息")
                # 显示原始输出供调试
                messagebox.showwarning("警告", f"未能解析网络配置信息。\n请检查网络接口名称是否正确。\n\n原始输出:\n{output[:500]}...")
            
        except Exception as e:
            self.update_status("获取失败")
            messagebox.showerror("错误", f"获取配置失败:\n{str(e)}")
            logging.error(f"获取配置失败: {str(e)}")
            
    def save_to_history(self, ip, mask, gateway, dns):
        """保存配置到历史记录"""
        config = {
            "ip": ip,
            "mask": mask,
            "gateway": gateway,
            "dns": dns,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.history.append(config)
        self.save_history()
        
    def load_history(self):
        """加载历史记录"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return deque(data.get("history", []), maxlen=self.max_history)
        except Exception as e:
            logging.error(f"加载历史记录失败: {str(e)}")
            
        return deque(maxlen=self.max_history)
        
    def save_history(self):
        """保存历史记录到文件"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump({"history": list(self.history)}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logging.error(f"保存历史记录失败: {str(e)}")
            
    def show_history(self):
        """显示历史记录窗口"""
        if not self.history:
            messagebox.showinfo("历史记录", "暂无历史记录")
            return
        
        # 如果历史记录窗口已存在，则刷新内容并聚焦到该窗口
        if self.history_window and self.history_window.winfo_exists():
            # 查找列表框控件
            for child in self.history_window.winfo_children():
                if isinstance(child, ttk.Frame):
                    for subchild in child.winfo_children():
                        if isinstance(subchild, tk.Listbox):
                            # 清空并重新填充历史记录
                            subchild.delete(0, tk.END)
                            for i, config in enumerate(self.history, 1):
                                display_text = f"{i:2d}. IP: {config['ip']} | 掩码: {config['mask']} | 网关: {config['gateway']} | DNS: {config['dns']} | {config['timestamp']}"
                                subchild.insert(tk.END, display_text)
                            break
            
            self.history_window.lift()
            self.history_window.focus()
            return
        
        # 创建新的历史记录窗口
        self.history_window = tk.Toplevel(self.root)
        self.history_window.title("历史记录")
        self.history_window.geometry("500x400")
        self.history_window.minsize(400, 300)
        self.history_window.configure(bg='#f0f0f0')
        
        # 设置窗口关闭事件
        def on_history_window_close():
            self.history_window.destroy()
            self.history_window = None
            
        self.history_window.protocol("WM_DELETE_WINDOW", on_history_window_close)
        
        # 主框架
        history_frame = ttk.Frame(self.history_window, padding="15")
        history_frame.pack(fill=tk.BOTH, expand=True)
        
        # 标题
        title_label = ttk.Label(history_frame, text="配置历史记录", font=('Segoe UI', 14, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # 列表框框架
        list_frame = ttk.Frame(history_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # 列表框和滚动条
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(list_frame, width=60, height=15, font=('Segoe UI', 9),
                            yscrollcommand=scrollbar.set, selectmode=tk.SINGLE)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)
        
        # 填充历史记录
        for i, config in enumerate(self.history, 1):
            display_text = f"{i:2d}. IP: {config['ip']} | 掩码: {config['mask']} | 网关: {config['gateway']} | DNS: {config['dns']} | {config['timestamp']}"
            listbox.insert(tk.END, display_text)
        
        # 按钮框架
        button_frame = ttk.Frame(history_frame)
        button_frame.pack(pady=10)
        
        # 恢复按钮
        def restore_config():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("警告", "请选择要恢复的配置")
                return
                
            index = selection[0]
            config = self.history[index]
            
            # 确认对话框
            if messagebox.askyesno("确认恢复", f"确定要恢复以下配置吗？\n\nIP: {config['ip']}\n掩码: {config['mask']}\n网关: {config['gateway']}\nDNS: {config['dns']}"):
                # 填充到输入框
                self.entries["IP地址"].delete(0, tk.END)
                self.entries["IP地址"].insert(0, config["ip"])
                
                self.entries["子网掩码"].delete(0, tk.END)
                self.entries["子网掩码"].insert(0, config["mask"])
                
                self.entries["网关"].delete(0, tk.END)
                self.entries["网关"].insert(0, config["gateway"])
                
                self.entries["DNS服务器"].delete(0, tk.END)
                self.entries["DNS服务器"].insert(0, config["dns"])
                
                self.history_window.destroy()
                self.history_window = None
                self.update_status("已加载历史配置")
                self.apply_config()
                self.update_status("已恢复历史配置")
        
        # 删除按钮
        def delete_config():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("警告", "请选择要删除的配置")
                return
            
            if messagebox.askyesno("确认删除", "确定要删除选中的配置吗？"):
                index = selection[0]
                # 从历史记录中删除
                history_list = list(self.history)
                del history_list[index]
                self.history = deque(history_list, maxlen=self.max_history)
                self.save_history()
                
                # 更新列表框
                listbox.delete(index)
                if not self.history:
                    self.history_window.destroy()
                    self.history_window = None
                    messagebox.showinfo("提示", "历史记录已清空")
        
        # 清空按钮
        def clear_history():
            if messagebox.askyesno("确认清空", "确定要清空所有历史记录吗？"):
                self.history.clear()
                self.save_history()
                self.history_window.destroy()
                self.history_window = None
                messagebox.showinfo("提示", "历史记录已清空")
        
        # 创建按钮
        btn_restore = ttk.Button(button_frame, text="恢复选中配置", command=restore_config)
        btn_restore.pack(side=tk.LEFT, padx=5)
        
        btn_delete = ttk.Button(button_frame, text="删除选中", command=delete_config)
        btn_delete.pack(side=tk.LEFT, padx=5)
        
        btn_clear = ttk.Button(button_frame, text="清空历史", command=clear_history)
        btn_clear.pack(side=tk.LEFT, padx=5)
        
        btn_close = ttk.Button(button_frame, text="关闭", command=on_history_window_close)
        btn_close.pack(side=tk.LEFT, padx=5)

def is_admin():
    """检查是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """以管理员权限重新运行程序"""
    try:
        script = sys.argv[0]
        params = ' '.join(sys.argv[1:])
        
        # 使用ShellExecuteEx以管理员权限运行
        import shell32
        shell32.ShellExecuteEx(
            lpVerb='runas',
            lpFile=sys.executable,
            lpParameters=f'"{script}" {params}'
        )
        return True
    except Exception as e:
        logging.error(f"提权失败: {str(e)}")
        return False

def main():
    """主函数"""
    # 检查管理员权限
    if not is_admin():
        messagebox.showwarning("权限警告", "需要管理员权限才能修改网络配置\n程序将尝试以管理员权限重新启动")
        
        # 重新以管理员权限运行
        try:
            import ctypes
            script = sys.argv[0]
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}"', None, 1
            )
            sys.exit(0)
        except Exception as e:
            messagebox.showerror("错误", f"无法获取管理员权限:\n{str(e)}")
            sys.exit(1)
    
    # 创建主窗口
    root = tk.Tk()
    app = NetworkConfigTool(root)
    
    # 运行程序
    root.mainloop()

if __name__ == "__main__":
    main()