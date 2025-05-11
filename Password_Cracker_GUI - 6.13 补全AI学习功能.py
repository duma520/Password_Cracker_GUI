import os
import sys
import json
import subprocess
import codecs
import random
import string
import math
import numpy as np
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit,
                             QProgressBar, QMessageBox, QCheckBox, QGroupBox, QComboBox,
                             QListWidget, QListWidgetItem, QAbstractItemView, QMenu, QAction,
                             QSplitter, QSizePolicy, QTabWidget, QSpinBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QDir, QTimer
from PyQt5.QtGui import QIcon, QColor
from threading import Lock
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from collections import defaultdict

# AI密码生成器类
class AIPasswordGenerator:
    def __init__(self):
        self.password_patterns = []
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 3))
        self.kmeans = None
        self.cluster_patterns = defaultdict(list)
        self.common_substitutions = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['$', '5'],
            't': ['7']
        }
    
    def learn_from_multiple_dictionaries(self, dict_paths, progress_callback=None):
        """从多个字典文件学习密码模式"""
        all_passwords = []
        total_files = len(dict_paths)
        
        for i, dict_path in enumerate(dict_paths, 1):
            try:
                with codecs.open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                    all_passwords.extend(passwords)
                
                if progress_callback:
                    progress_callback(i, total_files)
                    
            except Exception as e:
                print(f"读取字典文件 {dict_path} 失败: {str(e)}")
                continue
        
        if len(all_passwords) < 100:  # 样本太少不学习
            return False
            
        # 提取密码特征
        features = self.vectorizer.fit_transform(all_passwords)
        
        # 聚类分析密码模式
        n_clusters = min(20, len(all_passwords) // 50)
        if n_clusters < 2:
            return False
            
        self.kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        clusters = self.kmeans.fit_predict(features)
        
        # 按聚类分组密码
        self.cluster_patterns = defaultdict(list)
        for pwd, cluster in zip(all_passwords, clusters):
            self.cluster_patterns[cluster].append(pwd)
        
        # 提取常见模式
        self.password_patterns = []
        for cluster, pwds in self.cluster_patterns.items():
            if len(pwds) > 10:  # 只考虑有足够样本的聚类
                # 分析长度分布
                lengths = [len(pwd) for pwd in pwds]
                avg_len = int(np.mean(lengths))
                
                # 分析字符组成
                char_types = defaultdict(int)
                for pwd in pwds:
                    for c in pwd:
                        if c.isdigit():
                            char_types['digit'] += 1
                        elif c.isalpha():
                            if c.isupper():
                                char_types['upper'] += 1
                            else:
                                char_types['lower'] += 1
                        else:
                            char_types['special'] += 1
                
                # 保存模式
                pattern = {
                    'length': avg_len,
                    'digits': char_types['digit'] / sum(char_types.values()) if sum(char_types.values()) > 0 else 0,
                    'uppers': char_types['upper'] / sum(char_types.values()) if sum(char_types.values()) > 0 else 0,
                    'specials': char_types['special'] / sum(char_types.values()) if sum(char_types.values()) > 0 else 0,
                    'examples': random.sample(pwds, min(5, len(pwds)))
                }
                self.password_patterns.append(pattern)

                
        return len(self.password_patterns) > 0

    def learn_from_dictionary(self, dict_path):
        """从字典文件学习密码模式"""
        try:
            with codecs.open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if len(passwords) < 10:  # 太小的样本不学习
                return
            
            # 提取密码特征
            features = self.vectorizer.fit_transform(passwords)
            
            # 聚类分析密码模式
            n_clusters = min(10, len(passwords) // 10)
            if n_clusters < 2:
                return
                
            self.kmeans = KMeans(n_clusters=n_clusters, random_state=42)
            clusters = self.kmeans.fit_predict(features)
            
            # 按聚类分组密码
            self.cluster_patterns = defaultdict(list)
            for pwd, cluster in zip(passwords, clusters):
                self.cluster_patterns[cluster].append(pwd)
            
            # 提取常见模式
            self.password_patterns = []
            for cluster, pwds in self.cluster_patterns.items():
                if len(pwds) > 5:  # 只考虑有足够样本的聚类
                    # 分析长度分布
                    lengths = [len(pwd) for pwd in pwds]
                    avg_len = int(np.mean(lengths))
                    
                    # 分析字符组成
                    char_types = defaultdict(int)
                    for pwd in pwds:
                        for c in pwd:
                            if c.isdigit():
                                char_types['digit'] += 1
                            elif c.isalpha():
                                if c.isupper():
                                    char_types['upper'] += 1
                                else:
                                    char_types['lower'] += 1
                            else:
                                char_types['special'] += 1
                    
                    # 保存模式
                    pattern = {
                        'length': avg_len,
                        'digits': char_types['digit'] / sum(char_types.values()) if sum(char_types.values()) > 0 else 0,
                        'uppers': char_types['upper'] / sum(char_types.values()) if sum(char_types.values()) > 0 else 0,
                        'specials': char_types['special'] / sum(char_types.values()) if sum(char_types.values()) > 0 else 0,
                        'examples': random.sample(pwds, min(5, len(pwds)))
                    }
                    self.password_patterns.append(pattern)
                    
        except Exception as e:
            print(f"AI学习失败: {str(e)}")
    
    def generate_passwords(self, count=100):
        """基于学习到的模式生成密码"""
        passwords = []
        
        if not self.password_patterns:
            # 如果没有学习到模式，生成随机密码
            for _ in range(count):
                length = random.randint(6, 12)
                pwd = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%^&*', k=length))
                passwords.append(pwd)
            return passwords
        
        # 基于学习到的模式生成密码
        for _ in range(count):
            # 随机选择一个模式
            pattern = random.choice(self.password_patterns)
            
            # 基于模式生成密码
            length = max(4, min(20, pattern['length'] + random.randint(-2, 2)))
            pwd = []
            
            # 根据概率添加不同类型的字符
            while len(pwd) < length:
                r = random.random()
                if r < pattern['digits']:
                    pwd.append(random.choice(string.digits))
                elif r < pattern['digits'] + pattern['uppers']:
                    pwd.append(random.choice(string.ascii_uppercase))
                elif r < pattern['digits'] + pattern['uppers'] + pattern['specials']:
                    pwd.append(random.choice('!@#$%^&*'))
                else:
                    pwd.append(random.choice(string.ascii_lowercase))
            
            # 随机应用字符替换
            pwd_str = ''.join(pwd)
            if random.random() < 0.3:  # 30%概率应用替换
                for orig, subs in self.common_substitutions.items():
                    if orig in pwd_str and random.random() < 0.5:
                        pwd_str = pwd_str.replace(orig, random.choice(subs), 1)
            
            # 随机添加后缀数字
            if random.random() < 0.4:  # 40%概率添加数字后缀
                pwd_str += ''.join(random.choices(string.digits, k=random.randint(1, 3)))
            
            passwords.append(pwd_str)
        
        return passwords

# 破解线程类
class ArchiveCracker(QThread):
    progress_updated = pyqtSignal(int, int, int)  # current, total, file_index
    status_message = pyqtSignal(str)
    password_found = pyqtSignal(str, str)  # archive_path, password
    finished = pyqtSignal(str, bool)  # archive_path, success
    current_file_changed = pyqtSignal(str)

    def __init__(self, archive_path, dictionary_paths, recursive=False, seven_zip_path="7z.exe", 
                 resume_info=None, max_workers=1, ai_enabled=False, ai_generator=None):
        super().__init__()
        self.archive_path = archive_path
        self.dictionary_paths = dictionary_paths
        self.recursive = recursive
        self.seven_zip_path = seven_zip_path
        self._stop_flag = False
        self._pause_flag = False
        self.lock = Lock()
        self.total_passwords = 0
        self.tried_passwords = 0
        self.found_password = None
        self.current_dict_index = 0
        self.current_line = 0
        self.resume_info = resume_info or {}
        self.max_workers = max_workers
        self.ai_enabled = ai_enabled
        self.ai_generator = ai_generator or AIPasswordGenerator()
        self.ai_passwords = []
        self.ai_index = 0

    def stop(self):
        with self.lock:
            self._stop_flag = True

    def pause(self):
        with self.lock:
            self._pause_flag = True

    def resume(self):
        with self.lock:
            self._pause_flag = False

    def is_paused(self):
        with self.lock:
            return self._pause_flag

    def is_stopped(self):
        with self.lock:
            return self._stop_flag

    def count_passwords(self, file_path):
        try:
            with codecs.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except:
            try:
                with codecs.open(file_path, 'r', encoding='gbk', errors='ignore') as f:
                    return sum(1 for _ in f)
            except:
                return 0

    def try_password(self, password):
        try:
            cmd = [self.seven_zip_path, 't', '-p' + password, self.archive_path]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                return True
            return False
        except Exception as e:
            return False

    def process_dictionary(self, dict_path, dict_index):
        try:
            # 检查是否有恢复点
            resume_line = 0
            if str(dict_index) in self.resume_info:
                if self.resume_info[str(dict_index)]["file"] == dict_path:
                    resume_line = self.resume_info[str(dict_index)]["line"]
                    self.status_message.emit(f"从字典 {dict_path} 的第 {resume_line} 行恢复")

            # 如果是AI模式且是第一个字典，先学习模式
            if self.ai_enabled and dict_index == 0 and os.path.isfile(dict_path):
                self.status_message.emit(f"AI正在学习字典模式: {dict_path}")
                self.ai_generator.learn_from_dictionary(dict_path)
                self.ai_passwords = self.ai_generator.generate_passwords(1000)
                self.status_message.emit(f"AI已生成 {len(self.ai_passwords)} 个智能密码")

            # 尝试UTF-8编码
            try:
                with codecs.open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except:
                # 尝试GBK编码
                with codecs.open(dict_path, 'r', encoding='gbk', errors='ignore') as f:
                    lines = f.readlines()

            self.current_file_changed.emit(f"当前字典: {os.path.basename(dict_path)}")
            
            # 使用线程池处理密码尝试
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for i, line in enumerate(lines):
                    if i < resume_line:
                        continue

                    while self.is_paused() and not self.is_stopped():
                        self.msleep(100)

                    if self.is_stopped():
                        # 保存当前进度
                        self.resume_info[str(dict_index)] = {
                            "file": dict_path,
                            "line": i
                        }
                        return False

                    password = line.strip()
                    if not password:
                        continue

                    futures.append(executor.submit(self.try_password_with_progress, password, i))

                # 如果是AI模式，添加生成的密码
                if self.ai_enabled and dict_index == 0:
                    for pwd in self.ai_passwords:
                        if self.is_stopped():
                            break
                        futures.append(executor.submit(self.try_password_with_progress, pwd, -1))  # -1表示AI生成的密码

                for future in as_completed(futures):
                    if self.is_stopped():
                        return False

                    result, password, line_num = future.result()
                    if result:
                        self.found_password = password
                        self.password_found.emit(self.archive_path, password)
                        return True

        except Exception as e:
            self.status_message.emit(f"处理字典文件 {dict_path} 时出错: {str(e)}")
            return False

    def try_password_with_progress(self, password, line_num):
        result = self.try_password(password)
        
        with self.lock:
            self.tried_passwords += 1
            progress = int((self.tried_passwords / self.total_passwords) * 100)
            self.progress_updated.emit(progress, self.tried_passwords, self.current_dict_index)
        
        return (result, password, line_num)

    def run(self):
        try:
            # 检查7z.exe是否存在
            if not os.path.exists(self.seven_zip_path):
                self.status_message.emit(f"错误: 7z.exe 未找到 ({self.seven_zip_path})")
                self.finished.emit(self.archive_path, False)
                return

            # 检查压缩文件是否存在
            if not os.path.exists(self.archive_path):
                self.status_message.emit(f"错误: 压缩文件未找到 ({self.archive_path})")
                self.finished.emit(self.archive_path, False)
                return

            # 计算总密码数
            self.total_passwords = 0
            for i, dict_path in enumerate(self.dictionary_paths):
                if os.path.isfile(dict_path):
                    # 如果是恢复模式，只计算未尝试的部分
                    if str(i) in self.resume_info:
                        if self.resume_info[str(i)]["file"] == dict_path:
                            total_lines = self.count_passwords(dict_path)
                            resume_line = self.resume_info[str(i)]["line"]
                            self.total_passwords += (total_lines - resume_line)
                        else:
                            self.total_passwords += self.count_passwords(dict_path)
                    else:
                        self.total_passwords += self.count_passwords(dict_path)
                elif os.path.isdir(dict_path) and self.recursive:
                    for root, _, files in os.walk(dict_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            self.total_passwords += self.count_passwords(file_path)

            # 如果是AI模式，增加生成的密码数量
            if self.ai_enabled:
                self.total_passwords += 1000  # AI生成的密码数量

            if self.total_passwords == 0:
                self.status_message.emit("错误: 没有找到有效的字典文件或密码")
                self.finished.emit(self.archive_path, False)
                return

            # 处理字典文件
            for i, dict_path in enumerate(self.dictionary_paths):
                self.current_dict_index = i
                if os.path.isfile(dict_path):
                    if self.process_dictionary(dict_path, i):
                        self.finished.emit(self.archive_path, True)
                        return
                elif os.path.isdir(dict_path) and self.recursive:
                    for root, _, files in os.walk(dict_path):
                        for file in files:
                            if self.is_stopped():
                                self.finished.emit(self.archive_path, False)
                                return

                            file_path = os.path.join(root, file)
                            if self.process_dictionary(file_path, i):
                                self.finished.emit(self.archive_path, True)
                                return

            self.status_message.emit(f"{self.archive_path}: 密码未找到")
            self.finished.emit(self.archive_path, False)
        except Exception as e:
            print(f"[DEBUG] 发生错误: {str(e)}")
            self.status_message.emit(f"发生错误: {str(e)}")
            self.finished.emit(self.archive_path, False)


class PasswordCrackerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("7z压缩文件密码破解工具")
        self.setGeometry(100, 100, 1200, 800)
        self.cracker_threads = {}
        self.settings = QSettings("7zCracker", "PasswordCracker")
        self.config_file = "cracker_config.json"
        self.password_log_file = "found_passwords.log"
        self.resume_file = "cracker_resume.json"
        self.max_threads = os.cpu_count() or 4
        self.ai_generator = AIPasswordGenerator()

        # 添加这行初始化代码
        self.recursive_check = QCheckBox("递归搜索目录中的字典文件")

        # 先初始化主UI
        self.init_ui()
        
        # 然后初始化AI学习UI
        self.init_ai_learning_ui()
        
        self.load_settings()
        
        # 定时器用于更新界面
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_active_tasks)
        self.update_timer.start(1000)

    def show_ai_dict_context_menu(self, pos):
        """显示AI字典列表的右键菜单"""
        menu = QMenu()
        
        # 排序菜单
        sort_menu = QMenu("排序方式", self)
        
        sort_by_name = QAction("按文件名(A-Z)", self)
        sort_by_name.triggered.connect(lambda: self.sort_ai_dict_items('name'))
        
        sort_by_name_desc = QAction("按文件名(Z-A)", self)
        sort_by_name_desc.triggered.connect(lambda: self.sort_ai_dict_items('name_desc'))
        
        sort_menu.addAction(sort_by_name)
        sort_menu.addAction(sort_by_name_desc)
        
        menu.addMenu(sort_menu)
        menu.addSeparator()
        
        remove_action = QAction("移除选中", self)
        remove_action.triggered.connect(self.remove_selected_ai_dicts)
        menu.addAction(remove_action)
        
        menu.exec_(self.ai_dict_list.mapToGlobal(pos))

    def sort_ai_dict_items(self, by='name'):
        """排序AI字典列表"""
        items = []
        for i in range(self.ai_dict_list.count()):
            item = self.ai_dict_list.item(i)
            path = item.data(Qt.UserRole)
            items.append({
                'item': item,
                'path': path,
                'name': os.path.basename(path)
            })
        
        if by == 'name':
            items.sort(key=lambda x: x['name'].lower())
        elif by == 'name_desc':
            items.sort(key=lambda x: x['name'].lower(), reverse=True)
        
        self.ai_dict_list.clear()
        for item_data in items:
            item = item_data['item']
            path = item_data['path']
            
            new_item = QListWidgetItem(os.path.basename(path))
            new_item.setData(Qt.UserRole, path)
            self.ai_dict_list.addItem(new_item)

    def remove_selected_ai_dicts(self):
        """移除选中的AI字典"""
        for item in self.ai_dict_list.selectedItems():
            self.ai_dict_list.takeItem(self.ai_dict_list.row(item))

    def clear_ai_dict_list(self):
        """清空AI字典列表"""
        self.ai_dict_list.clear()

    def add_ai_dict_files(self):
        """添加字典文件到AI学习列表"""
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "选择字典文件", "",
            "文本文件 (*.txt *.dic *.lst);;所有文件 (*.*)")
            
        for file_path in file_paths:
            if not any(self.ai_dict_list.item(i).data(Qt.UserRole) == file_path 
                    for i in range(self.ai_dict_list.count())):
                item = QListWidgetItem(os.path.basename(file_path))
                item.setData(Qt.UserRole, file_path)
                self.ai_dict_list.addItem(item)


    def init_ai_learning_ui(self):
        """初始化AI学习相关UI"""
        # 获取主窗口中的选项卡控件
        tab_widget = self.findChild(QTabWidget)
        
        # 确保我们找到了选项卡控件
        if not tab_widget:
            print("错误: 未找到选项卡控件")
            return
        
        # 获取AI设置选项卡(应该是第二个选项卡)
        ai_tab = tab_widget.widget(1)
        
        # 确保我们找到了AI选项卡
        if not ai_tab:
            print("错误: 未找到AI设置选项卡")
            return
        
        # 获取AI选项卡的布局
        ai_layout = ai_tab.layout()
        
        # 修改字典选择区域
        self.ai_dict_group = QGroupBox("选择学习字典")
        self.ai_dict_layout = QVBoxLayout()
        
        # 改为使用 QListWidget 并启用复选框
        self.ai_dict_list = QListWidget()
        self.ai_dict_list.setSelectionMode(QAbstractItemView.MultiSelection)
        self.ai_dict_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ai_dict_list.customContextMenuRequested.connect(self.show_ai_dict_context_menu)

        # 设置项目为可选
        self.ai_dict_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        for i in range(self.ai_dict_list.count()):
            item = self.ai_dict_list.item(i)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)  # 默认选中

        # 添加按钮
        ai_dict_btn_layout = QHBoxLayout()
        self.ai_add_dict_btn = QPushButton("添加字典")
        self.ai_add_dict_btn.clicked.connect(self.add_ai_dict_files)
        self.ai_remove_btn = QPushButton("移除选中")
        self.ai_remove_btn.clicked.connect(self.remove_selected_ai_dicts)
        self.ai_clear_btn = QPushButton("清空列表")
        self.ai_clear_btn.clicked.connect(self.clear_ai_dict_list)
        
        ai_dict_btn_layout.addWidget(self.ai_add_dict_btn)
        ai_dict_btn_layout.addWidget(self.ai_remove_btn)
        ai_dict_btn_layout.addWidget(self.ai_clear_btn)
        
        self.ai_dict_layout.addWidget(self.ai_dict_list)
        self.ai_dict_layout.addLayout(ai_dict_btn_layout)
        self.ai_dict_group.setLayout(self.ai_dict_layout)
        
        # 添加生成设置区域
        self.ai_gen_group = QGroupBox("密码生成设置")
        self.ai_gen_layout = QVBoxLayout()
        
        # 密码数量设置
        count_layout = QHBoxLayout()
        count_layout.addWidget(QLabel("生成密码数量:"))
        self.ai_count_spin = QSpinBox()
        self.ai_count_spin.setRange(1, 1000000)
        self.ai_count_spin.setValue(20000)
        self.ai_count_spin.setSpecialValueText("无限制")
        count_layout.addWidget(self.ai_count_spin)
        count_layout.addStretch()
        
        # 生成按钮
        self.ai_generate_btn = QPushButton("开始学习并生成密码")
        self.ai_generate_btn.clicked.connect(self.start_ai_learning)
        
        # 进度条
        self.ai_progress_bar = QProgressBar()
        self.ai_progress_bar.setVisible(False)
        
        self.ai_gen_layout.addLayout(count_layout)
        self.ai_gen_layout.addWidget(self.ai_generate_btn)
        self.ai_gen_layout.addWidget(self.ai_progress_bar)
        self.ai_gen_group.setLayout(self.ai_gen_layout)
        
        # 将新控件添加到AI选项卡
        ai_layout.addWidget(self.ai_dict_group)
        ai_layout.addWidget(self.ai_gen_group)

    def start_ai_learning(self):
        """开始AI学习并生成密码"""
        # 获取选中的字典文件（只包括被勾选的）
        selected_items = []
        for i in range(self.ai_dict_list.count()):
            item = self.ai_dict_list.item(i)
            if item.checkState() == Qt.Checked:
                selected_items.append(item.data(Qt.UserRole))
                         
        if not selected_items:
            QMessageBox.warning(self, "警告", "请选择至少一个字典文件")
            return
            
        count = self.ai_count_spin.value()
        if count <= 0:
            count = None  # 无限制
            
        # 创建并启动学习线程
        self.ai_learning_thread = AILearningThread(
            selected_items, 
            self.ai_generator,
            count or 1000000  # 设置一个大数作为"无限制"
        )
        
        self.ai_learning_thread.progress_updated.connect(self.update_ai_progress)
        self.ai_learning_thread.learning_finished.connect(self.ai_learning_finished)
        self.ai_learning_thread.passwords_generated.connect(self.save_generated_passwords)
        
        self.ai_progress_bar.setVisible(True)
        self.ai_progress_bar.setValue(0)
        self.ai_generate_btn.setEnabled(False)
        self.ai_learning_thread.start()
        
    def update_ai_progress(self, current, total):
        """更新AI学习进度"""
        self.ai_progress_bar.setMaximum(total)
        self.ai_progress_bar.setValue(current)
        
    def ai_learning_finished(self, success, message):
        """AI学习完成处理"""
        self.ai_progress_bar.setVisible(False)
        self.ai_generate_btn.setEnabled(True)
        
        if success:
            QMessageBox.information(self, "完成", message)
        else:
            QMessageBox.warning(self, "错误", message)
            
    def save_generated_passwords(self, passwords):
        """保存生成的密码到文件"""
        if not passwords:
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_path = f"ai_passwords_{timestamp}.txt"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存生成的密码", default_path,
            "文本文件 (*.txt);;所有文件 (*.*)")
            
        if file_path:
            try:
                # 读取现有文件内容(如果存在)以避免重复
                existing = set()
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        existing.update(line.strip() for line in f if line.strip())
                
                # 添加新密码并去重
                existing.update(passwords)
                
                # 写入文件
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("\n".join(existing))
                    
                self.status_display.append(f"已保存 {len(existing)} 个密码到 {file_path}")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"保存密码文件失败: {str(e)}")

    def add_ai_dict_files(self):
        """添加字典文件到AI学习列表"""
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "选择字典文件", "",
            "文本文件 (*.txt *.dic *.lst);;所有文件 (*.*)")
            
        for file_path in file_paths:
            if not any(self.ai_dict_list.item(i).data(Qt.UserRole) == file_path 
                    for i in range(self.ai_dict_list.count())):
                item = QListWidgetItem(os.path.basename(file_path))
                item.setData(Qt.UserRole, file_path)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked)  # 默认选中
                self.ai_dict_list.addItem(item)


    def format_file_size(self, size):
        """格式化文件大小为易读的字符串"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def get_size_color(self, size):
        """根据文件大小生成更明显的渐变色"""
        if size == 0:  # 目录
            return QColor(180, 180, 180)
        
        # 使用HSL颜色空间，从蓝色(240°)到红色(0°)
        size_mb = size / (1024 * 1024)
        ratio = min(math.log10(size_mb + 1) / 3.0, 1.0)  # 对数比例
        
        hue = 240 * (1 - ratio)  # 蓝(240°) → 红(0°)
        saturation = 0.9
        lightness = 0.6 - (0.3 * ratio)  # 亮度调整
        
        return QColor.fromHslF(hue / 360, saturation, lightness)


    def update_progress_info(self, progress, tried, total):
        """更新详细的进度信息"""
        if not hasattr(self, 'start_time'):
            self.start_time = datetime.now()
        
        elapsed = datetime.now() - self.start_time
        if tried > 0:
            remaining = (elapsed / tried) * (total - tried)
        else:
            remaining = timedelta(0)
        
        info = (f"进度: {progress}% | 已尝试: {tried}/{total} "
            f"| 用时: {str(elapsed).split('.')[0]} "
            f"| 预计剩余: {str(remaining).split('.')[0]}")
        self.progress_info.setText(info)




    def init_ui(self):
        # 主窗口设置
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)  # 主布局间距
        main_layout.setContentsMargins(10, 10, 10, 10)  # 主布局边距

        # 使用垂直分割器组织界面
        splitter = QSplitter(Qt.Vertical)

        # ==================== 上部面板 - 设置区域 ====================
        top_panel = QWidget()
        top_layout = QVBoxLayout()
        top_layout.setSpacing(8)
        top_layout.setContentsMargins(8, 8, 8, 8)

        # 使用选项卡组织设置
        tab_widget = QTabWidget()

        # ------ 基本设置选项卡 ------
        basic_tab = QWidget()
        basic_layout = QVBoxLayout()
        basic_layout.setSpacing(8)
        basic_layout.setContentsMargins(5, 5, 5, 5)

        # 7z路径设置组
        sevenz_group = QGroupBox("7z设置")
        sevenz_layout = QHBoxLayout()
        self.sevenz_path_edit = QLineEdit()
        self.sevenz_path_edit.setPlaceholderText("7z.exe路径 (默认为当前目录下的7z.exe)")
        browse_sevenz_btn = QPushButton("浏览...")
        browse_sevenz_btn.clicked.connect(self.browse_sevenz)
        sevenz_layout.addWidget(self.sevenz_path_edit)
        sevenz_layout.addWidget(browse_sevenz_btn)
        sevenz_group.setLayout(sevenz_layout)
        basic_layout.addWidget(sevenz_group)

        # 性能设置组
        performance_group = QGroupBox("性能设置")
        performance_layout = QHBoxLayout()
        self.thread_label = QLabel("最大线程数:")
        self.thread_spin = QComboBox()
        self.thread_spin.addItems([str(i) for i in range(1, self.max_threads + 1)])
        self.thread_spin.setCurrentIndex(self.max_threads - 1)
        performance_layout.addWidget(self.thread_label)
        performance_layout.addWidget(self.thread_spin)
        performance_layout.addStretch()
        performance_group.setLayout(performance_layout)
        basic_layout.addWidget(performance_group)

        basic_tab.setLayout(basic_layout)
        tab_widget.addTab(basic_tab, "基本设置")

        # ------ AI设置选项卡 ------
        ai_tab = QWidget()
        ai_layout = QVBoxLayout()
        ai_layout.setSpacing(8)
        ai_layout.setContentsMargins(5, 5, 5, 5)
        
        self.ai_enable_check = QCheckBox("启用AI智能破解")
        self.ai_enable_check.setToolTip("启用后，AI会分析字典中的密码模式并生成类似的密码")
        
        ai_info = QLabel("AI破解功能会分析字典中的密码模式，生成更可能正确的密码变体，提高破解效率。")
        ai_info.setWordWrap(True)
        ai_info.setStyleSheet("color: #666;")
        
        ai_layout.addWidget(self.ai_enable_check)
        ai_layout.addWidget(ai_info)
        ai_layout.addStretch()

        ai_tab.setLayout(ai_layout)
        tab_widget.addTab(ai_tab, "AI设置")

        top_layout.addWidget(tab_widget)
        top_panel.setLayout(top_layout)
        splitter.addWidget(top_panel)

        # ==================== 中部面板 - 文件列表区域 ====================
        middle_panel = QWidget()
        middle_layout = QHBoxLayout()
        middle_layout.setSpacing(10)
        middle_layout.setContentsMargins(5, 5, 5, 5)

        # ------ 压缩文件列表 ------
        archive_group = QGroupBox("压缩文件列表 (支持拖放)")
        archive_layout = QVBoxLayout()
        self.archive_list = QListWidget()
        self.archive_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.archive_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.archive_list.customContextMenuRequested.connect(self.show_archive_list_context_menu)
        self.archive_list.setAcceptDrops(True)  # 启用拖放功能
        
        # 压缩文件操作按钮
        archive_button_layout = QHBoxLayout()
        add_archive_btn = QPushButton("添加文件")
        add_archive_btn.clicked.connect(self.add_archive_file)
        add_archive_dir_btn = QPushButton("添加目录")
        add_archive_dir_btn.clicked.connect(self.add_archive_dir)
        remove_archive_btn = QPushButton("移除选中")
        remove_archive_btn.clicked.connect(self.remove_selected_archives)
        clear_archive_btn = QPushButton("清空列表")
        clear_archive_btn.clicked.connect(self.clear_archive_list)
        
        archive_button_layout.addWidget(add_archive_btn)
        archive_button_layout.addWidget(add_archive_dir_btn)
        archive_button_layout.addWidget(remove_archive_btn)
        archive_button_layout.addWidget(clear_archive_btn)
        
        archive_layout.addWidget(self.archive_list)
        archive_layout.addLayout(archive_button_layout)
        archive_group.setLayout(archive_layout)
        middle_layout.addWidget(archive_group, 1)

        # ------ 字典文件列表 ------
        dict_group = QGroupBox("字典管理 (支持拖放)")
        dict_layout = QVBoxLayout()
        self.dict_list = QListWidget()
        self.dict_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.dict_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dict_list.customContextMenuRequested.connect(self.show_dict_list_context_menu)
        self.dict_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dict_list.customContextMenuRequested.connect(self.show_dict_list_context_menu)
        self.dict_list.setAcceptDrops(True)  # 启用拖放功能
        
        # 字典操作按钮
        dict_button_layout = QHBoxLayout()
        add_dict_btn = QPushButton("添加文件")
        add_dict_btn.clicked.connect(self.add_dict_file)
        add_dict_dir_btn = QPushButton("添加目录")
        add_dict_dir_btn.clicked.connect(self.add_dict_dir)
        remove_dict_btn = QPushButton("移除选中")
        remove_dict_btn.clicked.connect(self.remove_selected_dicts)
        clear_dict_btn = QPushButton("清空列表")
        clear_dict_btn.clicked.connect(self.clear_dict_list)
        
        dict_button_layout.addWidget(add_dict_btn)
        dict_button_layout.addWidget(add_dict_dir_btn)
        dict_button_layout.addWidget(remove_dict_btn)
        dict_button_layout.addWidget(clear_dict_btn)
        
        # 大小颜色图例
        legend_layout = QHBoxLayout()
        legend_label = QLabel("大小颜色: ")
        legend_layout.addWidget(legend_label)
        
        for size, text in [(0, "目录"), (1024, "1KB"), 
                        (1024*100, "100KB"), (1024*1024, "1MB"), 
                        (1024*1024*10, "10MB")]:
            color = self.get_size_color(size)
            label = QLabel(text)
            label.setStyleSheet(f"""
                background-color: {color.name()}; 
                padding: 2px 5px;
                border-radius: 3px;
                margin-right: 5px;
                border: 1px solid #ccc;
            """)
            legend_layout.addWidget(label)
        
        dict_layout.addWidget(self.dict_list)
        dict_layout.addLayout(dict_button_layout)
        dict_layout.addLayout(legend_layout)
        dict_layout.addWidget(self.recursive_check)
        dict_group.setLayout(dict_layout)
        middle_layout.addWidget(dict_group, 1)

        middle_panel.setLayout(middle_layout)
        splitter.addWidget(middle_panel)

        # ==================== 下部面板 - 状态区域 ====================
        bottom_panel = QWidget()
        bottom_layout = QVBoxLayout()
        bottom_layout.setSpacing(8)
        bottom_layout.setContentsMargins(5, 5, 5, 5)

        # 当前任务状态标签
        self.active_tasks_label = QLabel("当前任务: 无")
        self.active_tasks_label.setStyleSheet("font-weight: bold;")

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setTextVisible(True)

        # 新增进度信息标签
        self.progress_info = QLabel("准备就绪")
        self.progress_info.setAlignment(Qt.AlignCenter)
        self.progress_info.setStyleSheet("font-weight: bold; color: #333;")

        # 进度详情标签
        self.progress_detail_label = QLabel("进度: 0/0 (0%)")
        self.current_dict_label = QLabel("当前字典: 无")

        # 控制按钮区域
        control_layout = QVBoxLayout()  # 改为垂直布局
        control_layout.setSpacing(5)

        # 第一行：操作按钮
        action_btn_layout = QHBoxLayout()
        self.start_all_btn = QPushButton("开始全部")
        self.start_all_btn.clicked.connect(lambda: self.start_cracking(False))
        self.start_selected_btn = QPushButton("开始选中")
        self.start_selected_btn.clicked.connect(lambda: self.start_cracking(True))
        self.pause_btn = QPushButton("暂停")
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.stop_cracking)
        self.stop_btn.setEnabled(False)
        self.resume_btn = QPushButton("恢复破解")
        self.resume_btn.clicked.connect(self.resume_cracking)
        self.resume_btn.setEnabled(os.path.exists(self.resume_file))
        
        action_btn_layout.addWidget(self.start_all_btn)
        action_btn_layout.addWidget(self.start_selected_btn)
        action_btn_layout.addWidget(self.pause_btn)
        action_btn_layout.addWidget(self.stop_btn)
        action_btn_layout.addWidget(self.resume_btn)
        action_btn_layout.addStretch()

        # 第二行：配置按钮
        config_btn_layout = QHBoxLayout()
        self.save_config_btn = QPushButton("保存配置")
        self.save_config_btn.clicked.connect(self.save_settings)
        self.load_config_btn = QPushButton("加载配置")
        self.load_config_btn.clicked.connect(self.load_settings)
        
        config_btn_layout.addWidget(self.save_config_btn)
        config_btn_layout.addWidget(self.load_config_btn)
        config_btn_layout.addStretch()

        control_layout.addLayout(action_btn_layout)
        control_layout.addLayout(config_btn_layout)

        # 状态信息显示区域
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        self.status_display.setStyleSheet("""
            QTextEdit {
                background-color: #f8f8f8;
                border: 1px solid #ddd;
                border-radius: 3px;
            }
        """)

        # 将控件添加到下部布局
        bottom_layout.addWidget(self.active_tasks_label)
        bottom_layout.addWidget(self.progress_bar)
        bottom_layout.addWidget(self.progress_info)
        bottom_layout.addWidget(self.progress_detail_label)
        bottom_layout.addWidget(self.current_dict_label)
        bottom_layout.addLayout(control_layout)
        bottom_layout.addWidget(self.status_display)

        bottom_panel.setLayout(bottom_layout)
        splitter.addWidget(bottom_panel)

        # 设置分割器初始比例
        splitter.setSizes([150, 400, 250])

        # 完成主界面设置
        main_layout.addWidget(splitter)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # 设置窗口最小大小
        self.setMinimumSize(900, 700)


    def toggle_all_archive_items(self, checked):
        """切换所有压缩文件的选择状态"""
        for i in range(self.archive_list.count()):
            item = self.archive_list.item(i)
            item.setCheckState(Qt.Checked if checked else Qt.Unchecked)

    def toggle_all_dict_items(self, checked):
        """切换所有字典的选择状态"""
        for i in range(self.dict_list.count()):
            item = self.dict_list.item(i)
            item.setCheckState(Qt.Checked if checked else Qt.Unchecked)


    def browse_sevenz(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择7z.exe", "", "可执行文件 (*.exe)")
        if file_path:
            self.sevenz_path_edit.setText(file_path)


    def add_to_dictionary(self, password):
        """将密码添加到用户选择的字典文件"""
        if not password:
            return
        
        # 让用户选择要添加到的字典文件
        dict_files = [self.dict_list.item(i).data(Qt.UserRole) 
                    for i in range(self.dict_list.count())
                    if os.path.isfile(self.dict_list.item(i).data(Qt.UserRole))]
        
        if not dict_files:
            QMessageBox.warning(self, "警告", "没有可用的字典文件")
            return
        
        dict_file, ok = QInputDialog.getItem(
            self, "添加到字典", "选择字典文件:", 
            [os.path.basename(f) for f in dict_files], 0, False)
        
        if ok and dict_file:
            full_path = next(f for f in dict_files if os.path.basename(f) == dict_file)
            try:
                with open(full_path, 'a', encoding='utf-8') as f:
                    f.write(f"{password}\n")
                self.status_display.append(f"密码已添加到字典: {os.path.basename(full_path)}")
            except Exception as e:
                self.status_display.append(f"添加到字典失败: {str(e)}")


    def add_archive_file(self):
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "选择压缩文件", "", 
            "7z支持的所有格式 (*.7z *.zip *.rar *.tar *.gz *.bz2 *.xz *.cab *.arj *.z *.lzh *.iso);;所有文件 (*.*)")
        for file_path in file_paths:
            self.add_archive_item(file_path)

    def add_archive_dir(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "选择压缩文件目录", "",
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
        if dir_path:
            for root, _, files in os.walk(dir_path):
                for file in files:
                    if file.lower().endswith(('.7z', '.zip', '.rar', '.tar', '.gz', '.bz2', '.xz', '.cab', '.arj', '.z', '.lzh', '.iso')):
                        file_path = os.path.join(root, file)
                        self.add_archive_item(file_path)

    def add_archive_item(self, path):
        if not path:
            return
            
        # 检查是否已存在
        for i in range(self.archive_list.count()):
            if self.archive_list.item(i).data(Qt.UserRole) == path:
                return
                
        item = QListWidgetItem(path)
        item.setData(Qt.UserRole, path)  # 存储完整路径
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(Qt.Checked)
        item.setIcon(QIcon.fromTheme("package-x-generic"))
        self.archive_list.addItem(item)

    def remove_selected_archives(self):
        for item in self.archive_list.selectedItems():
            self.archive_list.takeItem(self.archive_list.row(item))

    def clear_archive_list(self):
        self.archive_list.clear()

    def show_archive_list_context_menu(self, pos):
        menu = QMenu()
        
        move_up_action = QAction("上移", self)
        move_up_action.triggered.connect(self.move_archive_item_up)
        menu.addAction(move_up_action)
        
        move_down_action = QAction("下移", self)
        move_down_action.triggered.connect(self.move_archive_item_down)
        menu.addAction(move_down_action)
        
        menu.addSeparator()
        
        toggle_action = QAction("切换选中状态", self)
        toggle_action.triggered.connect(self.toggle_archive_item_selection)
        menu.addAction(toggle_action)
        
        menu.addSeparator()
        
        remove_action = QAction("移除", self)
        remove_action.triggered.connect(self.remove_selected_archives)
        menu.addAction(remove_action)
        
        menu.exec_(self.archive_list.mapToGlobal(pos))

    def move_archive_item_up(self):
        current_row = self.archive_list.currentRow()
        if current_row > 0:
            item = self.archive_list.takeItem(current_row)
            self.archive_list.insertItem(current_row - 1, item)
            self.archive_list.setCurrentRow(current_row - 1)

    def move_archive_item_down(self):
        current_row = self.archive_list.currentRow()
        if current_row < self.archive_list.count() - 1:
            item = self.archive_list.takeItem(current_row)
            self.archive_list.insertItem(current_row + 1, item)
            self.archive_list.setCurrentRow(current_row + 1)

    def toggle_archive_item_selection(self):
        for item in self.archive_list.selectedItems():
            if item.checkState() == Qt.Checked:
                item.setCheckState(Qt.Unchecked)
            else:
                item.setCheckState(Qt.Checked)

    def add_dict_file(self):
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "选择字典文件", "",
            "文本文件 (*.txt *.dic *.lst);;所有文件 (*.*)")
        for file_path in file_paths:
            self.add_dict_item(file_path)

    def add_dict_dir(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "选择字典目录", "",
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks)
        if dir_path:
            self.add_dict_item(dir_path)

    def add_dict_item(self, path):
        if not path:
            return
            
        # 检查是否已存在
        for i in range(self.dict_list.count()):
            if self.dict_list.item(i).data(Qt.UserRole) == path:
                return
                
        item = QListWidgetItem()
        item.setData(Qt.UserRole, path)
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(Qt.Checked)  # 默认选中
        
        # 设置显示文本、图标和颜色
        size = 0
        if os.path.isfile(path):
            try:
                size = os.path.getsize(path)
                size_str = self.format_file_size(size)
                item.setText(f"{os.path.basename(path)} ({size_str})")
                item.setIcon(QIcon.fromTheme("text-x-generic"))
            except:
                item.setText(f"{os.path.basename(path)} (大小未知)")
        elif os.path.isdir(path):
            item.setText(f"{os.path.basename(path)} [目录]")
            item.setIcon(QIcon.fromTheme("folder"))
        
        # 设置颜色
        color = self.get_size_color(size)
        item.setForeground(color)
            
        self.dict_list.addItem(item)


    def remove_selected_dicts(self):
        for item in self.dict_list.selectedItems():
            self.dict_list.takeItem(self.dict_list.row(item))

    def clear_dict_list(self):
        self.dict_list.clear()

    def show_dict_list_context_menu(self, pos):
        menu = QMenu()
        
        # 排序菜单
        sort_menu = QMenu("排序方式", self)
        
        # 按文件名排序
        sort_by_name_action = QAction("按文件名(A-Z)", self)
        sort_by_name_action.triggered.connect(lambda: self.sort_dict_items(by='name_asc'))
        
        sort_by_name_desc_action = QAction("按文件名(Z-A)", self)
        sort_by_name_desc_action.triggered.connect(lambda: self.sort_dict_items(by='name_desc'))
        
        # 按文件大小排序
        sort_by_size_action = QAction("按文件大小(小→大)", self)
        sort_by_size_action.triggered.connect(lambda: self.sort_dict_items(by='size_asc'))
        
        sort_by_size_desc_action = QAction("按文件大小(大→小)", self)
        sort_by_size_desc_action.triggered.connect(lambda: self.sort_dict_items(by='size_desc'))
        
        # 按修改时间排序
        sort_by_mtime_action = QAction("按修改时间(旧→新)", self)
        sort_by_mtime_action.triggered.connect(lambda: self.sort_dict_items(by='mtime_asc'))
        
        sort_by_mtime_desc_action = QAction("按修改时间(新→旧)", self)
        sort_by_mtime_desc_action.triggered.connect(lambda: self.sort_dict_items(by='mtime_desc'))
        
        # 按文件类型排序
        sort_by_type_action = QAction("按文件类型", self)
        sort_by_type_action.triggered.connect(lambda: self.sort_dict_items(by='type'))
        
        # 添加到排序菜单
        sort_menu.addAction(sort_by_name_action)
        sort_menu.addAction(sort_by_name_desc_action)
        sort_menu.addSeparator()
        sort_menu.addAction(sort_by_size_action)
        sort_menu.addAction(sort_by_size_desc_action)
        sort_menu.addSeparator()
        sort_menu.addAction(sort_by_mtime_action)
        sort_menu.addAction(sort_by_mtime_desc_action)
        sort_menu.addSeparator()
        sort_menu.addAction(sort_by_type_action)
        
        menu.addMenu(sort_menu)
        menu.addSeparator()
        
        # 原有其他菜单项...
        move_up_action = QAction("上移", self)
        move_up_action.triggered.connect(self.move_dict_item_up)
        menu.addAction(move_up_action)
        
        move_down_action = QAction("下移", self)
        move_down_action.triggered.connect(self.move_dict_item_down)
        menu.addAction(move_down_action)
        
        menu.addSeparator()
        
        toggle_action = QAction("切换选中状态", self)
        toggle_action.triggered.connect(self.toggle_dict_item_selection)
        menu.addAction(toggle_action)
        
        menu.addSeparator()
        
        remove_action = QAction("移除", self)
        remove_action.triggered.connect(self.remove_selected_dicts)
        menu.addAction(remove_action)
        
        menu.exec_(self.dict_list.mapToGlobal(pos))


    def sort_dict_items(self, by='name_asc'):
        """按指定方式排序字典列表"""
        items = []
        for i in range(self.dict_list.count()):
            item = self.dict_list.item(i)
            path = item.data(Qt.UserRole)
            checked = item.checkState() == Qt.Checked
            
            # 获取文件信息
            file_info = {
                'item': item,
                'path': path,
                'name': os.path.basename(path),
                'checked': checked,
                'size': 0,
                'mtime': 0,
                'type': 'dir'  # 默认为目录
            }
            
            if os.path.isfile(path):
                try:
                    stat = os.stat(path)
                    file_info['size'] = stat.st_size
                    file_info['mtime'] = stat.st_mtime
                    file_info['type'] = os.path.splitext(path)[1].lower()  # 文件扩展名
                except:
                    pass
            elif os.path.isdir(path):
                file_info['type'] = 'dir'
            
            items.append(file_info)
        
        # 根据排序方式排序
        if by == 'name_asc':
            items.sort(key=lambda x: x['name'].lower())
        elif by == 'name_desc':
            items.sort(key=lambda x: x['name'].lower(), reverse=True)
        elif by == 'size_asc':
            items.sort(key=lambda x: (x['size'], x['name'].lower()))
        elif by == 'size_desc':
            items.sort(key=lambda x: (-x['size'], x['name'].lower()))
        elif by == 'mtime_asc':
            items.sort(key=lambda x: (x['mtime'], x['name'].lower()))
        elif by == 'mtime_desc':
            items.sort(key=lambda x: (-x['mtime'], x['name'].lower()))
        elif by == 'type':
            items.sort(key=lambda x: (x['type'], x['name'].lower()))
        
        # 重新添加项目（带颜色）
        self.dict_list.clear()
        for item_data in items:
            item = item_data['item']
            path = item_data['path']
            
            # 创建新项目（保持原有显示格式）
            new_item = QListWidgetItem()
            new_item.setData(Qt.UserRole, path)
            new_item.setFlags(new_item.flags() | Qt.ItemIsUserCheckable)
            new_item.setCheckState(Qt.Checked if item_data['checked'] else Qt.Unchecked)
            
            # 设置颜色 
            color = self.get_size_color(item_data['size'])
            new_item.setForeground(color)
            
            if os.path.isfile(path):
                size_str = self.format_file_size(item_data['size'])
                mtime_str = datetime.fromtimestamp(item_data['mtime']).strftime('%Y-%m-%d %H:%M')
                new_item.setText(f"{os.path.basename(path)} ({size_str}, {mtime_str})")
                new_item.setIcon(QIcon.fromTheme("text-x-generic"))
            elif os.path.isdir(path):
                new_item.setText(f"{os.path.basename(path)} [目录]")
                new_item.setIcon(QIcon.fromTheme("folder"))
                
            self.dict_list.addItem(new_item)






    def move_dict_item_up(self):
        current_row = self.dict_list.currentRow()
        if current_row > 0:
            item = self.dict_list.takeItem(current_row)
            self.dict_list.insertItem(current_row - 1, item)
            self.dict_list.setCurrentRow(current_row - 1)

    def move_dict_item_down(self):
        current_row = self.dict_list.currentRow()
        if current_row < self.dict_list.count() - 1:
            item = self.dict_list.takeItem(current_row)
            self.dict_list.insertItem(current_row + 1, item)
            self.dict_list.setCurrentRow(current_row + 1)

    def toggle_dict_item_selection(self):
        for item in self.dict_list.selectedItems():
            if item.checkState() == Qt.Checked:
                item.setCheckState(Qt.Unchecked)
            else:
                item.setCheckState(Qt.Checked)

    def save_settings(self):
        # 保存到QSettings
        self.settings.setValue("sevenz_path", self.sevenz_path_edit.text())
        self.settings.setValue("thread_count", self.thread_spin.currentText())
        self.settings.setValue("recursive", self.recursive_check.isChecked())
        self.settings.setValue("ai_enabled", self.ai_enable_check.isChecked())
        
        # 保存压缩文件列表
        archive_items = []
        for i in range(self.archive_list.count()):
            item = self.archive_list.item(i)
            archive_items.append({
                "path": item.data(Qt.UserRole),
                "checked": item.checkState() == Qt.Checked
            })
        self.settings.setValue("archive_items", json.dumps(archive_items))
        
        # 保存字典列表
        dict_items = []
        for i in range(self.dict_list.count()):
            item = self.dict_list.item(i)
            dict_items.append({
                "path": item.data(Qt.UserRole),
                "checked": item.checkState() == Qt.Checked
            })
        self.settings.setValue("dict_items", json.dumps(dict_items))

        # 保存AI字典列表（包括选中状态）
        ai_dict_items = []
        for i in range(self.ai_dict_list.count()):
            item = self.ai_dict_list.item(i)
            ai_dict_items.append({
                "path": item.data(Qt.UserRole),
                "checked": item.checkState() == Qt.Checked
            })
        self.settings.setValue("ai_dict_items", json.dumps(ai_dict_items))

        # 保存到配置文件
        config = {
            "sevenz_path": self.sevenz_path_edit.text(),
            "thread_count": self.thread_spin.currentText(),
            "recursive": self.recursive_check.isChecked(),
            "ai_enabled": self.ai_enable_check.isChecked(),
            "archive_items": archive_items,
            "dict_items": dict_items,
            "ai_dict_items": ai_dict_items,
            "ai_count": self.ai_count_spin.value()
        }
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            self.status_display.append("配置已保存到文件")
        except Exception as e:
            self.status_display.append(f"保存配置失败: {str(e)}")

    def load_settings(self):
        # 尝试从配置文件加载
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                self.sevenz_path_edit.setText(config.get("sevenz_path", "7z.exe"))
                thread_index = self.thread_spin.findText(str(config.get("thread_count", self.max_threads)))
                if thread_index >= 0:
                    self.thread_spin.setCurrentIndex(thread_index)
                self.recursive_check.setChecked(config.get("recursive", False))
                self.ai_enable_check.setChecked(config.get("ai_enabled", False))
                self.ai_count_spin.setValue(config.get("ai_count", 20000))
                
                # 加载压缩文件列表
                self.archive_list.clear()
                for item_data in config.get("archive_items", []):
                    item = QListWidgetItem(item_data["path"])
                    item.setData(Qt.UserRole, item_data["path"])
                    item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                    item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
                    item.setIcon(QIcon.fromTheme("package-x-generic"))
                    self.archive_list.addItem(item)
                
                # 加载字典列表
                self.dict_list.clear()
                for item_data in config.get("dict_items", []):
                    path = item_data["path"]
                    item = QListWidgetItem()
                    item.setData(Qt.UserRole, path)
                    item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                    item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
                    
                    size = 0
                    if os.path.isfile(path):
                        try:
                            size = os.path.getsize(path)
                            size_str = self.format_file_size(size)
                            item.setText(f"{os.path.basename(path)} ({size_str})")
                        except:
                            item.setText(f"{os.path.basename(path)} (大小未知)")
                        item.setIcon(QIcon.fromTheme("text-x-generic"))
                    elif os.path.isdir(path):
                        item.setText(f"{os.path.basename(path)} [目录]")
                        item.setIcon(QIcon.fromTheme("folder"))
                        
                    # 设置颜色
                    color = self.get_size_color(size)
                    item.setForeground(color)
                    
                    self.dict_list.addItem(item)
                
                # 加载AI字典列表
                self.ai_dict_list.clear()
                for path in config.get("ai_dict_items", []):
                    if os.path.exists(path):
                        item = QListWidgetItem(os.path.basename(path))
                        item.setData(Qt.UserRole, path)
                        self.ai_dict_list.addItem(item)
                
                self.status_display.append("配置已从文件加载")
                return
        except Exception as e:
            self.status_display.append(f"从文件加载配置失败: {str(e)}")
        
        # 如果文件加载失败，从QSettings加载
        sevenz_path = self.settings.value("sevenz_path", "7z.exe")
        self.sevenz_path_edit.setText(sevenz_path)
        
        thread_index = self.thread_spin.findText(self.settings.value("thread_count", str(self.max_threads)))
        if thread_index >= 0:
            self.thread_spin.setCurrentIndex(thread_index)
        
        recursive = self.settings.value("recursive", False, type=bool)
        self.recursive_check.setChecked(recursive)
        
        ai_enabled = self.settings.value("ai_enabled", False, type=bool)
        self.ai_enable_check.setChecked(ai_enabled)
        
        # 加载压缩文件列表
        self.archive_list.clear()
        archive_items = json.loads(self.settings.value("archive_items", "[]"))
        for item_data in archive_items:
            item = QListWidgetItem(item_data["path"])
            item.setData(Qt.UserRole, item_data["path"])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
            item.setIcon(QIcon.fromTheme("package-x-generic"))
            self.archive_list.addItem(item)
        
        # 加载字典列表
        self.dict_list.clear()
        dict_items = json.loads(self.settings.value("dict_items", "[]"))
        for item_data in dict_items:
            item = QListWidgetItem(item_data["path"])
            item.setData(Qt.UserRole, item_data["path"])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
            
            if os.path.isfile(item_data["path"]):
                item.setIcon(QIcon.fromTheme("text-x-generic"))
            elif os.path.isdir(item_data["path"]):
                item.setIcon(QIcon.fromTheme("folder"))
                
            self.dict_list.addItem(item)
        
        # 加载AI字典列表（包括选中状态）
        self.ai_dict_list.clear()
        ai_dict_items = json.loads(self.settings.value("ai_dict_items", "[]"))
        for item_data in ai_dict_items:
            if os.path.exists(item_data["path"]):
                item = QListWidgetItem(os.path.basename(item_data["path"]))
                item.setData(Qt.UserRole, item_data["path"])
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
                self.ai_dict_list.addItem(item)


    def save_resume_info(self):
        resume_data = {
            "archive_items": [],
            "dict_items": [],
            "resume_info": {},
            "thread_count": self.thread_spin.currentText(),
            "recursive": self.recursive_check.isChecked(),
            "ai_enabled": self.ai_enable_check.isChecked(),
            "sevenz_path": self.sevenz_path_edit.text()
        }
        
        # 保存压缩文件列表
        for i in range(self.archive_list.count()):
            item = self.archive_list.item(i)
            resume_data["archive_items"].append({
                "path": item.data(Qt.UserRole),
                "checked": item.checkState() == Qt.Checked
            })
        
        # 保存字典列表
        for i in range(self.dict_list.count()):
            item = self.dict_list.item(i)
            resume_data["dict_items"].append({
                "path": item.data(Qt.UserRole),
                "checked": item.checkState() == Qt.Checked
            })
        
        # 保存每个任务的恢复信息
        for archive_path, cracker in self.cracker_threads.items():
            if hasattr(cracker, 'resume_info'):
                resume_data["resume_info"][archive_path] = cracker.resume_info
        
        try:
            with open(self.resume_file, 'w', encoding='utf-8') as f:
                json.dump(resume_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.status_display.append(f"保存恢复信息失败: {str(e)}")

    def load_resume_info(self):
        try:
            if os.path.exists(self.resume_file):
                with open(self.resume_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            self.status_display.append(f"加载恢复信息失败: {str(e)}")
        return None

    def closeEvent(self, event):
        self.save_settings()
        if self.cracker_threads:
            self.save_resume_info()
            for cracker in self.cracker_threads.values():
                if cracker.isRunning():
                    cracker.stop()
                    cracker.wait(2000)

        if hasattr(self, 'ai_learning_thread') and self.ai_learning_thread.isRunning():
            self.ai_learning_thread.stop()
            self.ai_learning_thread.wait(2000)

        event.accept()

    def log_password(self, archive_path, password):
        try:
            with open(self.password_log_file, 'a', encoding='utf-8') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{timestamp} | {archive_path} | 密码: {password}\n")
        except Exception as e:
            self.status_display.append(f"记录密码失败: {str(e)}")

    def start_cracking(self, selected_only=False):
        sevenz_path = self.sevenz_path_edit.text() or "7z.exe"
        max_threads = int(self.thread_spin.currentText())
        ai_enabled = self.ai_enable_check.isChecked()

        if not os.path.exists(sevenz_path):
            QMessageBox.warning(self, "警告", "7z.exe不存在")
            return

        # 收集选中的压缩文件
        archive_paths = []
        for i in range(self.archive_list.count()):
            item = self.archive_list.item(i)
            if not selected_only or item.checkState() == Qt.Checked:
                archive_path = item.data(Qt.UserRole)
                if not os.path.exists(archive_path):
                    self.status_display.append(f"警告: 压缩文件不存在 {archive_path}")
                    continue
                archive_paths.append(archive_path)

        if not archive_paths:
            QMessageBox.warning(self, "警告", "请选择至少一个压缩文件")
            return

        # 收集选中的字典路径
        dict_paths = []
        for i in range(self.dict_list.count()):
            item = self.dict_list.item(i)
            if item.checkState() == Qt.Checked:
                dict_paths.append(item.data(Qt.UserRole))

        if not dict_paths:
            QMessageBox.warning(self, "警告", "请选择至少一个字典文件或目录")
            return

        self.status_display.clear()
        self.status_display.append(f"开始破解 {len(archive_paths)} 个压缩文件")
        self.status_display.append(f"使用7z路径: {sevenz_path}")
        self.status_display.append(f"使用字典: {', '.join(dict_paths)}")
        self.status_display.append(f"使用线程数: {max_threads}")
        if ai_enabled:
            self.status_display.append("AI智能破解已启用")

        # 停止任何正在运行的任务
        for cracker in self.cracker_threads.values():
            if cracker.isRunning():
                cracker.stop()

        self.cracker_threads = {}
        
        # 启动每个压缩文件的破解任务
        for archive_path in archive_paths:
            cracker = ArchiveCracker(
                archive_path, 
                dict_paths, 
                self.recursive_check.isChecked(), 
                sevenz_path,
                max_workers=max_threads,
                ai_enabled=ai_enabled,
                ai_generator=self.ai_generator
            )
            
            cracker.password_found.connect(self.password_found)
            cracker.status_message.connect(self.update_status)
            cracker.finished.connect(self.cracking_finished)
            
            self.cracker_threads[archive_path] = cracker
            cracker.start()

        self.update_control_buttons()

    def resume_cracking(self):
        resume_data = self.load_resume_info()
        if not resume_data:
            QMessageBox.warning(self, "警告", "无法加载恢复信息")
            return

        # 设置基本参数
        self.sevenz_path_edit.setText(resume_data.get("sevenz_path", "7z.exe"))
        thread_index = self.thread_spin.findText(str(resume_data.get("thread_count", self.max_threads)))
        if thread_index >= 0:
            self.thread_spin.setCurrentIndex(thread_index)
        self.recursive_check.setChecked(resume_data.get("recursive", False))
        self.ai_enable_check.setChecked(resume_data.get("ai_enabled", False))

        # 检查7z.exe是否存在
        sevenz_path = resume_data.get("sevenz_path", "7z.exe")
        if not os.path.exists(sevenz_path):
            QMessageBox.warning(self, "警告", "7z.exe不存在，无法恢复")
            return

        # 恢复压缩文件列表
        self.archive_list.clear()
        for item_data in resume_data.get("archive_items", []):
            item = QListWidgetItem(item_data["path"])
            item.setData(Qt.UserRole, item_data["path"])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
            item.setIcon(QIcon.fromTheme("package-x-generic"))
            self.archive_list.addItem(item)

        # 恢复字典列表
        self.dict_list.clear()
        for item_data in resume_data.get("dict_items", []):
            path = item_data["path"]
            item = QListWidgetItem()
            item.setData(Qt.UserRole, path)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
            
            if os.path.isfile(path):
                try:
                    size = os.path.getsize(path)
                    size_str = self.format_file_size(size)
                    item.setText(f"{os.path.basename(path)} ({size_str})")
                except:
                    item.setText(f"{os.path.basename(path)} (大小未知)")
                item.setIcon(QIcon.fromTheme("text-x-generic"))
            elif os.path.isdir(path):
                item.setText(f"{os.path.basename(path)} [目录]")
                item.setIcon(QIcon.fromTheme("folder"))
                
            self.dict_list.addItem(item)

        self.status_display.clear()
        self.status_display.append("恢复上次破解任务...")

        # 停止任何正在运行的任务
        for cracker in self.cracker_threads.values():
            if cracker.isRunning():
                cracker.stop()

        self.cracker_threads = {}
        
        # 恢复每个压缩文件的破解任务
        resume_info = resume_data.get("resume_info", {})
        dict_paths = [item.data(Qt.UserRole) for i in range(self.dict_list.count()) 
                     if self.dict_list.item(i).checkState() == Qt.Checked]
        ai_enabled = resume_data.get("ai_enabled", False)
        
        for archive_path in resume_info.keys():
            if not os.path.exists(archive_path):
                self.status_display.append(f"警告: 压缩文件不存在 {archive_path}")
                continue

            cracker = ArchiveCracker(
                archive_path, 
                dict_paths, 
                self.recursive_check.isChecked(), 
                sevenz_path,
                resume_info[archive_path],
                max_workers=int(self.thread_spin.currentText()),
                ai_enabled=ai_enabled,
                ai_generator=self.ai_generator
            )
            
            cracker.password_found.connect(self.password_found)
            cracker.status_message.connect(self.update_status)
            cracker.finished.connect(self.cracking_finished)
            cracker.progress_updated.connect(self.update_progress_info)
            
            self.cracker_threads[archive_path] = cracker
            cracker.start()

        self.update_control_buttons()

    def toggle_pause(self):
        if not self.cracker_threads:
            return

        # 检查是否所有任务都已暂停
        all_paused = all(cracker.is_paused() for cracker in self.cracker_threads.values() 
                        if cracker.isRunning())

        for cracker in self.cracker_threads.values():
            if cracker.isRunning():
                if all_paused:
                    cracker.resume()
                else:
                    cracker.pause()

        if all_paused:
            self.pause_btn.setText("暂停")
            self.status_display.append("继续所有任务...")
        else:
            self.pause_btn.setText("继续")
            self.status_display.append("暂停所有任务...")

    def stop_cracking(self):
        if not self.cracker_threads:
            return

        self.save_resume_info()
        for cracker in self.cracker_threads.values():
            if cracker.isRunning():
                cracker.stop()
        
        self.status_display.append("正在停止所有任务...")
        self.resume_btn.setEnabled(os.path.exists(self.resume_file))
        self.update_control_buttons()

    def password_found(self, archive_path, password):
        self.status_display.append(f"{archive_path}: 密码找到: {password}")
        self.log_password(archive_path, password)
        
        # 显示密码找到的对话框
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("密码找到")
        msg.setText(f"文件: {archive_path}")
        msg.setInformativeText(f"密码: {password}\n\n已记录到日志文件")
        
        # 添加复制密码按钮
        copy_btn = msg.addButton("复制密码", QMessageBox.ActionRole)
        save_btn = msg.addButton("保存到字典", QMessageBox.ActionRole)
        msg.addButton(QMessageBox.Ok)
        
        msg.exec_()
        
        if msg.clickedButton() == copy_btn:
            clipboard = QApplication.clipboard()
            clipboard.setText(password)
            self.status_display.append("密码已复制到剪贴板")
        elif msg.clickedButton() == save_btn:
            self.add_to_dictionary(password)
        
        # 停止该文件的破解任务
        if archive_path in self.cracker_threads:
            self.cracker_threads[archive_path].stop()

    def update_status(self, message):
        """改进状态显示，带时间戳和颜色"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # 根据消息类型设置颜色
        if "失败" in message or "错误" in message:
            color = "#FF0000"  # 红色
        elif "成功" in message or "找到" in message:
            color = "#00AA00"  # 绿色
        else:
            color = "#000000"  # 黑色
            
        self.status_display.append(f'<font color="{color}">[{timestamp}] {message}</font>')
        self.status_display.ensureCursorVisible()  # 自动滚动到底部


    def cracking_finished(self, archive_path, success):
        if not success:
            self.status_display.append(f"{archive_path}: 破解完成，未找到密码")

        self.update_control_buttons()

    def update_active_tasks(self):
        active_count = sum(1 for cracker in self.cracker_threads.values() if cracker.isRunning())
        if active_count > 0:
            active_files = [path for path, cracker in self.cracker_threads.items() 
                          if cracker.isRunning()]
            self.active_tasks_label.setText(f"当前任务: {active_count} 个进行中 ({', '.join(os.path.basename(f) for f in active_files[:3])}{'...' if len(active_files) > 3 else ''})")
        else:
            self.active_tasks_label.setText("当前任务: 无")
            
        # 更新恢复按钮状态
        self.resume_btn.setEnabled(os.path.exists(self.resume_file))

    def update_control_buttons(self):
        active_count = sum(1 for cracker in self.cracker_threads.values() if cracker.isRunning())
        
        self.start_all_btn.setEnabled(True)
        self.start_selected_btn.setEnabled(True)
        self.pause_btn.setEnabled(active_count > 0)
        self.stop_btn.setEnabled(active_count > 0)
        
        if active_count > 0:
            # 检查是否所有任务都已暂停
            all_paused = all(cracker.is_paused() for cracker in self.cracker_threads.values() 
                           if cracker.isRunning())
            self.pause_btn.setText("继续" if all_paused else "暂停")
        else:
            self.pause_btn.setText("暂停")


class AILearningThread(QThread):
    progress_updated = pyqtSignal(int, int)  # current, total
    learning_finished = pyqtSignal(bool, str)  # success, message
    passwords_generated = pyqtSignal(list)  # list of generated passwords
    
    def __init__(self, dict_paths, generator, count=20000):
        super().__init__()
        self.dict_paths = dict_paths
        self.generator = generator
        self.count = count
        self._stop_flag = False
        
    def stop(self):
        self._stop_flag = True
        
    def run(self):
        try:
            # 学习阶段
            success = self.generator.learn_from_multiple_dictionaries(
                self.dict_paths,
                lambda current, total: self.progress_updated.emit(current, total)
            )
            
            if self._stop_flag:
                self.learning_finished.emit(False, "学习已中止")
                return
                
            if not success:
                self.learning_finished.emit(False, "学习失败: 样本不足或模式识别失败")
                return
                
            # 生成阶段
            passwords = []
            batch_size = min(1000, max(100, self.count // 100))
            
            for i in range(0, self.count, batch_size):
                if self._stop_flag:
                    break
                    
                current_count = min(batch_size, self.count - i)
                passwords.extend(self.generator.generate_passwords(current_count))
                self.progress_updated.emit(i + current_count, self.count)
                
            # 去重
            unique_passwords = list(set(passwords))
            self.passwords_generated.emit(unique_passwords)
            self.learning_finished.emit(True, f"成功生成 {len(unique_passwords)} 个唯一密码")
            
        except Exception as e:
            print(f"[DEBUG] AI学习发生错误: {str(e)}")
            self.learning_finished.emit(False, f"发生错误: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # 检查7z.exe是否在当前目录
    if not os.path.exists("7z.exe"):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setText("7z.exe未找到")
        msg.setInformativeText("请确保7z.exe和7z.dll位于程序目录下")
        msg.setWindowTitle("警告")
        msg.exec_()
    
    # 检查scikit-learn是否安装
    try:
        import sklearn
    except ImportError:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("缺少必要依赖")
        msg.setInformativeText("请安装scikit-learn库以使用AI功能:\npip install scikit-learn")
        msg.setWindowTitle("错误")
        msg.exec_()
        sys.exit(1)
    
    window = PasswordCrackerGUI()
    window.show()
    sys.exit(app.exec_())