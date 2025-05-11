import os
import sys
import json
import subprocess
import codecs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit,
                             QProgressBar, QMessageBox, QCheckBox, QGroupBox, QComboBox,
                             QListWidget, QListWidgetItem, QAbstractItemView, QMenu, QAction,
                             QSplitter, QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QDir, QTimer
from PyQt5.QtGui import QIcon
from threading import Lock


class ArchiveCracker(QThread):
    progress_updated = pyqtSignal(int, int, int)  # current, total, file_index
    status_message = pyqtSignal(str)
    password_found = pyqtSignal(str, str)  # archive_path, password
    finished = pyqtSignal(str, bool)  # archive_path, success
    current_file_changed = pyqtSignal(str)

    def __init__(self, archive_path, dictionary_paths, recursive=False, seven_zip_path="7z.exe", 
                 resume_info=None, max_workers=1):
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
        self.init_ui()
        self.load_settings()
        
        # 定时器用于更新界面
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_active_tasks)
        self.update_timer.start(1000)

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # 使用分割器使界面可调整
        splitter = QSplitter(Qt.Vertical)
        
        # 上部面板 - 设置
        top_panel = QWidget()
        top_layout = QVBoxLayout()
        
        # 7z路径设置
        sevenz_group = QGroupBox("7z设置")
        sevenz_layout = QHBoxLayout()
        self.sevenz_path_edit = QLineEdit()
        self.sevenz_path_edit.setPlaceholderText("7z.exe路径 (默认为当前目录下的7z.exe)")
        browse_sevenz_btn = QPushButton("浏览...")
        browse_sevenz_btn.clicked.connect(self.browse_sevenz)
        sevenz_layout.addWidget(self.sevenz_path_edit)
        sevenz_layout.addWidget(browse_sevenz_btn)
        sevenz_group.setLayout(sevenz_layout)
        top_layout.addWidget(sevenz_group)
        
        # 线程设置
        thread_group = QGroupBox("性能设置")
        thread_layout = QHBoxLayout()
        self.thread_label = QLabel("最大线程数:")
        self.thread_spin = QComboBox()
        self.thread_spin.addItems([str(i) for i in range(1, self.max_threads + 1)])
        self.thread_spin.setCurrentIndex(self.max_threads - 1)
        thread_layout.addWidget(self.thread_label)
        thread_layout.addWidget(self.thread_spin)
        thread_layout.addStretch()
        thread_group.setLayout(thread_layout)
        top_layout.addWidget(thread_group)
        
        top_panel.setLayout(top_layout)
        splitter.addWidget(top_panel)
        
        # 中部面板 - 文件列表
        middle_panel = QWidget()
        middle_layout = QHBoxLayout()
        
        # 压缩文件列表
        archive_group = QGroupBox("压缩文件列表")
        archive_layout = QVBoxLayout()
        self.archive_list = QListWidget()
        self.archive_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.archive_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.archive_list.customContextMenuRequested.connect(self.show_archive_list_context_menu)
        
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
        
        # 字典文件列表
        dict_group = QGroupBox("字典管理")
        dict_layout = QVBoxLayout()
        self.dict_list = QListWidget()
        self.dict_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.dict_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dict_list.customContextMenuRequested.connect(self.show_dict_list_context_menu)
        
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
        
        self.recursive_check = QCheckBox("递归搜索目录中的字典文件")
        
        dict_layout.addWidget(self.dict_list)
        dict_layout.addLayout(dict_button_layout)
        dict_layout.addWidget(self.recursive_check)
        dict_group.setLayout(dict_layout)
        middle_layout.addWidget(dict_group, 1)
        
        middle_panel.setLayout(middle_layout)
        splitter.addWidget(middle_panel)
        
        # 下部面板 - 进度和状态
        bottom_panel = QWidget()
        bottom_layout = QVBoxLayout()
        
        # 当前任务状态
        self.active_tasks_label = QLabel("当前任务: 无")
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        
        # 进度详情
        self.progress_detail_label = QLabel("进度: 0/0 (0%)")
        self.current_dict_label = QLabel("当前字典: 无")
        
        # 控制按钮
        control_layout = QHBoxLayout()
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
        
        self.save_config_btn = QPushButton("保存配置")
        self.save_config_btn.clicked.connect(self.save_settings)
        self.load_config_btn = QPushButton("加载配置")
        self.load_config_btn.clicked.connect(self.load_settings)
        self.resume_btn = QPushButton("恢复破解")
        self.resume_btn.clicked.connect(self.resume_cracking)
        self.resume_btn.setEnabled(os.path.exists(self.resume_file))
        
        control_layout.addWidget(self.start_all_btn)
        control_layout.addWidget(self.start_selected_btn)
        control_layout.addWidget(self.pause_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.resume_btn)
        control_layout.addStretch()
        control_layout.addWidget(self.save_config_btn)
        control_layout.addWidget(self.load_config_btn)
        
        # 状态信息
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        
        bottom_layout.addWidget(self.active_tasks_label)
        bottom_layout.addWidget(self.progress_bar)
        bottom_layout.addWidget(self.progress_detail_label)
        bottom_layout.addWidget(self.current_dict_label)
        bottom_layout.addLayout(control_layout)
        bottom_layout.addWidget(self.status_display)
        
        bottom_panel.setLayout(bottom_layout)
        splitter.addWidget(bottom_panel)
        
        # 设置分割器比例
        splitter.setSizes([100, 300, 200])
        
        main_layout.addWidget(splitter)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # 设置窗口最小大小
        self.setMinimumSize(800, 600)

    def browse_sevenz(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择7z.exe", "", "可执行文件 (*.exe)")
        if file_path:
            self.sevenz_path_edit.setText(file_path)

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
                
        item = QListWidgetItem(path)
        item.setData(Qt.UserRole, path)  # 存储完整路径
        item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
        item.setCheckState(Qt.Checked)
        
        # 设置图标
        if os.path.isfile(path):
            item.setIcon(QIcon.fromTheme("text-x-generic"))
        elif os.path.isdir(path):
            item.setIcon(QIcon.fromTheme("folder"))
            
        self.dict_list.addItem(item)

    def remove_selected_dicts(self):
        for item in self.dict_list.selectedItems():
            self.dict_list.takeItem(self.dict_list.row(item))

    def clear_dict_list(self):
        self.dict_list.clear()

    def show_dict_list_context_menu(self, pos):
        menu = QMenu()
        
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
        
        # 保存到配置文件
        config = {
            "sevenz_path": self.sevenz_path_edit.text(),
            "thread_count": self.thread_spin.currentText(),
            "recursive": self.recursive_check.isChecked(),
            "archive_items": archive_items,
            "dict_items": dict_items
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
                    item = QListWidgetItem(item_data["path"])
                    item.setData(Qt.UserRole, item_data["path"])
                    item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                    item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
                    
                    if os.path.isfile(item_data["path"]):
                        item.setIcon(QIcon.fromTheme("text-x-generic"))
                    elif os.path.isdir(item_data["path"]):
                        item.setIcon(QIcon.fromTheme("folder"))
                        
                    self.dict_list.addItem(item)
                
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

    def save_resume_info(self):
        resume_data = {
            "archive_items": [],
            "dict_items": [],
            "resume_info": {},
            "thread_count": self.thread_spin.currentText(),
            "recursive": self.recursive_check.isChecked(),
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
                max_workers=max_threads
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
            item = QListWidgetItem(item_data["path"])
            item.setData(Qt.UserRole, item_data["path"])
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if item_data.get("checked", True) else Qt.Unchecked)
            
            if os.path.isfile(item_data["path"]):
                item.setIcon(QIcon.fromTheme("text-x-generic"))
            elif os.path.isdir(item_data["path"]):
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
                max_workers=int(self.thread_spin.currentText())
            )
            
            cracker.password_found.connect(self.password_found)
            cracker.status_message.connect(self.update_status)
            cracker.finished.connect(self.cracking_finished)
            
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
        QMessageBox.information(self, "成功", f"{archive_path}\n\n密码找到: {password}\n\n已记录到日志文件")
        
        # 停止该文件的破解任务
        if archive_path in self.cracker_threads:
            self.cracker_threads[archive_path].stop()

    def update_status(self, message):
        self.status_display.append(message)

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
    
    window = PasswordCrackerGUI()
    window.show()
    sys.exit(app.exec_())