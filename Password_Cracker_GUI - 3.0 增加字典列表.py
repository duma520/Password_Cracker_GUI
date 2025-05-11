import os
import sys
import json
import subprocess
import codecs
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit,
                             QProgressBar, QMessageBox, QCheckBox, QGroupBox, QComboBox,
                             QListWidget, QListWidgetItem, QAbstractItemView, QMenu, QAction)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QDir
from PyQt5.QtGui import QIcon
from threading import Lock


class ArchiveCracker(QThread):
    progress_updated = pyqtSignal(int)
    status_message = pyqtSignal(str)
    password_found = pyqtSignal(str)
    finished = pyqtSignal(bool)

    def __init__(self, archive_path, dictionary_paths, recursive=False, seven_zip_path="7z.exe"):
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

    def process_dictionary(self, dict_path):
        try:
            # 尝试UTF-8编码
            try:
                with codecs.open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except:
                # 尝试GBK编码
                with codecs.open(dict_path, 'r', encoding='gbk', errors='ignore') as f:
                    lines = f.readlines()

            for line in lines:
                while self.is_paused() and not self.is_stopped():
                    self.msleep(100)

                if self.is_stopped():
                    return False

                password = line.strip()
                if not password:
                    continue

                self.tried_passwords += 1
                self.status_message.emit(f"正在尝试: {password}")
                self.progress_updated.emit(int((self.tried_passwords / self.total_passwords) * 100))

                if self.try_password(password):
                    self.found_password = password
                    self.password_found.emit(password)
                    return True
        except Exception as e:
            self.status_message.emit(f"处理字典文件 {dict_path} 时出错: {str(e)}")
            return False

    def run(self):
        try:
            # 检查7z.exe是否存在
            if not os.path.exists(self.seven_zip_path):
                self.status_message.emit(f"错误: 7z.exe 未找到 ({self.seven_zip_path})")
                self.finished.emit(False)
                return

            # 检查压缩文件是否存在
            if not os.path.exists(self.archive_path):
                self.status_message.emit(f"错误: 压缩文件未找到 ({self.archive_path})")
                self.finished.emit(False)
                return

            # 计算总密码数
            self.total_passwords = 0
            for dict_path in self.dictionary_paths:
                if os.path.isfile(dict_path):
                    self.total_passwords += self.count_passwords(dict_path)
                elif os.path.isdir(dict_path) and self.recursive:
                    for root, _, files in os.walk(dict_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            self.total_passwords += self.count_passwords(file_path)

            if self.total_passwords == 0:
                self.status_message.emit("错误: 没有找到有效的字典文件或密码")
                self.finished.emit(False)
                return

            # 处理字典文件
            for dict_path in self.dictionary_paths:
                if os.path.isfile(dict_path):
                    if self.process_dictionary(dict_path):
                        self.finished.emit(True)
                        return
                elif os.path.isdir(dict_path) and self.recursive:
                    for root, _, files in os.walk(dict_path):
                        for file in files:
                            if self.is_stopped():
                                self.finished.emit(False)
                                return

                            file_path = os.path.join(root, file)
                            if self.process_dictionary(file_path):
                                self.finished.emit(True)
                                return

            self.status_message.emit("密码未找到")
            self.finished.emit(False)
        except Exception as e:
            self.status_message.emit(f"发生错误: {str(e)}")
            self.finished.emit(False)


class PasswordCrackerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("7z压缩文件密码破解工具")
        self.setGeometry(100, 100, 900, 700)
        self.cracker_thread = None
        self.settings = QSettings("7zCracker", "PasswordCracker")
        self.config_file = "cracker_config.json"
        self.password_log_file = "found_passwords.log"
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()

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
        main_layout.addWidget(sevenz_group)

        # 压缩文件选择
        archive_group = QGroupBox("压缩文件")
        archive_layout = QHBoxLayout()
        self.archive_path_edit = QLineEdit()
        self.archive_path_edit.setPlaceholderText("选择压缩文件...")
        browse_archive_btn = QPushButton("浏览...")
        browse_archive_btn.clicked.connect(self.browse_archive)
        archive_layout.addWidget(self.archive_path_edit)
        archive_layout.addWidget(browse_archive_btn)
        archive_group.setLayout(archive_layout)
        main_layout.addWidget(archive_group)

        # 字典文件管理
        dict_group = QGroupBox("字典管理")
        dict_layout = QVBoxLayout()

        # 字典列表
        self.dict_list = QListWidget()
        self.dict_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.dict_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.dict_list.customContextMenuRequested.connect(self.show_dict_list_context_menu)
        
        # 字典操作按钮
        dict_button_layout = QHBoxLayout()
        add_file_btn = QPushButton("添加文件")
        add_file_btn.clicked.connect(self.add_dict_file)
        add_dir_btn = QPushButton("添加目录")
        add_dir_btn.clicked.connect(self.add_dict_dir)
        remove_btn = QPushButton("移除选中")
        remove_btn.clicked.connect(self.remove_selected_dicts)
        clear_btn = QPushButton("清空列表")
        clear_btn.clicked.connect(self.clear_dict_list)
        
        dict_button_layout.addWidget(add_file_btn)
        dict_button_layout.addWidget(add_dir_btn)
        dict_button_layout.addWidget(remove_btn)
        dict_button_layout.addWidget(clear_btn)
        
        # 递归搜索复选框
        self.recursive_check = QCheckBox("递归搜索目录中的字典文件")
        
        dict_layout.addWidget(self.dict_list)
        dict_layout.addLayout(dict_button_layout)
        dict_layout.addWidget(self.recursive_check)
        
        dict_group.setLayout(dict_layout)
        main_layout.addWidget(dict_group)

        # 控制按钮
        control_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始")
        self.start_btn.clicked.connect(self.start_cracking)
        self.pause_btn = QPushButton("暂停")
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.stop_cracking)
        self.stop_btn.setEnabled(False)
        
        save_config_btn = QPushButton("保存配置")
        save_config_btn.clicked.connect(self.save_settings)
        load_config_btn = QPushButton("加载配置")
        load_config_btn.clicked.connect(self.load_settings)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.pause_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addStretch()
        control_layout.addWidget(save_config_btn)
        control_layout.addWidget(load_config_btn)
        main_layout.addLayout(control_layout)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.progress_bar)

        # 状态信息
        self.status_display = QTextEdit()
        self.status_display.setReadOnly(True)
        main_layout.addWidget(self.status_display)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def browse_sevenz(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择7z.exe", "", "可执行文件 (*.exe)")
        if file_path:
            self.sevenz_path_edit.setText(file_path)

    def browse_archive(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择压缩文件", "", 
            "7z支持的所有格式 (*.7z *.zip *.rar *.tar *.gz *.bz2 *.xz *.cab *.arj *.z *.lzh *.iso);;所有文件 (*.*)")
        if file_path:
            self.archive_path_edit.setText(file_path)

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

    def save_settings(self):
        # 保存到QSettings
        self.settings.setValue("sevenz_path", self.sevenz_path_edit.text())
        self.settings.setValue("archive_path", self.archive_path_edit.text())
        self.settings.setValue("recursive", self.recursive_check.isChecked())
        
        # 保存字典列表
        dict_paths = []
        for i in range(self.dict_list.count()):
            dict_paths.append(self.dict_list.item(i).data(Qt.UserRole))
        self.settings.setValue("dict_paths", json.dumps(dict_paths))
        
        # 保存到配置文件
        config = {
            "sevenz_path": self.sevenz_path_edit.text(),
            "archive_path": self.archive_path_edit.text(),
            "recursive": self.recursive_check.isChecked(),
            "dict_paths": dict_paths
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
                self.archive_path_edit.setText(config.get("archive_path", ""))
                self.recursive_check.setChecked(config.get("recursive", False))
                
                # 加载字典列表
                self.dict_list.clear()
                for path in config.get("dict_paths", []):
                    self.add_dict_item(path)
                
                self.status_display.append("配置已从文件加载")
                return
        except Exception as e:
            self.status_display.append(f"从文件加载配置失败: {str(e)}")
        
        # 如果文件加载失败，从QSettings加载
        sevenz_path = self.settings.value("sevenz_path", "7z.exe")
        self.sevenz_path_edit.setText(sevenz_path)
        
        archive_path = self.settings.value("archive_path", "")
        self.archive_path_edit.setText(archive_path)
        
        recursive = self.settings.value("recursive", False, type=bool)
        self.recursive_check.setChecked(recursive)
        
        # 加载字典列表
        self.dict_list.clear()
        dict_paths = json.loads(self.settings.value("dict_paths", "[]"))
        for path in dict_paths:
            self.add_dict_item(path)

    def closeEvent(self, event):
        self.save_settings()
        if self.cracker_thread and self.cracker_thread.isRunning():
            self.cracker_thread.stop()
            self.cracker_thread.wait(2000)
        event.accept()

    def log_password(self, archive_path, password):
        try:
            with open(self.password_log_file, 'a', encoding='utf-8') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{timestamp} | {archive_path} | 密码: {password}\n")
        except Exception as e:
            self.status_display.append(f"记录密码失败: {str(e)}")

    def start_cracking(self):
        archive_path = self.archive_path_edit.text()
        sevenz_path = self.sevenz_path_edit.text() or "7z.exe"

        if not archive_path:
            QMessageBox.warning(self, "警告", "请选择压缩文件")
            return

        if not os.path.exists(archive_path):
            QMessageBox.warning(self, "警告", "压缩文件不存在")
            return

        if self.dict_list.count() == 0:
            QMessageBox.warning(self, "警告", "请添加至少一个字典文件或目录")
            return

        # 收集选中的字典路径
        dict_paths = []
        for i in range(self.dict_list.count()):
            dict_paths.append(self.dict_list.item(i).data(Qt.UserRole))

        self.status_display.clear()
        self.status_display.append(f"开始破解: {archive_path}")
        self.status_display.append(f"使用7z路径: {sevenz_path}")
        self.status_display.append(f"使用字典: {', '.join(dict_paths)}")

        self.cracker_thread = ArchiveCracker(
            archive_path, dict_paths, self.recursive_check.isChecked(), sevenz_path)
        self.cracker_thread.password_found.connect(self.password_found)
        self.cracker_thread.status_message.connect(self.update_status)
        self.cracker_thread.progress_updated.connect(self.update_progress)
        self.cracker_thread.finished.connect(self.cracking_finished)

        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)

        self.cracker_thread.start()

    def toggle_pause(self):
        if self.cracker_thread.is_paused():
            self.cracker_thread.resume()
            self.pause_btn.setText("暂停")
            self.status_display.append("继续破解...")
        else:
            self.cracker_thread.pause()
            self.pause_btn.setText("继续")
            self.status_display.append("已暂停...")

    def stop_cracking(self):
        if self.cracker_thread:
            self.cracker_thread.stop()
            self.status_display.append("正在停止...")

    def password_found(self, password):
        archive_path = self.archive_path_edit.text()
        self.status_display.append(f"密码找到: {password}")
        self.log_password(archive_path, password)
        QMessageBox.information(self, "成功", f"密码找到: {password}\n\n已记录到日志文件")

    def update_status(self, message):
        self.status_display.append(message)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def cracking_finished(self, success):
        if not success:
            self.status_display.append("破解完成，未找到密码")

        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.pause_btn.setText("暂停")

        self.cracker_thread = None


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