import os
import sys
import zipfile
import rarfile
import py7zr
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit,
                             QProgressBar, QMessageBox, QCheckBox, QGroupBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from threading import Lock


class UnsupportedFormatError(Exception):
    pass


class ArchiveCracker(QThread):
    progress_updated = pyqtSignal(int)
    status_message = pyqtSignal(str)
    password_found = pyqtSignal(str)
    finished = pyqtSignal(bool)

    def __init__(self, archive_path, dictionary_paths, recursive=False):
        super().__init__()
        self.archive_path = archive_path
        self.dictionary_paths = dictionary_paths
        self.recursive = recursive
        self._stop_flag = False
        self._pause_flag = False
        self.lock = Lock()
        self.total_passwords = 0
        self.tried_passwords = 0

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
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except:
            return 0

    def get_archive_handler(self, archive_path):
        if zipfile.is_zipfile(archive_path):
            return zipfile.ZipFile
        elif rarfile.is_rarfile(archive_path):
            return rarfile.RarFile
        elif py7zr.is_7zfile(archive_path):
            return py7zr.SevenZipFile
        else:
            raise UnsupportedFormatError("不支持的压缩文件格式")

    def try_password(self, archive, password):
        try:
            if isinstance(archive, zipfile.ZipFile):
                archive.testzip()
                archive.extractall(pwd=password.encode())
                return True
            elif isinstance(archive, rarfile.RarFile):
                archive.testrar()
                archive.extractall(pwd=password)
                return True
            elif isinstance(archive, py7zr.SevenZipFile):
                archive.extractall(pwd=password)
                return True
        except:
            return False

    def process_dictionary(self, dict_path, archive_handler):
        try:
            with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                with archive_handler(self.archive_path) as archive:
                    for line in f:
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

                        if self.try_password(archive, password):
                            self.password_found.emit(password)
                            return True
        except Exception as e:
            self.status_message.emit(f"处理字典文件 {dict_path} 时出错: {str(e)}")
            return False

    def run(self):
        try:
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

            archive_handler = self.get_archive_handler(self.archive_path)

            # 处理单个字典文件
            for dict_path in self.dictionary_paths:
                if os.path.isfile(dict_path):
                    if self.process_dictionary(dict_path, archive_handler):
                        self.finished.emit(True)
                        return

            # 处理目录中的字典文件
            if self.recursive:
                for dict_path in self.dictionary_paths:
                    if os.path.isdir(dict_path):
                        for root, _, files in os.walk(dict_path):
                            for file in files:
                                if self.is_stopped():
                                    self.finished.emit(False)
                                    return

                                file_path = os.path.join(root, file)
                                if self.process_dictionary(file_path, archive_handler):
                                    self.finished.emit(True)
                                    return

            self.status_message.emit("密码未找到")
            self.finished.emit(False)
        except UnsupportedFormatError as e:
            self.status_message.emit(f"错误: {str(e)}")
            self.finished.emit(False)
        except Exception as e:
            self.status_message.emit(f"发生错误: {str(e)}")
            self.finished.emit(False)


class PasswordCrackerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("压缩文件密码破解工具")
        self.setGeometry(100, 100, 800, 600)
        self.cracker_thread = None
        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout()

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

        # 字典文件/目录选择
        dict_group = QGroupBox("字典设置")
        dict_layout = QVBoxLayout()

        # 字典文件选择
        dict_file_layout = QHBoxLayout()
        self.dict_path_edit = QLineEdit()
        self.dict_path_edit.setPlaceholderText("选择字典文件或目录...")
        browse_dict_btn = QPushButton("浏览...")
        browse_dict_btn.clicked.connect(self.browse_dict)
        dict_file_layout.addWidget(self.dict_path_edit)
        dict_file_layout.addWidget(browse_dict_btn)
        dict_layout.addLayout(dict_file_layout)

        # 递归搜索复选框
        self.recursive_check = QCheckBox("递归搜索目录中的字典文件")
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
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.pause_btn)
        control_layout.addWidget(self.stop_btn)
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

    def browse_archive(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择压缩文件", "",
            "压缩文件 (*.zip *.rar *.7z);;所有文件 (*.*)")
        if file_path:
            self.archive_path_edit.setText(file_path)

    def browse_dict(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件或目录", "",
            "文本文件 (*.txt);;所有文件 (*.*)")
        if path:
            self.dict_path_edit.setText(path)

    def start_cracking(self):
        archive_path = self.archive_path_edit.text()
        dict_path = self.dict_path_edit.text()

        if not archive_path:
            QMessageBox.warning(self, "警告", "请选择压缩文件")
            return

        if not dict_path:
            QMessageBox.warning(self, "警告", "请选择字典文件或目录")
            return

        if not os.path.exists(archive_path):
            QMessageBox.warning(self, "警告", "压缩文件不存在")
            return

        if not os.path.exists(dict_path):
            QMessageBox.warning(self, "警告", "字典文件或目录不存在")
            return

        # 收集所有字典路径
        dict_paths = []
        if os.path.isfile(dict_path):
            dict_paths.append(dict_path)
        elif os.path.isdir(dict_path):
            if self.recursive_check.isChecked():
                dict_paths.append(dict_path)
            else:
                for item in os.listdir(dict_path):
                    full_path = os.path.join(dict_path, item)
                    if os.path.isfile(full_path):
                        dict_paths.append(full_path)

        self.status_display.clear()
        self.status_display.append(f"开始破解: {archive_path}")
        self.status_display.append(f"使用字典: {', '.join(dict_paths)}")

        self.cracker_thread = ArchiveCracker(
            archive_path, dict_paths, self.recursive_check.isChecked())
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
        self.status_display.append(f"密码找到: {password}")
        QMessageBox.information(self, "成功", f"密码找到: {password}")

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
    
    # 确保必要的库已安装
    try:
        import zipfile
        import rarfile
        import py7zr
    except ImportError as e:
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("缺少必要的依赖库")
        msg.setInformativeText(f"请安装以下Python库: {str(e)}")
        msg.setWindowTitle("错误")
        msg.exec_()
        sys.exit(1)
    
    window = PasswordCrackerGUI()
    window.show()
    sys.exit(app.exec_())