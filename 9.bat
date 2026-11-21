cls
pyinstaller --noconfirm --onefile --windowed --icon=icon.ico --add-data "icon.ico;." --exclude-module=torch Password_Cracker_GUI.py
