cls
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "*.build" rmdir /s /q "*.build"
if exist "*.dist" rmdir /s /q "*.dist"

nuitka --standalone ^
    --enable-plugin=pyqt5 ^
    --windows-console-mode=disable ^
    --windows-icon-from-ico=icon.ico ^
    --jobs=4 ^
    Password_Cracker_GUI.py

if exist "*.build" rmdir /s /q "*.build"