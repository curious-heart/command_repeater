#!/bin/sh

script_name=$(basename "$0")
usage_str="用法： "$script_name" 目标文件夹（必须为空） 版本号"
if [ $# -lt 2 ]; then
    echo $usage_str
    exit 1
fi

dest_folder=$1
ver_str=$2

if [ "$(ls -A "$dest_folder" 2>/dev/null)" ]; then
    echo "错误：目标文件夹 $dest_folder 不是空的。"
    exit 2
fi

qt_deploy_tool=/usr/bin/linuxdeployqt-continuous-aarch64.AppImage
desktop_file_name=x-data-scanner.desktop
exe_folder=../"$desktop_file_name"-release

if [ ! -x "$qt_deploy_tool" ]; then
    echo "部署工具 $qt_deploy_tool 不存在或不可执行。"
    exit 1
fi

cp -rp ./configs $dest_folder/
cp -rp ./app_images $dest_folder
cp -p $exe_folder/$desktop_file_name $dest_folder/
$qt_deploy_tool $dest_folder/$desktop_file_name -appimage -no-copy-copyright-files

