@echo off
chcp 65001 >nul
title GenRouter Pro Installer - Cai dat cho Mini Router
cd /d "%~dp0"
python GenRouter_Installer.py
pause
