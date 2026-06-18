@echo off
chcp 65001 >nul
title TODO LIST 服务器
cd /d "%~dp0"
echo.
echo ╔══════════════════════════════════╗
echo ║   📋 TODO LIST 学习监督平台   ║
echo ╚══════════════════════════════════╝
echo.
echo 🚀 启动中...
node server.js
pause
