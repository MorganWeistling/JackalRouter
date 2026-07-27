@echo off
REM JackalRouter — удалённый деплой (двойной клик)
setlocal
cd /d "%~dp0"
where python >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Python не найден. Установите Python 3 с python.org и повторите.
    echo.
    pause
    exit /b 1
)
python "%~dp0deploy.py" %*
echo.
pause
