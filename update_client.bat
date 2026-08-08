@echo off
REM JackalRouter — пересборка Windows-клиента после самообновления.
REM Запускается САМИМ клиентом (кнопка "Update клиента"), не руками:
REM работающий .exe не может перезаписать сам себя, поэтому клиент
REM обновляет client/client.py и передаёт эстафету этому скрипту, а сам
REM закрывается — скрипт ждёт полного выхода, пересобирает через
REM PyInstaller и перезапускает уже новую версию.
REM chcp ОБЯЗАТЕЛЕН: без него cmd.exe читает этот UTF-8 файл в системной
REM (не-UTF8) кодовой странице и ломает парсинг прямо на кириллице в echo —
REM проверено, без chcp падает с "'закрытия' is not recognized as ...".
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Python не найден — пересобрать клиента нечем.
    echo Установите Python 3 с python.org и запустите этот файл ещё раз.
    pause
    exit /b 1
)

echo Жду закрытия JackalRouter.exe...
REM Wait-Process вместо tasklist^|find: последний оказался ненадёжным (падает
REM с "Parameter format not correct" в части окружений) и не нужен вовсе —
REM PowerShell есть в любой современной Windows. -ErrorAction SilentlyContinue
REM делает вызов безопасным, если процесс уже не запущен (или ещё не успел
REM стартовать) — тогда просто не ждём.
powershell -NoProfile -Command "Wait-Process -Name 'JackalRouter' -ErrorAction SilentlyContinue" >nul 2>&1
REM небольшая пауза — файл exe может ещё долю секунды считаться занятым
REM сразу после завершения процесса
timeout /t 1 /nobreak >nul

REM Бэкап текущего exe — если пересборка провалится, вернём рабочую версию
REM вместо того, чтобы оставить пользователя вообще без клиента.
if exist "client\dist\JackalRouter.exe" (
    move /Y "client\dist\JackalRouter.exe" "client\dist\JackalRouter.exe.bak" >nul
)

echo Пересобираю клиент (PyInstaller)...
python -m PyInstaller --noconfirm --onefile --windowed --name JackalRouter ^
    --distpath client\dist --workpath client\build --specpath client client\client.py

if errorlevel 1 (
    echo [ОШИБКА] Пересборка не удалась — возвращаю рабочую версию.
    if exist "client\dist\JackalRouter.exe.bak" move /Y "client\dist\JackalRouter.exe.bak" "client\dist\JackalRouter.exe" >nul
    if exist "client\dist\JackalRouter.exe" start "" "client\dist\JackalRouter.exe"
    pause
    exit /b 1
)

del "client\dist\JackalRouter.exe.bak" >nul 2>&1
echo Готово, запускаю новую версию.
start "" "client\dist\JackalRouter.exe"
