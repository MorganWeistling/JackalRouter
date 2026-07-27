#!/bin/bash
# JackalRouter — удалённый деплой (двойной клик на macOS)
# Если Gatekeeper блокирует: правый клик → «Открыть», или в терминале:
#   chmod +x deploy.command && ./deploy.command
cd "$(dirname "$0")" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ОШИБКА] Python 3 не найден."
    echo "Установите Command Line Tools:  xcode-select --install"
    echo "или Python с https://www.python.org/downloads/"
    read -n 1 -r -p "Нажмите любую клавишу для выхода…"
    exit 1
fi

python3 deploy.py "$@"

echo ""
read -n 1 -r -p "Готово. Нажмите любую клавишу для выхода…"
