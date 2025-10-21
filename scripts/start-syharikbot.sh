#!/bin/bash
set -e

#Переход в директорию с проектом
cd /path/to/project

#Создание виртуального окружения
python3 -m venv .venv

#Активация виртуального окружения
source .venv/bin/activate

#Инсталяция зависимостей
pip install -r requirements.txt

#Запуск бота
python3 main.py