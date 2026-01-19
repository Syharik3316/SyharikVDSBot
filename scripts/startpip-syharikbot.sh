#!/bin/bash
set -e

#Переход в директорию с проектом
cd /path/to/project

#Инсталяция зависимостей
pip install telebot --break-system-packages

#Инсталяция зависимостей
pip install paramiko --break-system-packages

#Инсталяция зависимостей
pip install -r requirements.txt --break-system-packages

#Запуск бота
python3 main.py