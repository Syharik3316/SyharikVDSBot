import telebot
import psutil
import os
import socket
import paramiko
import threading
import time
import json
import shutil
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# --- ГЛОБАЛЬНЫЕ НАСТРОЙКИ ---
BOT_TOKEN = 'BOT_TOKEN_HERE'
AUTHORIZED_USER_IDS = [USERIDHERE]
CONFIG_FILE = 'config.json'

# --- НАСТРОЙКИ МОНИТОРИНГА (для локального сервера) ---
MONITORING_ENABLED = True
CPU_THRESHOLD = 90.0
RAM_THRESHOLD = 90.0
DISK_THRESHOLD = 85.0
MONITORING_INTERVAL = 60

# --- Глобальные переменные ---
bot = telebot.TeleBot(BOT_TOKEN)
SERVERS = {}
SSH_PASSWORDS = {}  # { (user_id, server_name): "password" }
user_action_state = {} # { user_id: {type, payload, server_name, etc...} }
alert_states = {'cpu': False, 'ram': False, 'disk': False}


# --- ЗАГРУЗКА КОНФИГУРАЦИИ ---
def load_config():
    global SERVERS
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            SERVERS = {s['name']: s for s in config['servers']}
        print("Конфигурация серверов успешно загружена.")
        return True
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Ошибка загрузки {CONFIG_FILE}: {e}")
        return False

# --- ОСНОВНЫЕ ИСПОЛНЯЮЩИЕ ФУНКЦИИ ---

def get_ssh_connection(server, user_id):
    """Устанавливает и возвращает SSH соединение."""
    if server.get('host') == 'local':
        return None

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    auth_props = {'username': server['user']}
    if server['auth_method'] == 'key':
        try:
            auth_props['pkey'] = paramiko.RSAKey.from_private_key_file(server['key_path'])
        except paramiko.ssh_exception.SSHException:
            try:
                auth_props['pkey'] = paramiko.Ed25519Key.from_private_key_file(server['key_path'])
            except paramiko.ssh_exception.SSHException:
                auth_props['pkey'] = paramiko.ECDSAKey.from_private_key_file(server['key_path'])

    elif server['auth_method'] == 'password':
        password = SSH_PASSWORDS.get((user_id, server['name']))
        if not password:
            raise Exception("Пароль для этого сервера не был предоставлен.")
        auth_props['password'] = password

    ssh.connect(server['host'], **auth_props, timeout=15)
    return ssh

def execute_ssh_command(command, server, chat_id, message_id, user_id):
    try:
        bot.edit_message_text(f"Выполняю на *{server['name']}*: `{command}`", chat_id, message_id, parse_mode="Markdown")
        
        if server.get('host') == 'local':
            import subprocess
            process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
            output, error = process.stdout, process.stderr
        else:
            ssh = get_ssh_connection(server, user_id)
            stdin, stdout, stderr = ssh.exec_command(command, timeout=120)
            output = stdout.read().decode('utf-8', 'ignore')
            error = stderr.read().decode('utf-8', 'ignore')
            ssh.close()

        header = f"✅ *Результат с {server['name']}:* `{command}`\n\n"
        full_log = ""
        if output: full_log += f"--- ВЫВОД ---\n{output.strip()}"
        if error: full_log += f"\n\n--- ОШИБКИ ---\n{error.strip()}"
        if not full_log.strip(): full_log = "_Команда выполнена без вывода._"

        response = header
        if len(header) + len(full_log) < 4096:
            if output or error: response += f"```\n{full_log}\n```"
            else: response += full_log
        else:
            available_space = 4096 - len(header) - 50
            truncated_log = full_log[:available_space]
            response += f"```\n{truncated_log}\n```\n... (ответ был сокращен)"
        
        bot.edit_message_text(response, chat_id, message_id, parse_mode="Markdown", disable_web_page_preview=True)

    except Exception as e:
        error_text = f"❌ Ошибка на *{server['name']}*:\n```\n{str(e)}\n```"
        bot.edit_message_text(error_text, chat_id, message_id, parse_mode="Markdown")


def execute_file_download(remote_path, server, chat_id, message_id, user_id):
    local_path = os.path.basename(remote_path)
    try:
        bot.edit_message_text(f"Скачиваю `{remote_path}` с *{server['name']}*...", chat_id, message_id, parse_mode="Markdown")
        
        if server.get('host') == 'local':
             shutil.copy(remote_path, local_path)
        else:
            ssh = get_ssh_connection(server, user_id)
            sftp = ssh.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            ssh.close()

        bot.delete_message(chat_id, message_id)
        with open(local_path, 'rb') as doc:
            bot.send_document(chat_id, doc, caption=f"Файл `{local_path}` с сервера *{server['name']}*", parse_mode="Markdown")
        os.remove(local_path)
        
    except Exception as e:
        if os.path.exists(local_path): os.remove(local_path)
        error_text = f"❌ Ошибка скачивания с *{server['name']}*:\n```\n{str(e)}\n```"
        bot.edit_message_text(error_text, chat_id, message_id, parse_mode="Markdown")

def execute_file_upload(local_path, remote_path, server, chat_id, message_id, user_id):
    try:
        bot.edit_message_text(f"Загружаю *{os.path.basename(local_path)}* на *{server['name']}* в `{remote_path}`...", chat_id, message_id, parse_mode="Markdown")
        
        if server.get('host') == 'local':
             shutil.move(local_path, remote_path)
        else:
            ssh = get_ssh_connection(server, user_id)
            sftp = ssh.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            ssh.close()
            os.remove(local_path)

        bot.edit_message_text(f"✅ Файл успешно загружен на *{server['name']}*", chat_id, message_id, parse_mode="Markdown")
    except Exception as e:
        if os.path.exists(local_path): os.remove(local_path)
        error_text = f"❌ Ошибка загрузки на *{server['name']}*:\n```\n{str(e)}\n```"
        bot.edit_message_text(error_text, chat_id, message_id, parse_mode="Markdown")

def get_remote_status(server, chat_id, message_id, user_id):
    CMD = "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'; echo '--'; free | awk '/Mem/ {printf(\"%.1f\", $3/$2*100)}'; echo '--'; df -h / | awk 'NR==2 {print $5}'"
    try:
        bot.edit_message_text(f"Собираю статистику с *{server['name']}*...", chat_id, message_id, parse_mode="Markdown")
        ssh = get_ssh_connection(server, user_id)
        stdin, stdout, stderr = ssh.exec_command(CMD)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8')
        ssh.close()

        if error and not output: raise Exception(error)
        
        cpu, ram, disk = output.split('--')
        status_message = f"*Статус {server['name']}:*\n\n`ЦПУ:` {cpu.strip()}%\n`ОЗУ:` {ram.strip()}%\n`Диск:` {disk.strip()}"
        bot.edit_message_text(status_message, chat_id, message_id, parse_mode="Markdown")
    except Exception as e:
        bot.edit_message_text(f"❌ Не удалось получить статус с *{server['name']}*:\n```{e}```", chat_id, message_id, parse_mode="Markdown")


# --- ОБРАБОТЧИКИ КОМАНД ---

def is_authorized(user_id):
    if user_id not in AUTHORIZED_USER_IDS:
        # bot.send_message(user_id, "⛔ У вас нет доступа к этому боту.")
        return False
    return True

def ask_for_server(chat_id, action_type, text, payload=None):
    user_action_state[chat_id] = {'type': action_type, 'payload': payload}
    markup = InlineKeyboardMarkup(row_width=2)
    buttons = [InlineKeyboardButton(name, callback_data=f"select_server_{name}") for name in SERVERS.keys()]
    markup.add(*buttons)
    bot.send_message(chat_id, text, reply_markup=markup)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    if not is_authorized(message.from_user.id): return
    bot.reply_to(message, "Бот-администратор для VDS серверов. Введите /help для вывода списка команд.")

@bot.message_handler(commands=['help', 'h'])
def send_help(message):
    if not is_authorized(message.from_user.id): return
    help_text = (
        "*Бот для управления серверами*\n\n"
        "1. Вы вызываете команду (напр. `/logs /var/log/syslog`).\n"
        "2. Бот спрашивает, на каком сервере ее выполнить.\n\n"
        "*Команды:* \n"
        "*/status, /s* - Статус сервера (ЦПУ, ОЗУ, Диск)\n"
        "*/exec, /e <команда>* - Выполнить команду\n"
        "*/logs, /l <путь> [строк]* - Показать лог-файл\n"
        "*/download, /d <путь>* - Скачать файл с сервера\n"
        "*/upload, /up <путь>* - Загрузить файл в указанную папку\n"
        "*/update, /u* - Выполнить `apt update && apt upgrade -y`\n"
        "*/reboot, /r* - Перезагрузить сервер\n"
        "*/netstat, /ns* - Показать активные порты (`netstat -tuln`)\n\n"
        f"*Мониторинг:* {'включен' if MONITORING_ENABLED else 'выключен'}. Бот следит за состоянием *локального* сервера."
    )
    bot.reply_to(message, help_text, parse_mode="Markdown")

@bot.message_handler(commands=['status', 's'])
def command_status(message):
    if not is_authorized(message.from_user.id): return
    ask_for_server(message.chat.id, 'status', 'Статус какого сервера посмотреть?')

@bot.message_handler(commands=['exec', 'e'])
def command_exec(message):
    if not is_authorized(message.from_user.id): return
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "Пример: `/exec ls -l /root`")
        return
    ask_for_server(message.chat.id, 'exec', 'Где выполнить команду?', payload=parts[1])

@bot.message_handler(commands=['logs', 'l'])
def command_logs(message):
    if not is_authorized(message.from_user.id): return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Пример: `/logs /var/log/syslog 100`")
        return
    path = parts[1]
    lines = parts[2] if len(parts) > 2 else 50
    command = f"tail -n {lines} {path}"
    ask_for_server(message.chat.id, 'exec', f'Показать лог `{path}`?', payload=command)
    
@bot.message_handler(commands=['download', 'd'])
def command_download(message):
    if not is_authorized(message.from_user.id): return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Пример: `/d /etc/nginx/nginx.conf`")
        return
    path = parts[1]
    ask_for_server(message.chat.id, 'download', f'Скачать `{path}`?', payload=path)

@bot.message_handler(commands=['upload', 'up'])
def command_upload_prepare(message):
    if not is_authorized(message.from_user.id): return
    parts = message.text.split()
    if len(parts) < 2:
        bot.reply_to(message, "Пример: `/up /root/` (укажите папку для загрузки)")
        return
    path = parts[1]
    if not path.endswith('/'):
        bot.reply_to(message, "Путь должен быть папкой и заканчиваться на `/`")
        return
    ask_for_server(message.chat.id, 'upload', f'Загрузить файл в `{path}`?', payload=path)

@bot.message_handler(commands=['update', 'u'])
def command_update(message):
    if not is_authorized(message.from_user.id): return
    cmd = 'apt update && apt upgrade -y'
    ask_for_server(message.chat.id, 'exec', 'Выполнить полное обновление системы?', payload=cmd)

@bot.message_handler(commands=['reboot', 'r'])
def command_reboot(message):
    if not is_authorized(message.from_user.id): return
    ask_for_server(message.chat.id, 'exec', 'Вы уверены, что хотите перезагрузить сервер?', payload='reboot')
    
@bot.message_handler(commands=['netstat', 'ns'])
def command_netstat(message):
    if not is_authorized(message.from_user.id): return
    ask_for_server(message.chat.id, 'exec', 'Показать активные сетевые порты?', payload='netstat -tuln')

# --- ОБРАБОТЧИКИ ВВОДА ПОЛЬЗОВАТЕЛЯ ---

def process_action(user_id, chat_id, message_id):
    state = user_action_state.get(user_id, {})
    server_name = state.get('server_name')
    if not server_name:
        bot.edit_message_text("❌ Ошибка: сервер не был выбран.", chat_id, message_id)
        if user_id in user_action_state: del user_action_state[user_id]
        return

    server = SERVERS.get(server_name)
    action_type = state.get('type')
    payload = state.get('payload')

    if action_type == 'status':
        if server.get('host') == 'local':
            disk = psutil.disk_usage('/'); cpu = psutil.cpu_percent(1); ram = psutil.virtual_memory()
            bot.edit_message_text(f"*Статус {server['name']}:*\n\n`ЦПУ:` {cpu}%\n`ОЗУ:` {ram.percent}%\n`Диск:` {disk.percent}%", chat_id, message_id, parse_mode="Markdown")
        else:
            get_remote_status(server, chat_id, message_id, user_id)
    
    elif action_type == 'exec':
        execute_ssh_command(payload, server, chat_id, message_id, user_id)
    
    elif action_type == 'download':
        execute_file_download(payload, server, chat_id, message_id, user_id)
    
    elif action_type == 'upload':
        bot.edit_message_text(f"Готов принять файл для загрузки на *{server['name']}* в `{payload}`", chat_id, message_id, parse_mode="Markdown")
        state['awaiting_file'] = True
        return # Не удаляем состояние, ждем файл

    if user_id in user_action_state and not state.get('awaiting_file'):
        del user_action_state[user_id]

@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    user_id = call.from_user.id
    if not is_authorized(user_id): 
        bot.answer_callback_query(call.id, "Нет доступа")
        return
    
    state = user_action_state.get(user_id)
    if not state:
        bot.edit_message_text("Действие истекло, начните заново.", call.message.chat.id, call.message.message_id)
        return

    if call.data.startswith('select_server_'):
        server_name = call.data.replace('select_server_', '')
        state['server_name'] = server_name
        server = SERVERS.get(server_name)

        if server['auth_method'] == 'password' and not SSH_PASSWORDS.get((user_id, server_name)):
            state['awaiting_password'] = True
            bot.edit_message_text(f"Для *{server_name}* нужен пароль.\nОтправьте его следующим сообщением:", call.message.chat.id, call.message.message_id, parse_mode="Markdown")
            return
        
        markup = InlineKeyboardMarkup().add(InlineKeyboardButton("✅ Подтвердить", callback_data="confirm_action"), InlineKeyboardButton("❌ Отмена", callback_data="cancel_action"))
        action_name = state['type'].capitalize()
        payload_text = f": `{state['payload']}`" if state.get('payload') else ''
        bot.edit_message_text(f"Выполнить *{action_name}* на *{server_name}*?{payload_text}", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

    elif call.data == 'confirm_action':
        bot.answer_callback_query(call.id, "Принято")
        process_action(user_id, call.message.chat.id, call.message.message_id)

    elif call.data == 'cancel_action':
        if user_id in user_action_state: del user_action_state[user_id]
        bot.answer_callback_query(call.id, "Отменено")
        bot.edit_message_text("Действие отменено.", call.message.chat.id, call.message.message_id)

@bot.message_handler(content_types=['text'], func=lambda message: user_action_state.get(message.from_user.id, {}).get('awaiting_password'))
def handle_password(message):
    user_id = message.from_user.id
    state = user_action_state[user_id]
    server_name = state['server_name']
    
    SSH_PASSWORDS[(user_id, server_name)] = message.text
    bot.delete_message(message.chat.id, message.message_id)
    del state['awaiting_password']

    markup = InlineKeyboardMarkup().add(InlineKeyboardButton("✅ Подтвердить", callback_data="confirm_action"), InlineKeyboardButton("❌ Отмена", callback_data="cancel_action"))
    action_name = state['type'].capitalize()
    payload_text = f": `{state['payload']}`" if state.get('payload') else ''
    bot.send_message(message.chat.id, f"Пароль принят. Выполнить *{action_name}* на *{server_name}*?{payload_text}", reply_markup=markup, parse_mode="Markdown")

@bot.message_handler(content_types=['document'], func=lambda message: user_action_state.get(message.from_user.id, {}).get('awaiting_file'))
def handle_document(message):
    user_id = message.from_user.id
    state = user_action_state[user_id]
    server_name = state['server_name']
    server = SERVERS[server_name]
    remote_dir = state['payload']
    
    sent_msg = bot.reply_to(message, "Скачиваю файл от Telegram...")
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        local_path = message.document.file_name
        with open(local_path, 'wb') as new_file:
            new_file.write(downloaded_file)

        remote_path = os.path.join(remote_dir, message.document.file_name)
        execute_file_upload(local_path, remote_path, server, sent_msg.chat.id, sent_msg.message_id, user_id)
    except Exception as e:
        bot.edit_message_text(f"❌ Не удалось обработать файл: {e}", sent_msg.chat.id, sent_msg.message_id)
    finally:
        if user_id in user_action_state:
            del user_action_state[user_id]

# --- МОНИТОРИНГ ---
def monitoring_loop():
    local_server_name = next((name for name, s in SERVERS.items() if s.get('host') == 'local'), None)
    if not local_server_name:
        print("Мониторинг не запущен: локальный сервер не найден в config.json.")
        return

    while True:
        try:
            time.sleep(MONITORING_INTERVAL)
            cpu, ram, disk = psutil.cpu_percent(), psutil.virtual_memory().percent, psutil.disk_usage('/').percent
            
            checks = {'cpu': (cpu, CPU_THRESHOLD), 'ram': (ram, RAM_THRESHOLD), 'disk': (disk, DISK_THRESHOLD)}
            names = {'cpu': 'ЦПУ', 'ram': 'ОЗУ', 'disk': 'Диск'}

            for key, (value, threshold) in checks.items():
                if value > threshold and not alert_states[key]:
                    alert_states[key] = True
                    for uid in AUTHORIZED_USER_IDS:
                        bot.send_message(uid, f"🚨 ВНИМАНИЕ [{local_server_name}]: Нагрузка на {names[key]} - {value:.1f}% (Порог {threshold}%)")
                elif value <= threshold and alert_states[key]:
                    alert_states[key] = False
                    for uid in AUTHORIZED_USER_IDS:
                        bot.send_message(uid, f"✅ НОРМА [{local_server_name}]: Нагрузка на {names[key]} вернулась в норму ({value:.1f}%)")
        except Exception as e:
            print(f"Ошибка в цикле мониторинга: {e}")

# --- ЗАПУСК БОТА ---
if __name__ == '__main__':
    if load_config():
        if MONITORING_ENABLED:
            monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
            monitoring_thread.start()
        
        print("Бот запущен...")
        bot.polling(none_stop=True, interval=0)
    else:
        print("Бот не может быть запущен из-за ошибки конфигурации.")


