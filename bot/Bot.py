import logging
import re
import os
from pathlib import Path
from dotenv import load_dotenv
import paramiko
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler
import psycopg2
from psycopg2 import Error



TOKEN = os.getenv('TOKEN')
host = os.getenv('RMHOST')
port = os.getenv('RMPORT')
username = os.getenv('RMUSER')
password = os.getenv('RMPASSWORD')
debian_host = os.getenv('DBREPLHOST')
debian_port = os.getenv('DBREPLPORT')
debian_username = os.getenv('DBREPLUSER')
debian_password = os.getenv('DBREPLPASSWORD')
db_host = os.getenv('DBHOST')
db_port = os.getenv('DBPORT')
db_username = os.getenv('DBUSER')
db_password = os.getenv('DBPASSWORD')
databasee = os.getenv('DBDATABASE')

# Подключаем логирование
logging.basicConfig(
    filename='logfile.txt',  format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO, encoding="utf-8"
)
logger = logging.getLogger(__name__)

# Константы для ConversationHandler
FIND_EMAIL, FIND_PHONE_NUMBER, VERIFY_PASSWORD, GET_APT_LIST, SEARCH, CONFIRM_SAVE_PHONE_NUMBERS,  CONFIRM_SAVE_EMAILS  = range(7)


def start(update: Update, context):
    user = update.effective_user
    update.message.reply_text(f'Привет {user.full_name}!\n')
    logger.info(f"Команда /start инициирована пользователем {user.full_name}")
    logger.info(f"Бот ответил пользователю {user.full_name}: Привет {user.full_name}!")


def help_command(update: Update, context):
    update.message.reply_text('Доступные команды:\n'
                          '/find_email - поиск email-адресов\n'
                          '/find_phone_number - поиск номеров телефонов\n'
                          '/verify_password - проверка сложности пароля\n'
                          '/get_apt_list - установленные пакеты\n'
                          '/get_uname - информация о системе\n'
                          '/get_release - получение информации о релизе\n'
                          '/get_uptime - информация о времени работы системы\n'
                          '/get_df - информация о состоянии файловой системы\n'
                          '/get_free - информация о состоянии оперативной памяти\n'
                          '/get_mpstat - информация о производительности системы\n'
                          '/get_w - информация о работающих пользователях\n'
                          '/get_auths - последние входы в систему\n'
                          '/get_critical - последние критические события\n'
                          '/get_ps - запущенные процессы\n'
                          '/get_ss - используемые порты\n'
                          '/get_services - запущенные сервисы\n'
                          '/get_repl_logs - логи репликации\n'
                          '/get_emails - email-адреса\n'
                          '/get_phone_numbers - телефонные номера'
                          )


    logger.info("Инициирована команда /help")
    logger.info("Бот ответил пользователю на команду /help: Доступные команды: /find_email - поиск email-адресов, /find_phone_number - поиск номеров телефонов, /verify_password - проверка сложности пароля, /get_release - получение информации о релизе")


def find_email_command(update: Update, context):
    update.message.reply_text('Введите текст для поиска email-адресов:')
    logger.info(f"Запрос на поиск email-адресов инициирован пользователем {update.message.from_user.full_name}")
    return FIND_EMAIL

def get_apt_list_command(update: Update, context):
    update.message.reply_text("Выберите действие:\n" \
                 "1. Вывести список всех установленных пакетов\n" \
                 "2. Поиск информации о пакете")
    return GET_APT_LIST

def get_apt_list(update: Update, context):
    choice = update.message.text
    if choice == '1':
         apt_list = ssh_command("dpkg-query -l", host, port, username, password, update=update)
         ps_info_lines = apt_list.splitlines()
         for line in ps_info_lines:
          update.message.reply_text(line)
         return ConversationHandler.END
    elif choice == '2':
        update.message.reply_text('Введите название пакета для поиска информации:')
        return SEARCH
    else:
        update.message.reply_text('Неверный выбор. Пожалуйста, выберите 1 или 2.')
        return GET_APT_LIST

def get_package_info(update: Update, context):
    package_name = update.message.text
    package_info = ssh_command(f"dpkg-query -l | grep {package_name}", host, port, username, password, update=update)
    ps_info_lines = package_info.splitlines()
    for line in ps_info_lines:
        update.message.reply_text(line)
    return ConversationHandler.END


def find_email(update: Update, context):
    user_input = update.message.text
    logger.info(f"Пользователь {update.message.from_user.full_name} ввел для поиска следующий текст: {user_input}")
    email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    email_list = email_regex.findall(user_input)
    if not email_list:
        update.message.reply_text('Email-адреса не найдены')
        logger.info("Email-адреса не найдены")
        return ConversationHandler.END
    emails = '\n'.join(email_list)
    update.message.reply_text(emails)
    logger.info(f"Найдены email-адреса: {emails}")
    
    update.message.reply_text('Желаете сохранить найденные email-адреса в базе данных? (Да/Нет)')
    context.user_data['emails'] = email_list  
    return CONFIRM_SAVE_EMAILS

def confirm_save_email(update: Update, context):
    user_response = update.message.text.lower()
    email_list = context.user_data.get('emails', [])
    
    if user_response == 'да':
        
        try:
            for email in email_list:
                sql_query = f"INSERT INTO emails (email) VALUES ('{email}');"
                execute_sql_query(sql_query, update)
            update.message.reply_text('Email-адреса успешно сохранены в базе данных.')
            logger.info("Email-адреса успешно сохранены в базе данных.")
            
        except Exception as error:
            update.message.reply_text('Произошла ошибка при сохранении еmail-адресов в базе данных.')
            logger.error("Ошибка при сохранении еmail-адресов в базе данных: %s", error)
    
    elif user_response == 'нет':
        update.message.reply_text('Хорошо, еmail-адреса не будут сохранены в базе данных.')
        logger.info("Пользователь отказался от сохранения еmail-адресов в базе данных.")
    
    else:
        update.message.reply_text('Пожалуйста, введите "Да" или "Нет".')
        return CONFIRM_SAVE_PHONE_NUMBERS
    
    return ConversationHandler.END

def find_phone_number_command(update: Update, context):
    update.message.reply_text('Введите текст для поиска номеров телефонов:')
    logger.info(f"Запрос на поиск номеров телефонов инициирован пользователем {update.message.from_user.full_name}")
    return FIND_PHONE_NUMBER


def find_phone_number(update: Update, context):
    user_input = update.message.text
    logger.info(f"Пользователь {update.message.from_user.full_name} ввел для поиска следующий текст: {user_input}")
    phone_num_regex = re.compile(r'(?:\+7|8)\s?-?\s?\(?(?:\d{3})\)?\s?-?\s?\d{3}\s?-?\s?\d{2}\s?-?\s?\d{2}')
    phone_num_list = phone_num_regex.findall(user_input)
    if not phone_num_list:
        update.message.reply_text('Номера телефонов не найдены')
        logger.info("Номера телефонов не найдены")
        return ConversationHandler.END
    phone_numbers = '\n'.join(phone_num_list)
    update.message.reply_text(phone_numbers)
    logger.info(f"Найдены номера телефонов: {phone_numbers}")

    update.message.reply_text('Желаете сохранить найденные номера в базе данных? (Да/Нет)')
    context.user_data['phone_numbers'] = phone_num_list  
    return CONFIRM_SAVE_PHONE_NUMBERS

def confirm_save_phone_numbers(update: Update, context):
    user_response = update.message.text.lower()
    phone_num_list = context.user_data.get('phone_numbers', [])
    
    if user_response == 'да':
        
        try:
            for phone_number in phone_num_list:
                sql_query = f"INSERT INTO phone_numbers (phone_number) VALUES ('{phone_number}');"
                execute_sql_query(sql_query, update)
            update.message.reply_text('Номера успешно сохранены в базе данных.')
            logger.info("Номера успешно сохранены в базе данных.")
            
        except Exception as error:
            update.message.reply_text('Произошла ошибка при сохранении номеров в базе данных.')
            logger.error("Ошибка при сохранении номеров в базе данных: %s", error)
    
    elif user_response == 'нет':
        update.message.reply_text('Хорошо, номера не будут сохранены в базе данных.')
        logger.info("Пользователь отказался от сохранения номеров в базе данных.")
    
    else:
        update.message.reply_text('Пожалуйста, введите "Да" или "Нет".')
        return CONFIRM_SAVE_PHONE_NUMBERS
    
    return ConversationHandler.END


def verify_password_command(update: Update, context):
    update.message.reply_text('Введите пароль для проверки сложности:')
    logger.info(f"Запрос на проверку сложности пароля инициирован пользователем {update.message.from_user.full_name}")
    return VERIFY_PASSWORD


def verify_password(update: Update, context):
    password = update.message.text
    logger.info(f"Пользователь {update.message.from_user.full_name} ввел пароль для проверки сложности: {password}")
    password_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$')
    if password_regex.match(password):
        update.message.reply_text('Пароль сложный')
        logger.info("Пароль сложный")
    else:
        update.message.reply_text('Пароль простой')
        logger.info("Пароль простой")
    return ConversationHandler.END

def get_release_command(update: Update, context):
    update.message.reply_text('Получение информации о релизе...')
    logger.info(f"Запрос на получение информации о релизе инициирован пользователем {update.message.from_user.full_name}")
    release_info = ssh_command("lsb_release -a", host, port, username, password, update=update)
    update.message.reply_text(release_info)
    logger.info(f"Информация о релизе отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_uname_command(update: Update, context):
    update.message.reply_text('Получение информации о системе...')
    logger.info(f"Запрос на получение информации о системе инициирован пользователем {update.message.from_user.full_name}")
    uname_info = ssh_command("uname -a", host, port, username, password)
    update.message.reply_text(uname_info)
    return ConversationHandler.END

def get_uptime_command(update: Update, context):
    update.message.reply_text('Получение информации о времени работы системы...')
    logger.info(f"Запрос на получение времени работы системы инициирован пользователем {update.message.from_user.full_name}")
    uptime_info = ssh_command("uptime", host, port, username, password, update=update)
    update.message.reply_text(uptime_info)
    logger.info(f"Информация о времени работы системы отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_df_command(update: Update, context):
    update.message.reply_text('Получение информации о состоянии файловой системы...')
    logger.info(f"Запрос на получение информации о состоянии файловой системы инициирован пользователем {update.message.from_user.full_name}")
    df_info = ssh_command("df -h", host, port, username, password, update=update)
    update.message.reply_text(df_info)
    logger.info(f"Информация о состоянии файловой системы отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_free_command(update: Update, context):
    update.message.reply_text('Получение информации о состоянии оперативной памяти...')
    logger.info(f"Запрос на получение информации о состоянии оперативной памяти инициирован пользователем {update.message.from_user.full_name}")
    free_info = ssh_command("free -h", host, port, username, password, update=update)
    update.message.reply_text(free_info)
    logger.info(f"Информация о состоянии оперативной памяти отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_mpstat_command(update: Update, context):
    update.message.reply_text('Получение информации о производительности системы...')
    logger.info(f"Запрос на получение информации о производительности системы инициирован пользователем {update.message.from_user.full_name}")
    mpstat_info = ssh_command("mpstat", host, port, username, password, update=update)
    update.message.reply_text(mpstat_info)
    logger.info(f"Информация о производительности системы отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_w_command(update: Update, context):
    update.message.reply_text('Получение информации о работающих пользователях...')
    logger.info(f"Запрос на получение информации о работающих пользователях инициирован пользователем {update.message.from_user.full_name}")
    w_info = ssh_command("w", host, port, username, password, update=update)
    update.message.reply_text(w_info)
    logger.info(f"Информация о работающих пользователях отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_auths_command(update: Update, context):
    update.message.reply_text('Получение информации о последних входах в систему...')
    logger.info(f"Запрос на получение информации о последних входах в систему инициирован пользователем {update.message.from_user.full_name}")
    auths_info = ssh_command("last -n 10", host, port, username, password, update=update)
    update.message.reply_text(auths_info)
    logger.info(f"Информация о последних входах в систему отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_critical_command(update: Update, context):
    update.message.reply_text('Получение информации о последних критических событиях...')
    logger.info(f"Запрос на получение информации о последних критических событиях инициирован пользователем {update.message.from_user.full_name}")
    critical_info = ssh_command("journalctl -p 0 -n 5", host, port, username, password, update=update)
    update.message.reply_text(critical_info)
    logger.info(f"Информация о последних критических событиях отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_ps_command(update: Update, context):
    update.message.reply_text('Получение информации о запущенных процессах...')
    logger.info(f"Запрос на получение информации о запущенных процессах инициирован пользователем {update.message.from_user.full_name}")
    ps_info = ssh_command("ps aux", host, port, username, password, update=update)
    
    ps_info_lines = ps_info.splitlines()
    
    for line in ps_info_lines:
        update.message.reply_text(line)
    
    logger.info(f"Информация о запущенных процессах отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_ss_command(update: Update, context):
    update.message.reply_text('Получение информации об используемых портах...')
    logger.info(f"Запрос на получение информации об используемых портах инициирован пользователем {update.message.from_user.full_name}")
    ss_info = ssh_command("ss -tuln", host, port, username, password, update=update)
    update.message.reply_text(ss_info)
    logger.info(f"Информация об используемых портах отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_services_command(update: Update, context):
    update.message.reply_text('Получение информации о запущенных сервисах...')
    logger.info(f"Запрос на получение информации о запущенных сервисах инициирован пользователем {update.message.from_user.full_name}")
    services_info = ssh_command("systemctl list-units --type=service", host, port, username, password, update=update)
    ps_info_lines = services_info.splitlines()
    
    for line in ps_info_lines:
        update.message.reply_text(line)
   
    logger.info(f"Информация о запущенных сервисах отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END


def get_repl_logs_command(update: Update, context):
    update.message.reply_text('Получение информации о логах репликации...')
    logger.info(f"Запрос на получение информации о логах репликации инициирован пользователем {update.message.from_user.full_name}")
    sql_query = "SELECT pg_read_file(pg_current_logfile());"
    data = execute_sql_query(sql_query, update)
    
    if data:
      for row in data:
        lines = row[0].split('\n')
        replication_lines = [line.strip() for line in lines if 'repl' in line.lower()]
        for line in replication_lines:
            update.message.reply_text(line.strip()) 
   
    logger.info(f"Информация о логах репликации отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_emails_command(update: Update, context):
    update.message.reply_text('Получение информации обо всех email-адресах...')
    logger.info(f"Запрос на получение информации обо всех email-адресах инициирован пользователем {update.message.from_user.full_name}")
    
    sql_query = "SELECT * FROM emails;"
    data = execute_sql_query(sql_query, update)
    
    if data:
        for row in data:
            update.message.reply_text(str(row))
    
    logger.info(f"Информация обо всех email-адресах отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def get_phone_numbers_command(update: Update, context):
    update.message.reply_text('Получение информации о телефонных номерах...')
    logger.info(f"Запрос на получение информации о телефонных номерах инициирован пользователем {update.message.from_user.full_name}")
    
    sql_query = "SELECT * FROM phone_numbers;"
    data = execute_sql_query(sql_query, update)
    
    if data:
        for row in data:
            update.message.reply_text(str(row))
    
    logger.info(f"Информация о телефонных номерах отправлена пользователю {update.message.from_user.full_name}")
    return ConversationHandler.END

def ssh_command(command, host, port, username, password, update=None):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, port=port)

        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()  # Чтение вывода ошибок
        ssh.close()

        if error:
            error_message = f"Ошибка выполнения команды '{command}': {error}"
            if update:
                update.message.reply_text(error_message)
            else:
                print(error_message)
            return None

        return output
    
    except paramiko.SSHException as e:
        error_message = f"Ошибка SSH: {e}"
        if update:
            update.message.reply_text(error_message)
        else:
            print(error_message)
        return None
    except Exception as e:
        error_message = f"Произошла ошибка: {e}"
        if update:
            update.message.reply_text(error_message)
        else:
            print(error_message)
        return None

def execute_sql_query(sql_query, update: Update):
    try:
        connection = psycopg2.connect(user=db_username,
                                      password=db_password,
                                      host=db_host,
                                      port=db_port, 
                                      database=databasee)

        cursor = connection.cursor()
        cursor.execute(sql_query)
        
        # Если это запрос на вставку, коммитим изменения в базу данных
        if sql_query.strip().upper().startswith("INSERT"):
            connection.commit()
            return None
        else:
            data = cursor.fetchall()
            if not data:
                update.message.reply_text("В таблице нет данных.")
                return None

            return data
        
    except (Exception, Error) as error:
        logging.error("Ошибка при работе с PostgreSQL: %s", error)
        update.message.reply_text("Произошла ошибка при выполнении запроса.")
        return None
    finally:
        if connection is not None:
            cursor.close()
            connection.close()
            


def echo(update: Update, context):
    update.message.reply_text(update.message.text)
    logger.info("Отправлен ответ на сообщение пользователя")


def main():
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher

    conv_handler_find_email = ConversationHandler(
        entry_points=[CommandHandler('find_email', find_email_command)],
        states={
            FIND_EMAIL: [MessageHandler(Filters.text & ~Filters.command, find_email)],
            CONFIRM_SAVE_EMAILS: [MessageHandler(Filters.text & ~Filters.command, confirm_save_email)],
        },
       fallbacks=[]
    )

    conv_handler_find_phone_number = ConversationHandler(
    entry_points=[CommandHandler('find_phone_number', find_phone_number_command)],
    states={
        FIND_PHONE_NUMBER: [MessageHandler(Filters.text & ~Filters.command, find_phone_number)],
        CONFIRM_SAVE_PHONE_NUMBERS: [MessageHandler(Filters.text & ~Filters.command, confirm_save_phone_numbers)],
    },
    fallbacks=[]
)

    conv_handler_verify_password = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verify_password_command)],
        states={
            VERIFY_PASSWORD: [MessageHandler(Filters.text & ~Filters.command, verify_password)],
        },
       fallbacks=[]
    )

    conv_handler_get_apt_list = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', get_apt_list_command)],
        states={
            GET_APT_LIST: [MessageHandler(Filters.text & ~Filters.command, get_apt_list)],
            SEARCH: [MessageHandler(Filters.text & ~Filters.command, get_package_info)],
        },
       fallbacks=[]
    )


    conv_handler_get_release = ConversationHandler(
        entry_points=[CommandHandler('get_release', get_release_command)],
        states={},
        fallbacks=[]
    )
    conv_handler_get_uname = ConversationHandler(
    entry_points=[CommandHandler('get_uname', get_uname_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_uptime = ConversationHandler(
    entry_points=[CommandHandler('get_uptime', get_uptime_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_df = ConversationHandler(
    entry_points=[CommandHandler('get_df', get_df_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_free = ConversationHandler(
    entry_points=[CommandHandler('get_free', get_free_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_mpstat = ConversationHandler(
    entry_points=[CommandHandler('get_mpstat', get_mpstat_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_w = ConversationHandler(
    entry_points=[CommandHandler('get_w', get_w_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_auths = ConversationHandler(
    entry_points=[CommandHandler('get_auths', get_auths_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_critical = ConversationHandler(
    entry_points=[CommandHandler('get_critical', get_critical_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_ps = ConversationHandler(
    entry_points=[CommandHandler('get_ps', get_ps_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_ss = ConversationHandler(
    entry_points=[CommandHandler('get_ss', get_ss_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_services = ConversationHandler(
    entry_points=[CommandHandler('get_services', get_services_command)],
    states={},
    fallbacks=[]
    )
    
    conv_handler_get_repl_logs = ConversationHandler(
    entry_points=[CommandHandler('get_repl_logs', get_repl_logs_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_emails = ConversationHandler(
    entry_points=[CommandHandler('get_emails', get_emails_command)],
    states={},
    fallbacks=[]
    )

    conv_handler_get_phone_numbers = ConversationHandler(
    entry_points=[CommandHandler('get_phone_numbers', get_phone_numbers_command)],
    states={},
    fallbacks=[]
    )

    dp.add_handler(conv_handler_get_uname) 
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", help_command))
    dp.add_handler(conv_handler_find_email)
    dp.add_handler(conv_handler_find_phone_number)
    dp.add_handler(conv_handler_verify_password)
    dp.add_handler(conv_handler_get_apt_list)
    dp.add_handler(conv_handler_get_release)
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))
    dp.add_handler(conv_handler_get_uptime)
    dp.add_handler(conv_handler_get_df)
    dp.add_handler(conv_handler_get_free)
    dp.add_handler(conv_handler_get_mpstat)
    dp.add_handler(conv_handler_get_w)
    dp.add_handler(conv_handler_get_auths)
    dp.add_handler(conv_handler_get_critical)
    dp.add_handler(conv_handler_get_ps)
    dp.add_handler(conv_handler_get_ss)
    dp.add_handler(conv_handler_get_services)
    dp.add_handler(conv_handler_get_repl_logs)
    dp.add_handler(conv_handler_get_emails)
    dp.add_handler( conv_handler_get_phone_numbers)


    updater.start_polling()
    logger.info("Бот начал опрос")
    updater.idle()


if __name__ == '__main__':
    main()
