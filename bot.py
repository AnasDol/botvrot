import os
import re
import time
import asyncio
import json
from datetime import datetime
from telegram import Update, ChatPermissions
from telegram.ext import (
    Application,
    ContextTypes,
    MessageHandler,
    CommandHandler,
    filters
)
from config import ANTISPAM_CONFIG, user_warnings, message_history
from dotenv import load_dotenv
from telegram.constants import ParseMode

# Загружаем токен из .env
load_dotenv()

# Константы
STATE_FILE = "bot_state.json"
TOKEN = os.getenv('TELEGRAM_TOKEN')
OWNER_ID = int(os.getenv('OWNER_ID'))
MAX_WARNINGS = ANTISPAM_CONFIG["MAX_WARNINGS"]
BLACKLIST = ANTISPAM_CONFIG["BLACKLIST_WORDS"]


# Функции для работы с состоянием
def save_state():
    state = {
        "user_warnings": user_warnings,
        "antispam_config": ANTISPAM_CONFIG,
        "banned_users": ANTISPAM_CONFIG.get('banned_users', {})
    }
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


def load_state():
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            state = json.load(f)

        # Восстанавливаем состояние
        user_warnings.update(state.get("user_warnings", {}))

        # Обновляем конфиг антиспама
        ANTISPAM_CONFIG.update(state.get("antispam_config", {}))

        # Восстанавливаем заблокированных пользователей
        if 'banned_users' not in ANTISPAM_CONFIG:
            ANTISPAM_CONFIG['banned_users'] = {}
        ANTISPAM_CONFIG['banned_users'].update(state.get("banned_users", {}))

        # Обновляем глобальные ссылки
        global BLACKLIST, MAX_WARNINGS
        BLACKLIST = ANTISPAM_CONFIG["BLACKLIST_WORDS"]
        MAX_WARNINGS = ANTISPAM_CONFIG["MAX_WARNINGS"]

    except FileNotFoundError:
        print("Файл состояния не найден, используется начальная конфигурация")
    except json.JSONDecodeError:
        print("Ошибка чтения файла состояния, используется начальная конфигурация")

# Проверка на спам
def is_spam(text: str) -> bool:
    if not text:
        return False

    # Проверка по чёрному списку
    if any(re.search(rf'\b{re.escape(word)}\b', text, re.IGNORECASE) for word in BLACKLIST):
        return True

    # Проверка на массовое упоминание (@username более 5 раз)
    if len(re.findall(r'@\w+', text)) > 5:
        return True

    # Проверка на избыточные спецсимволы
    if len(re.findall(r'[!*#$%^&]{3,}', text)) > 3:
        return True

    return False


# Проверка повторяющихся сообщений
def is_repeated(chat_id: int, user_id: int, text: str) -> bool:
    if not text:
        return False

    now = time.time()
    key = f"{chat_id}_{user_id}"

    # Инициализация истории сообщений
    if key not in message_history:
        message_history[key] = []

    # Очистка старых сообщений
    message_history[key] = [
        (msg, t) for msg, t in message_history[key]
        if now - t <= ANTISPAM_CONFIG["REPEAT_TIME_WINDOW"]
    ]

    # Проверка повторений
    repeat_count = sum(1 for msg, _ in message_history[key] if msg == text)
    message_history[key].append((text, now))

    return repeat_count >= ANTISPAM_CONFIG["MAX_REPEATED_MESSAGES"]


# Асинхронная функция для удаления сообщения с задержкой
async def delete_message_after_delay(context, chat_id, message_id, delay=30):
    await asyncio.sleep(delay)
    try:
        await context.bot.delete_message(chat_id, message_id)
    except Exception as e:
        print(f"Ошибка при удалении сообщения: {e}")


# Обработчик сообщений
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Пропускаем сообщения от администраторов
    if update.effective_user.id in ANTISPAM_CONFIG["ADMIN_IDS"]:
        return

    chat = update.effective_chat
    user = update.effective_user
    message = update.effective_message
    message_text = message.text or ""
    mention = "[" + user.name + "](tg://user?id=" + str(user.id) + ")"

    # Проверка на спам
    spam_detected = is_spam(message_text) or is_repeated(chat.id, user.id, message_text)

    if not spam_detected:
        return

    # Инициализация счетчика предупреждений
    user_key = f"{chat.id}_{user.id}"
    if user_key not in user_warnings:
        user_warnings[user_key] = 0

    # Увеличение счетчика
    user_warnings[user_key] += 1
    warnings_count = user_warnings[user_key]

    # Удаление спам-сообщения
    if ANTISPAM_CONFIG["DELETE_SPAM"]:
        try:
            await context.bot.delete_message(chat.id, message.id)
            await context.bot.sendMessage(
                chat_id=update.message.chat_id,
                parse_mode="Markdown",
                text=f"⚠️ Внимание {mention}! "
                     f"Сообщение удалено антиспам-ботом. Вынесено предупреждений: {warnings_count}. "
                     f"{'Следующее нарушение приведет к блокировке!' if warnings_count == MAX_WARNINGS else ''}"
            )

        except Exception as e:
            print(f"Ошибка удаления сообщения: {e}")

    # Действия в зависимости от количества предупреждений
    if warnings_count > MAX_WARNINGS:
        # Бан пользователя
        try:
            await context.bot.ban_chat_member(
                chat.id,
                user.id,
                until_date=time.time() + ANTISPAM_CONFIG["BAN_DURATION"]
            )
            await update.effective_chat.send_message(
                text=f"🚫 Пользователь {('@' + user.username) if user.username is not None else user.full_name} заблокирован за спам!"
            )
            # Сброс предупреждений
            del user_warnings[user_key]
            save_state()  # Сохраняем состояние после изменения

            # Добавляем в список заблокированных
            if 'banned_users' not in ANTISPAM_CONFIG:
                ANTISPAM_CONFIG['banned_users'] = {}
            ANTISPAM_CONFIG['banned_users'][user_key] = time.time() + ANTISPAM_CONFIG["BAN_DURATION"]
            save_state()  # Сохраняем состояние после изменения

        except Exception as e:
            print(f"Ошибка бана: {e}")


# Команда для добавления администратора
async def add_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌ Только владелец бота может использовать эту команду")
        return

    try:
        new_admin_id = int(context.args[0])
        if new_admin_id not in ANTISPAM_CONFIG["ADMIN_IDS"]:
            ANTISPAM_CONFIG["ADMIN_IDS"].append(new_admin_id)
            save_state()  # Сохраняем состояние после изменения
            await update.message.reply_text(f"✅ Пользователь {new_admin_id} добавлен в администраторы")
        else:
            await update.message.reply_text("ℹ️ Этот пользователь уже администратор")
    except (IndexError, ValueError):
        await update.message.reply_text("Использование: /add_admin <user_id>")


# Статистика предупреждений
async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ANTISPAM_CONFIG["ADMIN_IDS"]:
        return

    stats_text = "📊 Статистика предупреждений:\n"
    for user_key, count in user_warnings.items():
        chat_id, user_id = user_key.split('_')
        stats_text += f"👤 Пользователь {user_id} в чате {chat_id}: {count} предупреждений\n"

    await update.message.reply_text(stats_text or "ℹ️ Нет данных о предупреждениях")


# Команда для разблокировки пользователя
async def unban_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ANTISPAM_CONFIG["ADMIN_IDS"]:
        await update.message.reply_text("❌ Только администраторы могут использовать эту команду")
        return

    try:
        if not context.args:
            await update.message.reply_text("Использование: /unban <user_id>")
            return

        user_id = int(context.args[0])
        chat_id = update.effective_chat.id

        # Снимаем бан
        await context.bot.unban_chat_member(chat_id, user_id)

        # Удаляем из списка заблокированных
        user_key = f"{chat_id}_{user_id}"
        if 'banned_users' in ANTISPAM_CONFIG and user_key in ANTISPAM_CONFIG['banned_users']:
            del ANTISPAM_CONFIG['banned_users'][user_key]
            save_state()  # Сохраняем состояние после изменения

        # Сбрасываем предупреждения
        if user_key in user_warnings:
            del user_warnings[user_key]
            save_state()  # Сохраняем состояние после изменения

        await update.message.reply_text(f"✅ Пользователь {user_id} разблокирован")

    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка: {str(e)}")


async def add_to_blacklist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ANTISPAM_CONFIG["ADMIN_IDS"]:
        await update.message.reply_text("❌ Только администраторы могут использовать эту команду")
        return

    if not update.message.reply_to_message:
        await update.message.reply_text(
            "⚠️ Ответьте этой командой на сообщение, которое нужно добавить в чёрный список")
        return

    target_message = update.message.reply_to_message
    text_to_add = target_message.text.lower() or target_message.caption.lower()

    if not text_to_add:
        await update.message.reply_text("ℹ️ Целевое сообщение не содержит текста")
        return

    if text_to_add in BLACKLIST:
        await update.message.reply_text("ℹ️ Этот текст уже в чёрном списке")
        return

    BLACKLIST.append(text_to_add)
    ANTISPAM_CONFIG["BLACKLIST_WORDS"] = BLACKLIST
    save_state()  # Сохраняем состояние после изменения

    await update.message.reply_text(
        f"✅ Текст добавлен в чёрный список:\n`{text_to_add}`",
        parse_mode=ParseMode.MARKDOWN
    )


# Основная функция
def main():
    # Загружаем состояние при запуске
    load_state()

    app = Application.builder().token(TOKEN).build()

    # Обработчики
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND & filters.ChatType.GROUPS,
        handle_message
    ))
    app.add_handler(CommandHandler("add_admin", add_admin))
    app.add_handler(CommandHandler("stats", stats))
    app.add_handler(CommandHandler("unban", unban_user))
    app.add_handler(CommandHandler("blacklist", add_to_blacklist))

    print("Антиспам бот запущен...")
    app.run_polling()


if __name__ == "__main__":
    main()