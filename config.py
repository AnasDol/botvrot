# Настройки антиспам-фильтра
ANTISPAM_CONFIG = {
    "MAX_WARNINGS": 2,  # Максимум предупреждений перед баном
    "BAN_DURATION": 86400,  # Длительность бана в секундах (86400 = 1 день)
    "DELETE_SPAM": True,  # Автоматически удалять спам

    # Ключевые слова для фильтрации
    "BLACKLIST_WORDS": [
        "купить", "продать", "http://", "https://",
        "бесплатно", "реклама", "промокод"
    ],

    # Исключения для администраторов
    "ADMIN_IDS": [1389663038],  # ID администраторов

    # Настройки обнаружения повторений
    "MAX_REPEATED_MESSAGES": 3,  # Макс одинаковых сообщений подряд
    "REPEAT_TIME_WINDOW": 60  # Временное окно в секундах
}

# Хранилище данных (в памяти)
user_warnings = {}
message_history = {}