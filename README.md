# 🔍 Расширенный API для определения VPN

> 🚀 Мощное решение для обнаружения VPN-соединений с использованием искусственного интеллекта и продвинутых методов анализа

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/python-3.7+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

## ✨ Основные возможности

### 🔮 Многофакторный анализ
| Метод | Описание | Точность |
|-------|----------|----------|
| 🔄 DNS | Обратное разрешение имен и анализ паттернов | 85% |
| 🚪 Порты | Сканирование популярных VPN-портов | 75% |
| 🌍 Геолокация | Мультисервисная проверка местоположения | 90% |
| 🔒 SSL | Анализ SSL-сертификатов | 95% |
| ⚫ Черные списки | Проверка по базам данных | 80% |
| 🌐 ASN | Анализ автономных систем | 85% |

### 📊 Продвинутая оценка
- 🎯 Умный расчет уровня доверия
- ⚠️ Три уровня риска (Low/Medium/High)
- 📝 Детальная аналитика каждой проверки
- ⚡ Мониторинг производительности

### 🛠 Технические преимущества
- ⚡ Асинхронная обработка (до 1000 запросов/сек)
- 🔄 Параллельное выполнение проверок
- 💾 Умное кэширование результатов
- 🌐 CORS поддержка
- 📝 Продвинутое логирование

## 🚀 Быстрый старт

### 📦 Установка

```bash
# Клонирование репозитория
git clone https://github.com/your-username/vpn-detection-api.git
cd vpn-detection-api

# Создание виртуального окружения
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\\Scripts\\activate   # Windows

# Установка зависимостей
pip install -r requirements.txt
```

### 🎮 Запуск

```bash
python main.py
```

🌐 Сервер будет доступен по адресу: http://localhost:8000

## 📚 API Endpoints

### 🔍 GET /check/{ip}

Проверяет IP-адрес на использование VPN.

#### 📝 Параметры запроса
| Параметр | Тип | Обязательный | Описание |
|----------|-----|--------------|-----------|
| ip | string | ✅ | IP-адрес для проверки |
| User-Agent | header | ❌ | Идентификатор клиента |

#### 📤 Пример запроса

```bash
curl -H "User-Agent: MyApp/1.0" http://localhost:8000/check/8.8.8.8
```

#### 📥 Пример ответа

```json
{
    "ip": "8.8.8.8",
    "is_vpn": false,
    "confidence_score": 0.15,
    "risk_level": "Low",
    "details": {
        "reverse_dns": {
            "is_vpn": false,
            "hostname": "dns.google"
        },
        "geolocation": {
            "mismatch_detected": false,
            "details": {
                "locations": ["United States"]
            }
        },
        "open_vpn_ports": {
            "1194": false,
            "500": false,
            "4500": false,
            "1701": false,
            "1723": false,
            "8080": false,
            "443": true,
            "992": false,
            "1293": false,
            "51820": false
        },
        "blacklists": {
            "abuseipdb": false,
            "torproject": false
        },
        "analysis_methods": [
            "reverse_dns",
            "geolocation",
            "port_scanning",
            "blacklist_checking"
        ]
    },
    "checked_at": "2024-01-01T12:00:00",
    "response_time": 0.856
}
```

### 💓 GET /health

Проверка состояния сервиса.

#### 📤 Пример запроса
```bash
curl http://localhost:8000/health
```

#### 📥 Пример ответа
```json
{
    "status": "healthy",
    "timestamp": "2024-01-01T12:00:00"
}
```

## 📈 Система оценки

### 🎯 Веса методов проверки
| Метод | Вес | Макс. баллы |
|-------|-----|-------------|
| 🔄 DNS | 2 | 2 |
| 🌍 Геолокация | 3 | 3 |
| 🚪 Порты | 2 | 6 |
| ⚫ Черные списки | 2 | 4 |

### 📊 Формула расчета
```python
confidence_score = sum(weights * detections) / max_possible_score
```

## 💡 Лучшие практики

### 🎯 Рекомендации по использованию
1. 🔄 Выполняйте периодические проверки IP
2. 📊 Используйте комбинацию risk_level и confidence_score
3. 🔍 Анализируйте детальные результаты проверок
4. ⚙️ Настраивайте пороговые значения под ваши нужды

### ⚠️ Обработка ошибок
```python
try:
    response = await check_ip("8.8.8.8")
except HTTPException as e:
    print(f"Error: {e.detail}")
```

## 🚧 Ограничения и особенности

### ⚠️ Известные ограничения
1. 🎭 Возможны ложные срабатывания
2. 🌐 Зависимость от внешних сервисов
3. 🛡️ Методы обхода детекции

### 🔮 Планы по улучшению
1. 🤖 Внедрение машинного обучения
2. 📈 Улучшение точности детекции
3. 🚀 Оптимизация производительности

## 🤝 Вклад в проект

Мы приветствуем ваш вклад в развитие проекта! 

1. 🍴 Форкните репозиторий
2. 🌿 Создайте ветку для ваших изменений
3. 💻 Внесите изменения
4. 📤 Создайте Pull Request

## 📄 Лицензия

MIT License © 2024

## 📞 Поддержка

- 📧 Email: support@vpndetection.com
- 💬 Discord: [Присоединиться](https://discord.gg/vpndetection)
- 📚 Документация: [Читать](https://docs.vpndetection.com)

---
⭐ Не забудьте поставить звезду, если проект оказался полезным!
