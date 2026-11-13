# Lab 6 - Secure Account Management System

Вебзастосунок для лабораторної роботи №6 з дисципліни "Безпека програм та даних".

## Реалізовано
- Реєстрація користувачів
- Політика складності пароля
- Хешування паролів
- CAPTCHA
- Активація облікового запису через токен
- Захист від Brute Force
- Журнал входів
- RBAC: user/admin
- 2FA через OTP
- Google OpenID Connect
- Відновлення пароля через токен

## Технології
- Python
- Flask
- SQLite
- Flask-Login
- Flask-SQLAlchemy
- Authlib

## Запуск

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
