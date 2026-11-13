from flask import (
    Flask,
    render_template_string,
    request,
    redirect,
    url_for,
    flash,
    session
)

from flask_sqlalchemy import SQLAlchemy

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from authlib.integrations.flask_client import OAuth

from datetime import datetime, timedelta

import os
import re
import random
import secrets


# =========================================================
# APP
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = "lab6-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# =========================================================
# GOOGLE OPENID CONNECT
# =========================================================

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url=(
        "https://accounts.google.com/.well-known/"
        "openid-configuration"
    ),
    client_kwargs={
        "scope": "openid email profile"
    }
)


# =========================================================
# DATABASE
# =========================================================

class User(UserMixin, db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(300),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="user"
    )

    # Активація
    activated = db.Column(
        db.Boolean,
        default=False
    )

    activation_token = db.Column(
        db.String(200),
        nullable=True
    )

    activation_expires = db.Column(
        db.DateTime,
        nullable=True
    )

    # Brute Force
    failed_attempts = db.Column(
        db.Integer,
        default=0
    )

    blocked_until = db.Column(
        db.DateTime,
        nullable=True
    )

    manually_blocked = db.Column(
        db.Boolean,
        default=False
    )

    # 2FA
    two_factor_enabled = db.Column(
        db.Boolean,
        default=False
    )

    otp_code = db.Column(
        db.String(10),
        nullable=True
    )

    otp_expires = db.Column(
        db.DateTime,
        nullable=True
    )

    # Password reset
    reset_token = db.Column(
        db.String(200),
        nullable=True
    )

    reset_expires = db.Column(
        db.DateTime,
        nullable=True
    )


class LoginLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    email = db.Column(
        db.String(120),
        nullable=False
    )

    ip_address = db.Column(
        db.String(100),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    result = db.Column(
        db.String(150),
        nullable=False
    )


@login_manager.user_loader
def load_user(user_id):

    return db.session.get(
        User,
        int(user_id)
    )


# =========================================================
# HELPERS
# =========================================================

def validate_password(password):

    if len(password) < 8:
        return "Пароль повинен містити мінімум 8 символів."

    if not re.search(r"[A-Z]", password):
        return "Пароль повинен містити велику літеру."

    if not re.search(r"[a-z]", password):
        return "Пароль повинен містити малу літеру."

    if not re.search(r"\d", password):
        return "Пароль повинен містити цифру."

    if not re.search(r"[^A-Za-z0-9]", password):
        return "Пароль повинен містити спеціальний символ."

    return None


def add_login_log(email, result):

    log = LoginLog(
        email=email,
        ip_address=request.remote_addr,
        result=result
    )

    db.session.add(log)
    db.session.commit()


# =========================================================
# HTML TEMPLATE
# =========================================================

PAGE = """
<!DOCTYPE html>
<html lang="uk">

<head>

<meta charset="UTF-8">

<title>Лабораторна робота №6</title>

<style>

body {
    font-family: Arial, sans-serif;
    max-width: 1000px;
    margin: 40px auto;
    padding: 20px;
}

nav {
    margin-bottom: 20px;
}

nav a {
    margin-right: 15px;
}

input {
    width: 100%;
    padding: 10px;
    margin: 6px 0 12px 0;
    box-sizing: border-box;
}

button {
    padding: 10px 18px;
    cursor: pointer;
}

.message {
    padding: 12px;
    background: #eeeeee;
    margin-bottom: 15px;
}

.box {
    border: 1px solid #cccccc;
    padding: 25px;
    border-radius: 8px;
}

.success {
    color: green;
    font-weight: bold;
}

.danger {
    color: red;
    font-weight: bold;
}

.info {
    background: #f4f4f4;
    padding: 15px;
    margin: 15px 0;
}

.otp {
    font-size: 28px;
    font-weight: bold;
}

table {
    border-collapse: collapse;
    width: 100%;
}

th,
td {
    border: 1px solid #cccccc;
    padding: 8px;
}

th {
    background: #eeeeee;
}

.activation-link {
    word-break: break-all;
    background: #f4f4f4;
    padding: 12px;
}

.google-button {
    display: inline-block;
    padding: 12px 18px;
    border: 1px solid #aaaaaa;
    text-decoration: none;
    margin-top: 10px;
}

</style>

</head>

<body>

<nav>

<a href="/">
Головна
</a>

{% if current_user.is_authenticated %}

<a href="/profile">
Профіль
</a>

{% if current_user.role == "admin" %}

<a href="/admin">
Адмін-панель
</a>

{% endif %}

<a href="/logout">
Вийти
</a>

{% else %}

<a href="/register">
Реєстрація
</a>

<a href="/login">
Вхід
</a>

{% endif %}

</nav>

<hr>

{% with messages = get_flashed_messages() %}

{% for message in messages %}

<div class="message">
{{ message }}
</div>

{% endfor %}

{% endwith %}

<div class="box">

{{ content|safe }}

</div>

</body>
</html>
"""


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    content = """
    <h1>Лабораторна робота №6</h1>

    <p>
    Безпечна система управління обліковими записами.
    </p>

    <p>
    Реалізовано:
    реєстрацію,
    CAPTCHA,
    активацію акаунта,
    Brute Force protection,
    журнал входів,
    2FA,
    Google OpenID Connect
    та відновлення пароля.
    </p>
    """

    return render_template_string(
        PAGE,
        content=content
    )


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        captcha_answer = request.form.get(
            "captcha",
            ""
        ).strip()

        correct_answer = session.get(
            "captcha_answer"
        )

        if captcha_answer != str(correct_answer):

            flash("Неправильна CAPTCHA.")

            return redirect(
                url_for("register")
            )

        error = validate_password(password)

        if error:

            flash(error)

            return redirect(
                url_for("register")
            )

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:

            flash(
                "Користувач з таким email уже існує."
            )

            return redirect(
                url_for("register")
            )

        token = secrets.token_urlsafe(32)

        user = User(

            email=email,

            password_hash=generate_password_hash(
                password,
                method="scrypt"
            ),

            role="user",

            activated=False,

            activation_token=token,

            activation_expires=(
                datetime.utcnow()
                + timedelta(minutes=15)
            ),

            failed_attempts=0,

            manually_blocked=False,

            two_factor_enabled=False
        )

        db.session.add(user)
        db.session.commit()

        return redirect(
            url_for(
                "activation_sent",
                user_id=user.id
            )
        )

    a = random.randint(1, 9)
    b = random.randint(1, 9)

    session["captcha_answer"] = a + b

    register_form = render_template_string(
        """
        <h2>Реєстрація</h2>

        <form method="POST">

        <label>Email:</label>

        <input
            type="email"
            name="email"
            required
        >

        <label>Пароль:</label>

        <input
            type="password"
            name="password"
            required
        >

        <p>
        Пароль повинен містити:
        мінімум 8 символів,
        велику і малу літери,
        цифру та спеціальний символ.
        </p>

        <label>
        CAPTCHA:
        {{ a }} + {{ b }} = ?
        </label>

        <input
            type="number"
            name="captcha"
            required
        >

        <button type="submit">
        Зареєструватися
        </button>

        </form>
        """,
        a=a,
        b=b
    )

    return render_template_string(
        PAGE,
        content=register_form
    )


# =========================================================
# ACTIVATION
# =========================================================

@app.route("/activation-sent/<int:user_id>")
def activation_sent(user_id):

    user = db.session.get(
        User,
        user_id
    )

    if not user:
        return "Користувача не знайдено.", 404

    activation_url = url_for(
        "activate",
        token=user.activation_token,
        _external=True
    )

    content = f"""
    <h2>Активація облікового запису</h2>

    <p>Реєстрація успішна.</p>

    <h3>Тестовий email</h3>

    <p>
    Кому:
    <b>{user.email}</b>
    </p>

    <p>
    Для активації акаунта перейдіть за посиланням:
    </p>

    <div class="activation-link">

    <a href="{activation_url}">
    {activation_url}
    </a>

    </div>

    <p>
    Посилання дійсне 15 хвилин.
    </p>
    """

    return render_template_string(
        PAGE,
        content=content
    )


@app.route("/activate/<token>")
def activate(token):

    user = User.query.filter_by(
        activation_token=token
    ).first()

    if not user:

        flash(
            "Токен неправильний або вже використаний."
        )

        return redirect(
            url_for("login")
        )

    if user.activation_expires < datetime.utcnow():

        flash(
            "Термін дії токена завершився."
        )

        return redirect(
            url_for("login")
        )

    user.activated = True
    user.activation_token = None
    user.activation_expires = None

    db.session.commit()

    flash(
        "Обліковий запис успішно активовано."
    )

    return redirect(
        url_for("login")
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(
            email=email
        ).first()

        if not user:

            add_login_log(
                email,
                "Користувача не знайдено"
            )

            flash(
                "Неправильний email або пароль."
            )

            return redirect(
                url_for("login")
            )

        if user.manually_blocked:

            add_login_log(
                email,
                "Заблоковано адміністратором"
            )

            flash(
                "Обліковий запис заблокований адміністратором."
            )

            return redirect(
                url_for("login")
            )

        if user.blocked_until:

            if datetime.utcnow() < user.blocked_until:

                add_login_log(
                    email,
                    "Тимчасово заблоковано"
                )

                flash(
                    "Акаунт тимчасово заблокований."
                )

                return redirect(
                    url_for("login")
                )

            else:

                user.blocked_until = None
                user.failed_attempts = 0

                db.session.commit()

        if not check_password_hash(
            user.password_hash,
            password
        ):

            user.failed_attempts += 1

            attempts_left = (
                3 - user.failed_attempts
            )

            if user.failed_attempts >= 3:

                user.blocked_until = (
                    datetime.utcnow()
                    + timedelta(minutes=1)
                )

                user.failed_attempts = 0

                db.session.commit()

                add_login_log(
                    email,
                    "Brute Force - акаунт заблоковано"
                )

                flash(
                    "3 неправильні спроби. "
                    "Акаунт заблокований на 1 хвилину."
                )

                return redirect(
                    url_for("login")
                )

            db.session.commit()

            add_login_log(
                email,
                "Невдалий пароль"
            )

            flash(
                f"Неправильний пароль. "
                f"Залишилось спроб: {attempts_left}"
            )

            return redirect(
                url_for("login")
            )

        if not user.activated:

            add_login_log(
                email,
                "Акаунт не активовано"
            )

            flash(
                "Обліковий запис ще не активовано."
            )

            return redirect(
                url_for("login")
            )

        user.failed_attempts = 0
        user.blocked_until = None

        db.session.commit()

        if user.two_factor_enabled:

            otp = str(
                random.randint(
                    100000,
                    999999
                )
            )

            user.otp_code = otp

            user.otp_expires = (
                datetime.utcnow()
                + timedelta(minutes=5)
            )

            db.session.commit()

            session[
                "pending_2fa_user_id"
            ] = user.id

            add_login_log(
                email,
                "Очікується 2FA"
            )

            return redirect(
                url_for("two_factor")
            )

        login_user(user)

        add_login_log(
            email,
            "Успішний вхід"
        )

        flash("Вхід успішний.")

        return redirect(
            url_for("profile")
        )

    content = """
    <h2>Вхід</h2>

    <form method="POST">

    <label>Email:</label>

    <input
        type="email"
        name="email"
        required
    >

    <label>Пароль:</label>

    <input
        type="password"
        name="password"
        required
    >

    <button type="submit">
    Увійти
    </button>

    </form>

    <p>
    <a href="/forgot-password">
    Забули пароль?
    </a>
    </p>

    <hr>

    <p>або</p>

    <a
        class="google-button"
        href="/login/google"
    >
    Увійти через Google
    </a>
    """

    return render_template_string(
        PAGE,
        content=content
    )


# =========================================================
# PASSWORD RESET
# =========================================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():

    if request.method == "POST":

        email = request.form[
            "email"
        ].strip().lower()

        user = User.query.filter_by(
            email=email
        ).first()

        if not user:

            flash(
                "Користувача з таким email не знайдено."
            )

            return redirect(
                url_for("forgot_password")
            )

        token = secrets.token_urlsafe(32)

        user.reset_token = token

        user.reset_expires = (
            datetime.utcnow()
            + timedelta(minutes=10)
        )

        db.session.commit()

        return redirect(
            url_for(
                "reset_sent",
                user_id=user.id
            )
        )

    content = """
    <h2>Відновлення пароля</h2>

    <p>
    Введіть email облікового запису.
    </p>

    <form method="POST">

    <label>Email:</label>

    <input
        type="email"
        name="email"
        required
    >

    <button type="submit">
    Надіслати посилання
    </button>

    </form>
    """

    return render_template_string(
        PAGE,
        content=content
    )


@app.route("/reset-sent/<int:user_id>")
def reset_sent(user_id):

    user = db.session.get(
        User,
        user_id
    )

    if not user:

        return "Користувача не знайдено.", 404

    if not user.reset_token:

        flash(
            "Немає активного запиту на відновлення пароля."
        )

        return redirect(
            url_for("login")
        )

    reset_url = url_for(
        "reset_password",
        token=user.reset_token,
        _external=True
    )

    content = f"""
    <h2>Відновлення пароля</h2>

    <h3>Тестовий email</h3>

    <p>
    Кому:
    <b>{user.email}</b>
    </p>

    <p>
    Для встановлення нового пароля
    перейдіть за посиланням:
    </p>

    <div class="activation-link">

    <a href="{reset_url}">
    {reset_url}
    </a>

    </div>

    <p>
    Посилання дійсне 10 хвилин.
    </p>
    """

    return render_template_string(
        PAGE,
        content=content
    )


@app.route(
    "/reset-password/<token>",
    methods=["GET", "POST"]
)
def reset_password(token):

    user = User.query.filter_by(
        reset_token=token
    ).first()

    if not user:

        flash(
            "Токен відновлення неправильний "
            "або вже використаний."
        )

        return redirect(
            url_for("forgot_password")
        )

    if (
        not user.reset_expires
        or datetime.utcnow()
        > user.reset_expires
    ):

        user.reset_token = None
        user.reset_expires = None

        db.session.commit()

        flash(
            "Термін дії посилання "
            "для відновлення пароля завершився."
        )

        return redirect(
            url_for("forgot_password")
        )

    if request.method == "POST":

        password = request.form[
            "password"
        ]

        error = validate_password(
            password
        )

        if error:

            flash(error)

            return redirect(
                url_for(
                    "reset_password",
                    token=token
                )
            )

        user.password_hash = (
            generate_password_hash(
                password,
                method="scrypt"
            )
        )

        # Одноразовий токен
        user.reset_token = None
        user.reset_expires = None

        user.failed_attempts = 0
        user.blocked_until = None

        db.session.commit()

        flash(
            "Пароль успішно змінено. "
            "Тепер можна увійти."
        )

        return redirect(
            url_for("login")
        )

    content = """
    <h2>Новий пароль</h2>

    <form method="POST">

    <label>
    Введіть новий пароль:
    </label>

    <input
        type="password"
        name="password"
        required
    >

    <p>
    Мінімум 8 символів,
    велика і мала літера,
    цифра та спеціальний символ.
    </p>

    <button type="submit">
    Змінити пароль
    </button>

    </form>
    """

    return render_template_string(
        PAGE,
        content=content
    )


# =========================================================
# 2FA
# =========================================================

@app.route("/2fa", methods=["GET", "POST"])
def two_factor():

    user_id = session.get(
        "pending_2fa_user_id"
    )

    if not user_id:

        flash(
            "Немає активного запиту 2FA."
        )

        return redirect(
            url_for("login")
        )

    user = db.session.get(
        User,
        user_id
    )

    if not user:

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        entered_code = request.form.get(
            "otp",
            ""
        ).strip()

        if not user.otp_expires:

            flash(
                "OTP-код недійсний."
            )

            return redirect(
                url_for("login")
            )

        if datetime.utcnow() > user.otp_expires:

            user.otp_code = None
            user.otp_expires = None

            db.session.commit()

            session.pop(
                "pending_2fa_user_id",
                None
            )

            add_login_log(
                user.email,
                "OTP прострочений"
            )

            flash(
                "Термін дії OTP-коду завершився."
            )

            return redirect(
                url_for("login")
            )

        if entered_code != user.otp_code:

            add_login_log(
                user.email,
                "Неправильний OTP"
            )

            flash(
                "Неправильний OTP-код."
            )

            return redirect(
                url_for("two_factor")
            )

        user.otp_code = None
        user.otp_expires = None

        db.session.commit()

        session.pop(
            "pending_2fa_user_id",
            None
        )

        login_user(user)

        add_login_log(
            user.email,
            "Успішний вхід з 2FA"
        )

        flash(
            "2FA успішно пройдено."
        )

        return redirect(
            url_for("profile")
        )

    content = f"""
    <h2>
    Двофакторна автентифікація
    </h2>

    <div class="info">

    <h3>Тестовий email</h3>

    <p>
    Кому:
    <b>{user.email}</b>
    </p>

    <p>
    Ваш OTP-код:
    </p>

    <div class="otp">
    {user.otp_code}
    </div>

    <p>
    Код дійсний 5 хвилин.
    </p>

    </div>

    <form method="POST">

    <input
        type="text"
        name="otp"
        maxlength="6"
        required
    >

    <button type="submit">
    Підтвердити
    </button>

    </form>
    """

    return render_template_string(
        PAGE,
        content=content
    )


# =========================================================
# PROFILE
# =========================================================

@app.route("/profile")
@login_required
def profile():

    activation_status = (
        '<span class="success">Активований</span>'
        if current_user.activated
        else
        '<span class="danger">Не активований</span>'
    )

    if current_user.two_factor_enabled:

        two_factor_status = (
            '<span class="success">'
            'Увімкнено'
            '</span>'
        )

        two_factor_button = """
        <a href="/2fa/disable">
        Вимкнути 2FA
        </a>
        """

    else:

        two_factor_status = (
            '<span class="danger">'
            'Вимкнено'
            '</span>'
        )

        two_factor_button = """
        <a href="/2fa/enable">
        Увімкнути 2FA
        </a>
        """

    content = f"""
    <h2>Профіль</h2>

    <p>
    <b>Email:</b>
    {current_user.email}
    </p>

    <p>
    <b>Роль:</b>
    {current_user.role}
    </p>

    <p>
    <b>Статус акаунта:</b>
    {activation_status}
    </p>

    <hr>

    <h3>
    Двофакторна автентифікація
    </h3>

    <p>
    <b>2FA:</b>
    {two_factor_status}
    </p>

    <p>
    {two_factor_button}
    </p>
    """

    return render_template_string(
        PAGE,
        content=content
    )


@app.route("/2fa/enable")
@login_required
def enable_2fa():

    current_user.two_factor_enabled = True

    db.session.commit()

    flash(
        "Двофакторну автентифікацію увімкнено."
    )

    return redirect(
        url_for("profile")
    )


@app.route("/2fa/disable")
@login_required
def disable_2fa():

    current_user.two_factor_enabled = False
    current_user.otp_code = None
    current_user.otp_expires = None

    db.session.commit()

    flash(
        "Двофакторну автентифікацію вимкнено."
    )

    return redirect(
        url_for("profile")
    )


# =========================================================
# GOOGLE OPENID CONNECT
# =========================================================

@app.route("/login/google")
def google_login():

    redirect_uri = url_for(
        "google_callback",
        _external=True
    )

    return google.authorize_redirect(
        redirect_uri
    )


@app.route("/auth/google/callback")
def google_callback():

    try:

        token = google.authorize_access_token()

        userinfo = token.get("userinfo")

        if not userinfo:

            flash(
                "Не вдалося отримати дані користувача Google."
            )

            return redirect(
                url_for("login")
            )

        email = userinfo.get(
            "email",
            ""
        ).lower()

        if not email:

            flash(
                "Google не повернув email."
            )

            return redirect(
                url_for("login")
            )

        user = User.query.filter_by(
            email=email
        ).first()

        if not user:

            random_password = (
                secrets.token_urlsafe(32)
            )

            user = User(

                email=email,

                password_hash=generate_password_hash(
                    random_password,
                    method="scrypt"
                ),

                role="user",

                activated=True,

                failed_attempts=0,

                manually_blocked=False,

                two_factor_enabled=False
            )

            db.session.add(user)
            db.session.commit()

        if user.manually_blocked:

            add_login_log(
                email,
                "Google login - користувач заблокований"
            )

            flash(
                "Обліковий запис заблокований адміністратором."
            )

            return redirect(
                url_for("login")
            )

        login_user(user)

        add_login_log(
            email,
            "Успішний вхід через Google"
        )

        flash(
            "Вхід через Google успішний."
        )

        return redirect(
            url_for("profile")
        )

    except Exception as e:

        print(
            "Google OAuth error:",
            e
        )

        flash(
            "Помилка входу через Google."
        )

        return redirect(
            url_for("login")
        )


# =========================================================
# ADMIN
# =========================================================

@app.route("/admin")
@login_required
def admin():

    if current_user.role != "admin":

        return "Доступ заборонено.", 403

    users = User.query.all()

    logs = (
        LoginLog.query
        .order_by(
            LoginLog.id.desc()
        )
        .limit(50)
        .all()
    )

    user_rows = ""

    for user in users:

        if user.manually_blocked:

            status = "Заблокований"

            button = f"""
            <a href="/admin/unblock/{user.id}">
            Розблокувати
            </a>
            """

        else:

            status = "Активний"

            button = f"""
            <a href="/admin/block/{user.id}">
            Заблокувати
            </a>
            """

        user_rows += f"""
        <tr>
            <td>{user.id}</td>
            <td>{user.email}</td>
            <td>{user.role}</td>
            <td>{status}</td>
            <td>{button}</td>
        </tr>
        """

    log_rows = ""

    for log in logs:

        log_rows += f"""
        <tr>
            <td>{log.email}</td>
            <td>{log.ip_address}</td>
            <td>{log.timestamp}</td>
            <td>{log.result}</td>
        </tr>
        """

    content = f"""
    <h2>Адмін-панель</h2>

    <h3>Користувачі</h3>

    <table>

    <tr>
        <th>ID</th>
        <th>Email</th>
        <th>Роль</th>
        <th>Статус</th>
        <th>Дія</th>
    </tr>

    {user_rows}

    </table>

    <h3>Журнал входів</h3>

    <table>

    <tr>
        <th>Email</th>
        <th>IP</th>
        <th>Час</th>
        <th>Результат</th>
    </tr>

    {log_rows}

    </table>
    """

    return render_template_string(
        PAGE,
        content=content
    )


@app.route("/admin/block/<int:user_id>")
@login_required
def block_user(user_id):

    if current_user.role != "admin":

        return "Доступ заборонено.", 403

    user = db.session.get(
        User,
        user_id
    )

    if user:

        user.manually_blocked = True
        db.session.commit()

        flash(
            f"Користувача {user.email} заблоковано."
        )

    return redirect(
        url_for("admin")
    )


@app.route("/admin/unblock/<int:user_id>")
@login_required
def unblock_user(user_id):

    if current_user.role != "admin":

        return "Доступ заборонено.", 403

    user = db.session.get(
        User,
        user_id
    )

    if user:

        user.manually_blocked = False
        user.failed_attempts = 0
        user.blocked_until = None

        db.session.commit()

        flash(
            f"Користувача {user.email} розблоковано."
        )

    return redirect(
        url_for("admin")
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash(
        "Ви вийшли із системи."
    )

    return redirect(
        url_for("index")
    )


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    with app.app_context():

        db.create_all()

        admin_user = User.query.filter_by(
            email="admin@lab.local"
        ).first()

        if not admin_user:

            admin_user = User(

                email="admin@lab.local",

                password_hash=generate_password_hash(
                    "Admin123!",
                    method="scrypt"
                ),

                role="admin",

                activated=True,

                failed_attempts=0,

                manually_blocked=False,

                two_factor_enabled=False
            )

            db.session.add(admin_user)
            db.session.commit()

            print(
                "Створено адміністратора:"
            )

            print(
                "Email: admin@lab.local"
            )

            print(
                "Password: Admin123!"
            )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
