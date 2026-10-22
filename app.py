
import os
import re
import hmac
import secrets
import sqlite3
import time
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    session, url_for
)
from security import hash_password, check_password

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "Set SECRET_KEY in your environment before starting the app."
    )

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=300
)

OTP_VALIDITY = 30
SESSION_VALIDITY = 300


def get_db():
    conn = sqlite3.connect("banking.db", timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def generate_otp():
    return f"{secrets.randbelow(900000) + 100000}"


def generate_account_number(cursor):
    while True:
        number = str(secrets.randbelow(900000000000) + 100000000000)
        cursor.execute(
            "SELECT id FROM accounts WHERE account_number = ?",
            (number,)
        )
        if cursor.fetchone() is None:
            return number


def create_database():
    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                account_number TEXT UNIQUE NOT NULL,
                balance REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number TEXT NOT NULL,
                transaction_type TEXT NOT NULL,
                amount REAL NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (account_number)
                    REFERENCES accounts(account_number)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_settings (
                username TEXT PRIMARY KEY,
                transaction_pin_hash TEXT,
                notifications_enabled INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (username)
                    REFERENCES users(username) ON DELETE CASCADE
            )
        """)

        conn.commit()
    finally:
        conn.close()


def create_account_for_user(username):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT account_number, balance FROM accounts WHERE username = ?",
            (username,)
        )
        account = cursor.fetchone()

        if account:
            return account

        account_number = generate_account_number(cursor)
        cursor.execute("""
            INSERT INTO accounts (username, account_number, balance)
            VALUES (?, ?, 0.0)
        """, (username, account_number))
        conn.commit()
        return account_number, 0.0
    finally:
        conn.close()


def check_session():
    if "logged_in_user" not in session:
        return False

    start_time = session.get("dashboard_start_time")
    if not start_time or time.time() - start_time >= SESSION_VALIDITY:
        session.clear()
        return False

    return True


def save_transaction(cursor, account_number, transaction_type,
                     amount, description):
    cursor.execute("""
        INSERT INTO transactions
        (account_number, transaction_type, amount, description)
        VALUES (?, ?, ?, ?)
    """, (account_number, transaction_type, amount, description))


def require_login():
    if not check_session():
        return redirect("/login")
    return None


def render_otp_page(template, otp_key, time_key, error=None):
    # OTP is deliberately never passed to the HTML template.
    started = session.get(time_key, time.time())
    remaining = max(0, int(OTP_VALIDITY - (time.time() - started)))
    return render_template(
        template,
        remaining=remaining,
        error=error
    )


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    country_code = request.form.get("country_code", "+91")
    mobile = request.form.get("mobile", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not all([username, email, mobile, password]):
        return render_template(
            "register.html", error="Please fill all required fields."
        )

    if len(username) > 50 or len(email) > 254:
        return render_template(
            "register.html", error="Username or email is too long."
        )

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return render_template(
            "register.html", error="Enter a valid email address."
        )

    if password != confirm_password:
        return render_template(
            "register.html", error="Passwords do not match."
        )

    if len(password) < 8:
        return render_template(
            "register.html",
            error="Password must contain at least 8 characters."
        )

    if not mobile.isdigit() or len(mobile) != 10:
        return render_template(
            "register.html",
            error="Mobile number must contain 10 digits."
        )

    if country_code == "+91" and mobile[0] not in "6789":
        return render_template(
            "register.html", error="Invalid Indian mobile number."
        )

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        )
        if cursor.fetchone():
            return render_template(
                "register.html",
                error="Username or Email already exists."
            )
    finally:
        conn.close()

    # Do not store a plaintext password in the client-side session.
    # Hash it before temporarily storing it.
    session.clear()
    session["register_data"] = {
        "username": username,
        "email": email,
        "country_code": country_code,
        "mobile": mobile,
        "password_hash": hash_password(password)
    }

    session["register_otp"] = generate_otp()
    session["register_otp_time"] = time.time()

    # TODO: Send this OTP to the user's verified email using a
    # configured email provider. Do not print or display the OTP.
    return redirect("/registerotp")


@app.route("/registerotp", methods=["GET", "POST"])
def registerotp():
    if "register_data" not in session:
        return redirect("/register")

    if request.method == "GET":
        return render_otp_page(
            "registerotp.html", "register_otp", "register_otp_time"
        )

    otp = request.form.get("otp", "").strip()
    correct_otp = session.get("register_otp")
    otp_time = session.get("register_otp_time")

    if not correct_otp or not otp_time:
        return render_otp_page(
            "registerotp.html", "register_otp", "register_otp_time",
            "OTP expired. Please restart registration."
        )

    if time.time() - otp_time > OTP_VALIDITY:
        session.pop("register_otp", None)
        session.pop("register_otp_time", None)
        return render_otp_page(
            "registerotp.html", "register_otp", "register_otp_time",
            "OTP expired. Please restart registration."
        )

    if not hmac.compare_digest(otp, correct_otp):
        return render_otp_page(
            "registerotp.html", "register_otp", "register_otp_time",
            "Invalid OTP. Please try again."
        )

    data = session.get("register_data")
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, email, password)
            VALUES (?, ?, ?)
        """, (data["username"], data["email"], data["password_hash"]))

        account_number = generate_account_number(cursor)
        cursor.execute("""
            INSERT INTO accounts (username, account_number, balance)
            VALUES (?, ?, 0.0)
        """, (data["username"], account_number))

        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return render_otp_page(
            "registerotp.html", "register_otp", "register_otp_time",
            "Username or Email already exists."
        )
    finally:
        conn.close()

    session.clear()
    return render_template(
        "register.html", success=True, account_number=account_number
    )


@app.route("/resend_register_otp", methods=["POST"])
def resend_register_otp():
    if "register_data" not in session:
        return redirect("/register")

    session["register_otp"] = generate_otp()
    session["register_otp_time"] = time.time()

    # TODO: Send the new OTP through the configured email provider.
    return redirect("/registerotp")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return render_template(
            "login.html", error="Please enter username and password."
        )

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, email, password FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
    finally:
        conn.close()

    if not user:
        return render_template(
            "login.html", error="Invalid Username or Password."
        )

    try:
        valid = check_password(password, user[2])
    except Exception:
        valid = False

    if not valid:
        return render_template(
            "login.html", error="Invalid Username or Password."
        )

    session.clear()
    session["otp_username"] = user[0]
    session["otp_email"] = user[1]
    session["login_otp"] = generate_otp()
    session["login_otp_time"] = time.time()

    # TODO: Send OTP to user[1] through a configured email provider.
    return redirect("/loginotp")


@app.route("/loginotp", methods=["GET", "POST"])
def loginotp():
    if "otp_username" not in session:
        return redirect("/login")

    if request.method == "GET":
        return render_otp_page(
            "loginotp.html", "login_otp", "login_otp_time"
        )

    otp = request.form.get("otp", "").strip()
    correct_otp = session.get("login_otp")
    otp_time = session.get("login_otp_time")

    if not correct_otp or not otp_time:
        return render_otp_page(
            "loginotp.html", "login_otp", "login_otp_time",
            "OTP expired. Please login again."
        )

    if time.time() - otp_time > OTP_VALIDITY:
        session.pop("login_otp", None)
        session.pop("login_otp_time", None)
        return render_otp_page(
            "loginotp.html", "login_otp", "login_otp_time",
            "OTP expired. Please login again."
        )

    if not hmac.compare_digest(otp, correct_otp):
        return render_otp_page(
            "loginotp.html", "login_otp", "login_otp_time",
            "Invalid OTP. Please try again."
        )

    username = session.pop("otp_username")
    session.pop("otp_email", None)
    session.pop("login_otp", None)
    session.pop("login_otp_time", None)

    session["logged_in_user"] = username
    session["dashboard_start_time"] = time.time()
    session.permanent = True

    create_account_for_user(username)
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    account_number, balance = create_account_for_user(username)

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT transaction_type, description, amount, created_at
            FROM transactions
            WHERE account_number = ?
            ORDER BY id DESC LIMIT 5
        """, (account_number,))
        transactions = cursor.fetchall()
    finally:
        conn.close()

    message = session.pop("transaction_message", "")
    return render_template(
        "dashboard.html",
        username=username,
        account_number=account_number,
        balance=float(balance),
        transactions=transactions,
        success=message
    )


@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    account_number, balance = create_account_for_user(username)
    balance = float(balance)

    if request.method == "GET":
        return render_template(
            "deposit.html", account_number=account_number, balance=balance
        )

    try:
        amount = round(float(request.form.get("amount", "")), 2)
    except (ValueError, TypeError):
        return render_template(
            "deposit.html", account_number=account_number, balance=balance,
            error="Please enter a valid amount."
        )

    if amount <= 0:
        return render_template(
            "deposit.html", account_number=account_number, balance=balance,
            error="Deposit amount must be greater than zero."
        )

    description = request.form.get(
        "description", ""
    ).strip() or "Cash Deposit"

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        cursor.execute("""
            UPDATE accounts SET balance = balance + ?
            WHERE account_number = ?
        """, (amount, account_number))
        save_transaction(cursor, account_number, "DEPOSIT", amount, description)
        conn.commit()

        cursor.execute(
            "SELECT balance FROM accounts WHERE account_number = ?",
            (account_number,)
        )
        balance = float(cursor.fetchone()[0])
    except sqlite3.Error:
        conn.rollback()
        return render_template(
            "deposit.html", account_number=account_number, balance=balance,
            error="Deposit failed. Please try again."
        )
    finally:
        conn.close()

    return render_template(
        "deposit.html", account_number=account_number, balance=balance,
        success=f"Deposit of ₹{amount:.2f} completed successfully."
    )


@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    account_number, balance = create_account_for_user(username)
    balance = float(balance)

    def withdrawal_page(**kwargs):
        return render_template(
            "withdrawl.html",
            account_number=account_number,
            balance=balance,
            **kwargs
        )

    if request.method == "GET":
        return withdrawal_page()

    try:
        amount = round(float(request.form.get("amount", "")), 2)
    except (ValueError, TypeError):
        return withdrawal_page(error="Please enter a valid amount.")

    if amount <= 0:
        return withdrawal_page(
            error="Withdrawal amount must be greater than zero."
        )

    description = request.form.get(
        "description", ""
    ).strip() or "Cash Withdrawal"

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        cursor.execute(
            "SELECT balance FROM accounts WHERE account_number = ?",
            (account_number,)
        )
        row = cursor.fetchone()
        latest_balance = float(row[0]) if row else 0.0

        if amount > latest_balance:
            conn.rollback()
            balance = latest_balance
            return withdrawal_page(error="Insufficient balance.")

        cursor.execute("""
            UPDATE accounts SET balance = balance - ?
            WHERE account_number = ?
        """, (amount, account_number))
        save_transaction(
            cursor, account_number, "WITHDRAW", amount, description
        )
        conn.commit()

        cursor.execute(
            "SELECT balance FROM accounts WHERE account_number = ?",
            (account_number,)
        )
        balance = float(cursor.fetchone()[0])
    except sqlite3.Error:
        conn.rollback()
        return withdrawal_page(error="Withdrawal failed. Please try again.")
    finally:
        conn.close()

    return withdrawal_page(
        success=f"Withdrawal of ₹{amount:.2f} completed successfully."
    )


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT OR IGNORE INTO user_settings (username) VALUES (?)",
            (username,)
        )
        conn.commit()

        message = request.args.get("message", "")
        error = ""

        if request.method == "POST":
            action = request.form.get("action", "")

            if action == "password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("confirm_password", "")

                cursor.execute(
                    "SELECT password FROM users WHERE username = ?",
                    (username,)
                )
                row = cursor.fetchone()

                if not row or not check_password(current_password, row[0]):
                    error = "Current password is incorrect."
                elif len(new_password) < 8:
                    error = "New password must contain at least 8 characters."
                elif new_password != confirm_password:
                    error = "New passwords do not match."
                else:
                    cursor.execute(
                        "UPDATE users SET password = ? WHERE username = ?",
                        (hash_password(new_password), username)
                    )
                    conn.commit()
                    message = "Password updated successfully."

            elif action == "pin":
                new_pin = request.form.get("new_pin", "").strip()
                confirm_pin = request.form.get("confirm_pin", "").strip()
                current_pin = request.form.get("current_pin", "").strip()

                cursor.execute("""
                    SELECT transaction_pin_hash FROM user_settings
                    WHERE username = ?
                """, (username,))
                current = cursor.fetchone()[0]

                if current and not check_password(current_pin, current):
                    error = "Current transaction PIN is incorrect."
                elif not new_pin.isdigit() or len(new_pin) != 4:
                    error = "Transaction PIN must be exactly 4 digits."
                elif new_pin != confirm_pin:
                    error = "Transaction PINs do not match."
                else:
                    cursor.execute("""
                        UPDATE user_settings SET transaction_pin_hash = ?
                        WHERE username = ?
                    """, (hash_password(new_pin), username))
                    conn.commit()
                    message = "Transaction PIN saved successfully."

            elif action == "notifications":
                enabled = (
                    1 if request.form.get("notifications_enabled") == "on"
                    else 0
                )
                cursor.execute("""
                    UPDATE user_settings SET notifications_enabled = ?
                    WHERE username = ?
                """, (enabled, username))
                conn.commit()
                message = "Notification preference saved."

        cursor.execute(
            "SELECT email FROM users WHERE username = ?", (username,)
        )
        user = cursor.fetchone()

        cursor.execute("""
            SELECT transaction_pin_hash, notifications_enabled
            FROM user_settings WHERE username = ?
        """, (username,))
        preferences = cursor.fetchone()

        return render_template(
            "settings.html",
            username=username,
            email=user[0] if user else "",
            pin_set=bool(preferences and preferences[0]),
            notifications_enabled=bool(preferences and preferences[1]),
            message=message,
            error=error
        )
    finally:
        conn.close()


@app.route("/payments", methods=["GET", "POST"])
def payments():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    account_number, balance = create_account_for_user(username)
    balance = float(balance)

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT OR IGNORE INTO user_settings (username) VALUES (?)",
            (username,)
        )
        conn.commit()

        cursor.execute("""
            SELECT transaction_pin_hash FROM user_settings
            WHERE username = ?
        """, (username,))
        pin_row = cursor.fetchone()

        if not pin_row or not pin_row[0]:
            return redirect(
                "/settings?message=Set%20a%204-digit%20transaction%20PIN%20before%20making%20payments."
            )

        error = ""
        success = ""

        if request.method == "POST":
            recipient_input = request.form.get("recipient", "").strip()
            amount_text = request.form.get("amount", "").strip()
            note = request.form.get("note", "").strip()[:100]
            transaction_pin = request.form.get("transaction_pin", "").strip()

            if not check_password(transaction_pin, pin_row[0]):
                error = "Incorrect transaction PIN. Payment was not made."
            else:
                try:
                    amount = round(float(amount_text), 2)
                    if amount <= 0:
                        raise ValueError
                except (ValueError, TypeError):
                    amount = 0
                    error = "Enter a valid payment amount greater than ₹0."

                if not error:
                    lookup = recipient_input
                    if lookup.lower().endswith("@ruralbank"):
                        lookup = lookup[:-len("@ruralbank")]

                    cursor.execute("""
                        SELECT accounts.username, accounts.account_number
                        FROM accounts
                        WHERE accounts.account_number = ?
                           OR accounts.username = ? COLLATE NOCASE
                    """, (lookup, lookup))
                    recipient = cursor.fetchone()

                    if not recipient:
                        error = "Recipient not found."
                    elif recipient[0].lower() == username.lower():
                        error = "You cannot pay your own account."
                    else:
                        recipient_username, recipient_account = recipient
                        try:
                            cursor.execute("BEGIN IMMEDIATE")
                            cursor.execute(
                                "SELECT balance FROM accounts WHERE account_number = ?",
                                (account_number,)
                            )
                            latest = cursor.fetchone()
                            latest_balance = float(latest[0]) if latest else 0.0

                            if amount > latest_balance:
                                conn.rollback()
                                error = "Insufficient balance. Payment was not made."
                            else:
                                cursor.execute("""
                                    UPDATE accounts SET balance = balance - ?
                                    WHERE account_number = ?
                                """, (amount, account_number))
                                cursor.execute("""
                                    UPDATE accounts SET balance = balance + ?
                                    WHERE account_number = ?
                                """, (amount, recipient_account))

                                sender_desc = f"Payment to {recipient_username}"
                                recipient_desc = f"Payment from {username}"
                                if note:
                                    sender_desc += f" - {note}"
                                    recipient_desc += f" - {note}"

                                save_transaction(
                                    cursor, account_number, "TRANSFER_SENT",
                                    amount, sender_desc
                                )
                                save_transaction(
                                    cursor, recipient_account,
                                    "TRANSFER_RECEIVED", amount, recipient_desc
                                )
                                conn.commit()
                                success = (
                                    f"Payment of ₹{amount:.2f} sent successfully "
                                    f"to {recipient_username}."
                                )
                        except sqlite3.Error:
                            conn.rollback()
                            error = "Payment failed. No money was transferred."

        cursor.execute("""
            SELECT username, account_number FROM accounts
            WHERE username != ? ORDER BY username COLLATE NOCASE
        """, (username,))
        beneficiaries = cursor.fetchall()

        cursor.execute(
            "SELECT balance FROM accounts WHERE account_number = ?",
            (account_number,)
        )
        row = cursor.fetchone()
        if row:
            balance = float(row[0])

        return render_template(
            "payments.html",
            username=username,
            account_number=account_number,
            balance=balance,
            beneficiaries=beneficiaries,
            error=error,
            success=success
        )
    finally:
        conn.close()


@app.route("/transactions")
def transactions():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT account_number FROM accounts WHERE username = ?",
            (username,)
        )
        account = cursor.fetchone()

        if not account:
            return redirect("/dashboard")

        cursor.execute("""
            SELECT id, transaction_type, description, amount, created_at
            FROM transactions
            WHERE account_number = ?
            ORDER BY id DESC LIMIT 100
        """, (account[0],))
        rows = cursor.fetchall()

        return render_template(
            "transactions.html",
            username=username,
            transactions=rows
        )
    except sqlite3.Error:
        app.logger.exception("Unable to load transaction history")
        return "Unable to load transactions. Please try again.", 500
    finally:
        conn.close()


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    create_database()
    app.run(debug=False)
