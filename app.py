from flask import Flask, render_template, request, redirect, session
import sqlite3
import random
import time
from security import hash_password, check_password

app = Flask(__name__)
app.secret_key = "rural-banking-secret-key"

OTP_VALIDITY = 30
SESSION_VALIDITY = 300


def get_db():
    conn = sqlite3.connect("banking.db")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def generate_account_number(cursor):
    while True:
        number = str(random.randint(100000000000, 999999999999))
        cursor.execute(
            "SELECT id FROM accounts WHERE account_number = ?",
            (number,)
        )
        if cursor.fetchone() is None:
            return number


def create_database():
    conn = get_db()
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
    conn.close()


def create_account_for_user(username):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT account_number, balance FROM accounts WHERE username = ?",
        (username,)
    )
    account = cursor.fetchone()

    if account:
        conn.close()
        return account

    account_number = generate_account_number(cursor)

    cursor.execute("""
        INSERT INTO accounts (username, account_number, balance)
        VALUES (?, ?, ?)
    """, (username, account_number, 0.0))

    conn.commit()
    conn.close()

    return account_number, 0.0


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


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        country_code = request.form.get("country_code", "+91")
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([username, email, mobile, password]):
            return render_template(
                "register.html",
                error="Please fill all required fields."
            )

        if password != confirm_password:
            return render_template(
                "register.html",
                error="Passwords do not match."
            )

        if not mobile.isdigit() or len(mobile) != 10:
            return render_template(
                "register.html",
                error="Mobile number must contain 10 digits."
            )

        if country_code == "+91" and mobile[0] not in "6789":
            return render_template(
                "register.html",
                error="Invalid Indian mobile number."
            )

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        )
        exists = cursor.fetchone()
        conn.close()

        if exists:
            return render_template(
                "register.html",
                error="Username or Email already exists."
            )

        session["register_data"] = {
            "username": username,
            "email": email,
            "country_code": country_code,
            "mobile": mobile,
            "password": password
        }

        session["register_otp"] = str(random.randint(100000, 999999))
        session["register_otp_time"] = time.time()

        print("Registration OTP:", session["register_otp"])
        return redirect("/registerotp")

    return render_template("register.html")


@app.route("/registerotp", methods=["GET", "POST"])
def registerotp():
    if "register_data" not in session:
        return redirect("/register")

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        correct_otp = session.get("register_otp")
        otp_time = session.get("register_otp_time")

        if not correct_otp or not otp_time:
            return render_template(
                "registerotp.html",
                error="OTP expired. Please resend OTP."
            )

        if time.time() - otp_time > OTP_VALIDITY:
            session.pop("register_otp", None)
            session.pop("register_otp_time", None)
            return render_template(
                "registerotp.html",
                error="OTP expired. Please resend OTP."
            )

        if otp != correct_otp:
            return render_template(
                "registerotp.html",
                error="Invalid OTP. Please try again."
            )

        data = session.get("register_data")
        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (username, email, password)
                VALUES (?, ?, ?)
            """, (
                data["username"],
                data["email"],
                hash_password(data["password"])
            ))

            account_number = generate_account_number(cursor)

            cursor.execute("""
                INSERT INTO accounts (username, account_number, balance)
                VALUES (?, ?, ?)
            """, (data["username"], account_number, 0.0))

            conn.commit()

            session.pop("register_data", None)
            session.pop("register_otp", None)
            session.pop("register_otp_time", None)

            return render_template(
                "register.html",
                success=True,
                account_number=account_number
            )

        except sqlite3.IntegrityError:
            conn.rollback()
            return render_template(
                "registerotp.html",
                error="Username or Email already exists."
            )

        finally:
            conn.close()

    elapsed = time.time() - session.get("register_otp_time", time.time())
    remaining = max(0, int(OTP_VALIDITY - elapsed))

    return render_template(
        "registerotp.html",
        demo_otp=session.get("register_otp"),
        remaining=remaining
    )


@app.route("/resend_register_otp")
def resend_register_otp():
    if "register_data" not in session:
        return redirect("/register")

    session["register_otp"] = str(random.randint(100000, 999999))
    session["register_otp_time"] = time.time()

    print("New Registration OTP:", session["register_otp"])
    return redirect("/registerotp")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template(
                "login.html",
                error="Please enter username and password."
            )

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            try:
                valid = check_password(password, user[3])
            except Exception:
                valid = False

            if valid:
                session["otp_username"] = username
                session["login_otp"] = str(
                    random.randint(100000, 999999)
                )
                session["login_otp_time"] = time.time()

                print("Login OTP:", session["login_otp"])
                return redirect("/loginotp")

        return render_template(
            "login.html",
            error="Invalid Username or Password."
        )

    return render_template("login.html")


@app.route("/loginotp", methods=["GET", "POST"])
def loginotp():
    if "otp_username" not in session:
        return redirect("/login")

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        correct_otp = session.get("login_otp")
        otp_time = session.get("login_otp_time")

        if not correct_otp or not otp_time:
            return render_template(
                "loginotp.html",
                error="OTP expired. Please login again."
            )

        if time.time() - otp_time > OTP_VALIDITY:
            session.pop("login_otp", None)
            session.pop("login_otp_time", None)
            return render_template(
                "loginotp.html",
                error="OTP expired. Please login again."
            )

        if otp != correct_otp:
            return render_template(
                "loginotp.html",
                error="Invalid OTP. Please try again."
            )

        username = session.pop("otp_username")
        session.pop("login_otp", None)
        session.pop("login_otp_time", None)

        session["logged_in_user"] = username
        session["dashboard_start_time"] = time.time()

        create_account_for_user(username)
        return redirect("/dashboard")

    elapsed = time.time() - session.get("login_otp_time", time.time())
    remaining = max(0, int(OTP_VALIDITY - elapsed))

    return render_template(
        "loginotp.html",
        demo_otp=session.get("login_otp"),
        remaining=remaining
    )


@app.route("/dashboard")
def dashboard():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    create_account_for_user(username)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT account_number, balance
        FROM accounts WHERE username = ?
    """, (username,))
    account = cursor.fetchone()

    account_number = account[0]
    balance = float(account[1])

    cursor.execute("""
        SELECT transaction_type, description, amount, created_at
        FROM transactions
        WHERE account_number = ?
        ORDER BY id DESC
        LIMIT 5
    """, (account_number,))
    transactions = cursor.fetchall()

    conn.close()

    message = session.pop("transaction_message", "")
    return render_template(
        "dashboard.html",
        username=username,
        account_number=account_number,
        balance=balance,
        transactions=transactions,
        success=message
    )


@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    create_account_for_user(username)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT account_number, balance
        FROM accounts WHERE username = ?
    """, (username,))
    account = cursor.fetchone()

    if not account:
        conn.close()
        return redirect("/dashboard")

    account_number, balance = account[0], float(account[1])

    if request.method == "POST":
        try:
            amount = round(float(request.form.get("amount", "")), 2)
        except (ValueError, TypeError):
            conn.close()
            return render_template(
                "deposit.html",
                account_number=account_number,
                balance=balance,
                error="Please enter a valid amount."
            )

        description = request.form.get(
            "description", ""
        ).strip() or "Cash Deposit"

        if amount <= 0:
            conn.close()
            return render_template(
                "deposit.html",
                account_number=account_number,
                balance=balance,
                error="Deposit amount must be greater than zero."
            )

        try:
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute("""
                UPDATE accounts
                SET balance = balance + ?
                WHERE account_number = ?
            """, (amount, account_number))

            save_transaction(
                cursor, account_number, "DEPOSIT", amount, description
            )
            conn.commit()

            cursor.execute(
                "SELECT balance FROM accounts WHERE account_number = ?",
                (account_number,)
            )
            balance = float(cursor.fetchone()[0])
            conn.close()

            return render_template(
                "deposit.html",
                account_number=account_number,
                balance=balance,
                success=f"Deposit of ₹{amount:.2f} completed successfully."
            )

        except sqlite3.Error:
            conn.rollback()
            conn.close()
            return render_template(
                "deposit.html",
                account_number=account_number,
                balance=balance,
                error="Deposit failed. Please try again."
            )

    conn.close()
    return render_template(
        "deposit.html",
        account_number=account_number,
        balance=balance
    )


@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    create_account_for_user(username)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT account_number, balance
        FROM accounts WHERE username = ?
    """, (username,))
    account = cursor.fetchone()

    if not account:
        conn.close()
        return redirect("/dashboard")

    account_number, balance = account[0], float(account[1])

    if request.method == "POST":
        try:
            amount = round(float(request.form.get("amount", "")), 2)
        except (ValueError, TypeError):
            conn.close()
            return render_template(
                "withdrawl.html",
                account_number=account_number,
                balance=balance,
                error="Please enter a valid amount."
            )

        description = request.form.get(
            "description", ""
        ).strip() or "Cash Withdrawal"

        if amount <= 0:
            conn.close()
            return render_template(
                "withdrawl.html",
                account_number=account_number,
                balance=balance,
                error="Withdrawal amount must be greater than zero."
            )

        try:
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute(
                "SELECT balance FROM accounts WHERE account_number = ?",
                (account_number,)
            )
            latest_balance = float(cursor.fetchone()[0])

            if amount > latest_balance:
                conn.close()
                return render_template(
                    "withdrawl.html",
                    account_number=account_number,
                    balance=latest_balance,
                    error="Insufficient balance."
                )

            cursor.execute("""
                UPDATE accounts
                SET balance = balance - ?
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
            conn.close()

            return render_template(
                "withdrawl.html",
                account_number=account_number,
                balance=balance,
                success=f"Withdrawal of ₹{amount:.2f} completed successfully."
            )

        except sqlite3.Error:
            conn.rollback()
            conn.close()
            return render_template(
                "withdrawl.html",
                account_number=account_number,
                balance=balance,
                error="Withdrawal failed. Please try again."
            )

    conn.close()
    return render_template(
        "withdrawl.html",
        account_number=account_number,
        balance=balance
    )


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    conn = get_db()
    cursor = conn.cursor()

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
                SELECT transaction_pin_hash
                FROM user_settings WHERE username = ?
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
                    UPDATE user_settings
                    SET transaction_pin_hash = ?
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
                UPDATE user_settings
                SET notifications_enabled = ?
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
    conn.close()

    return render_template(
        "settings.html",
        username=username,
        email=user[0] if user else "",
        pin_set=bool(preferences and preferences[0]),
        notifications_enabled=bool(preferences and preferences[1]),
        message=message,
        error=error
    )


@app.route("/payments", methods=["GET", "POST"])
def payments():
    if not check_session():
        return redirect("/login")

    username = session["logged_in_user"]
    create_account_for_user(username)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT OR IGNORE INTO user_settings (username) VALUES (?)",
        (username,)
    )
    conn.commit()

    cursor.execute("""
        SELECT transaction_pin_hash
        FROM user_settings WHERE username = ?
    """, (username,))
    pin_row = cursor.fetchone()

    if not pin_row or not pin_row[0]:
        conn.close()
        return redirect(
            "/settings?message=Set%20a%204-digit%20transaction%20PIN%20before%20making%20payments."
        )

    cursor.execute("""
        SELECT account_number, balance
        FROM accounts WHERE username = ?
    """, (username,))
    sender = cursor.fetchone()
    account_number, balance = sender[0], float(sender[1])

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
                    JOIN users ON users.username = accounts.username
                    WHERE accounts.account_number = ?
                       OR accounts.username = ? COLLATE NOCASE
                """, (lookup, lookup))
                recipient = cursor.fetchone()

                if not recipient:
                    error = (
                        "Recipient not found. Use a registered username, "
                        "account number, or username@ruralbank."
                    )
                elif recipient[0].lower() == username.lower():
                    error = "You cannot send a payment to your own account."
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
                                cursor, account_number,
                                "TRANSFER_SENT", amount, sender_desc
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

                            cursor.execute(
                                "SELECT balance FROM accounts WHERE account_number = ?",
                                (account_number,)
                            )
                            balance = float(cursor.fetchone()[0])

                    except sqlite3.Error:
                        conn.rollback()
                        error = (
                            "Payment could not be completed. "
                            "No money was transferred."
                        )

    cursor.execute("""
        SELECT username, account_number
        FROM accounts
        WHERE username != ?
        ORDER BY username COLLATE NOCASE
    """, (username,))
    beneficiaries = cursor.fetchall()
    conn.close()

    return render_template(
        "payments.html",
        username=username,
        account_number=account_number,
        balance=balance,
        beneficiaries=beneficiaries,
        error=error,
        success=success
    )


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

        account_number = account[0]

        # FIXED: Return columns in the same order expected by transactions.html.
        cursor.execute("""
            SELECT transaction_type, description, amount, created_at
            FROM transactions
            WHERE account_number = ?
            ORDER BY id DESC
            LIMIT 100
        """, (account_number,))

        transaction_rows = cursor.fetchall()

        return render_template(
            "transactions.html",
            username=username,
            transactions=transaction_rows
        )

    except sqlite3.Error:
        app.logger.exception("Unable to load transaction history")
        return "Unable to load transactions. Please try again.", 500

    finally:
        conn.close()


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    create_database()
    app.run(debug=True)
