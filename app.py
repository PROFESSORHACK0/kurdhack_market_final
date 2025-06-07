
from flask import Flask, render_template, request, redirect, flash, session
from flask_mail import Mail, Message
import sqlite3, bcrypt, random
from config import *

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Mail Config
app.config.update(
    MAIL_SERVER=MAIL_SERVER,
    MAIL_PORT=MAIL_PORT,
    MAIL_USE_TLS=MAIL_USE_TLS,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=MAIL_PASSWORD
)
mail = Mail(app)

def init_db():
    conn = sqlite3.connect('database/users.db')
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password_hash TEXT,
            is_verified INTEGER DEFAULT 0,
            verification_code TEXT
        )
    """)
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        code = str(random.randint(100000, 999999))

        conn = sqlite3.connect('database/users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password_hash, verification_code) VALUES (?, ?, ?)",
                      (email, hashed, code))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("ئەم ئیمەیڵە تۆمارکراوە.", "danger")
            return redirect('/register')
        conn.close()

        msg = Message("کۆدی پشتڕاستکردن", sender=MAIL_USERNAME, recipients=[email])
        msg.body = f"کۆدی پشتڕاستکردنت: {code}"
        mail.send(msg)

        session['email'] = email
        flash("کۆدی پشتڕاستکردن نێردرا بۆ ئیمەیڵ.", "info")
        return redirect('/verify')
    return render_template("register.html")

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code = request.form['code']
        email = session.get('email')
        conn = sqlite3.connect('database/users.db')
        c = conn.cursor()
        c.execute("SELECT verification_code FROM users WHERE email = ?", (email,))
        result = c.fetchone()
        if result and code == result[0]:
            c.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
            conn.commit()
            conn.close()
            flash("پشتڕاستکرا.", "success")
            return redirect('/login')
        else:
            flash("کۆدی هەڵە.", "danger")
    return render_template("verify.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        conn = sqlite3.connect('database/users.db')
        c = conn.cursor()
        c.execute("SELECT password_hash, is_verified FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password, user[0]):
            if user[1] == 1:
                flash("بەخێربێیت.", "success")
                return redirect('/home')
            else:
                flash("ئەتەوێت سەرەتا پشتڕاست بکەیت.", "warning")
                session['email'] = email
                return redirect('/verify')
        else:
            flash("چوونەژوورەوە سەرکەوتوو نەبوو.", "danger")
    return render_template("login.html")

@app.route('/home')
def home():
    return render_template("home.html")

@app.route('/success')
def success():
    return render_template("success.html")

@app.route("/test-email")
def test_email():
    try:
        msg = Message("تاقیکردنەوەی ناردنی ئەیمەیڵ",
                      sender=MAIL_USERNAME,
                      recipients=[MAIL_USERNAME])
        msg.body = "ئەمە نامەیەکی تاقیکردنە."
        mail.send(msg)
        return "نامە نێردرا!"
    except Exception as e:
        return f"هەڵەیەک ڕوویدا: {e}"

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
