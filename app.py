import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, symbol_filter
from datetime import datetime, timezone, timedelta
from functools import wraps

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Register the usd filter
app.jinja_env.filters["usd"] = usd
print(app.jinja_env.filters)  # This should list the 'usd' filter


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
os.environ["RAPIDAPI_KEY"] = '551ef3ebf8mshe17d4dc78a97efdp1a2896jsnc281a9979673'
if not os.environ.get("RAPIDAPI_KEY"):
    raise RuntimeError("RAPIDAPI_KEY not set")

# Create the trades table
db.execute("""
CREATE TABLE IF NOT EXISTS trades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    price REAL NOT NULL,
    time TEXT NOT NULL,
    symbol TEXT NOT NULL,
    shares INTEGER NOT NULL,
    name TEXT NOT NULL
);
""")

# Login required decorator


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Query database for user's current password hash
        user = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])

        if not user or not check_password_hash(user[0]["hash"], current_password):
            flash("Incorrect current password", "error")
            return redirect("/change_password")

        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return redirect("/change_password")

        # Hash the new password
        new_password_hash = generate_password_hash(new_password)

        # Update the password in the database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_password_hash, session["user_id"])

        flash("Password successfully changed", "success")
        return redirect("/")

    return render_template("change_password.html")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        username = db.execute(
            'SELECT username FROM users WHERE id = ?', session['user_id'])[0]['username']
        current_time = datetime.now(
            timezone(timedelta(hours=-5))).strftime('%Y-%m-%d %H:%M:%S')
        shares = 'AMOUNT:'

        if request.form.get('adder'):
            amount = float(request.form.get('adder'))
            new_balance_add = db.execute(
                'SELECT cash FROM users WHERE id = ?', session['user_id'])[0]['cash'] + amount
            db.execute('UPDATE users SET cash = ? WHERE id = ?',
                       new_balance_add, session['user_id'])

            name = '+'
            symbol = 'DEPOSIT +'
            db.execute("INSERT INTO trades (username, price, time, symbol, shares, name) VALUES (?, ?, ?, ?, ?, ?)",
                       username, amount, current_time, symbol, shares, name)

            flash("Money Successfully Added")
            return redirect("/")

        elif request.form.get('subtractor'):
            amount = float(request.form.get('subtractor'))
            new_balance_subtract = db.execute(
                'SELECT cash FROM users WHERE id = ?', session['user_id'])[0]['cash'] - amount
            if new_balance_subtract < 0:
                return apology("Insufficient funds", 400)
            db.execute('UPDATE users SET cash = ? WHERE id = ?',
                       new_balance_subtract, session['user_id'])

            name = '-'
            symbol = 'WITHDRAWAL -'
            db.execute("INSERT INTO trades (username, price, time, symbol, shares, name) VALUES (?, ?, ?, ?, ?, ?)",
                       username, amount, current_time, symbol, shares, name)

            flash("Money Successfully Withdrawn")
            return redirect("/")

        else:
            return apology("Please input amount you'd like to add or subtract", 400)
    else:
        username = db.execute(
            "SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
        user_table = db.execute(
            "SELECT * FROM trades WHERE username = ?", username)
        q = symbol_filter(user_table)
        user_cash = db.execute(
            'SELECT cash FROM users WHERE id = ?', session['user_id'])[0]['cash']
        stock_cash = sum(lookup(row)["price"] * q[row] for row in q)

        return render_template("landing.html", user_cash=user_cash, user_table=user_table, usd=usd, stock_cash=stock_cash, q=q, lookup=lookup)


@app.route("/buy", methods=["GET", "POST"])
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol or not shares:
            return apology("must provide symbol and shares", 400)

        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be a number", 400)

        if shares <= 0:
            return apology("shares must be a positive number", 400)

        q = lookup(symbol)
        if not q:
            return apology("invalid symbol", 400)

        cost = q["price"] * shares
        cash = db.execute("SELECT cash FROM users WHERE id = ?",
                          session["user_id"])[0]["cash"]

        if cost > cash:
            return apology("can't afford", 400)

        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?",
                   cost, session["user_id"])
        db.execute("INSERT INTO trades (username, symbol, shares, price, time, name) VALUES (?, ?, ?, ?, ?, ?)",
                   db.execute("SELECT username FROM users WHERE id = ?",
                              session["user_id"])[0]["username"],
                   symbol, shares, q["price"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), q.get("name", "N/A"))

        flash("Bought successfully!")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    username = db.execute("SELECT username FROM users WHERE id = ?",
                          session["user_id"])[0]["username"]
    trades = db.execute(
        "SELECT symbol, shares, price, time FROM trades WHERE username = ?", username)
    print(f"Trades fetched for {username}: {trades}")  # Debugging line
    return render_template("history.html", usd=usd, trades=trades)


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)

        q = lookup(symbol)
        if not q:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", name=q.get("name", "N/A"), price=usd(q["price"]), symbol=q["symbol"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))
        if len(rows) != 0:
            return apology("username already exists", 400)

        hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   request.form.get("username"), hash)

        flash("Registered successfully!")
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol or not shares:
            return apology("must provide symbol and shares", 400)

        try:
            shares = int(shares)
        except ValueError:
            return apology("shares must be a number", 400)

        if shares <= 0:
            return apology("shares must be a positive number", 400)

        username = db.execute(
            "SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
        owned_shares = db.execute("SELECT SUM(shares) AS total_shares FROM trades WHERE username = ? AND symbol = ?",
                                  username, symbol)[0]["total_shares"]

        if shares > owned_shares:
            return apology("too many shares", 400)

        q = lookup(symbol)
        if not q:
            return apology("invalid symbol", 400)

        sale_price = q["price"] * shares
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",
                   sale_price, session["user_id"])
        db.execute("INSERT INTO trades (username, symbol, shares, price, time, name) VALUES (?, ?, ?, ?, ?, ?)",
                   username, symbol, -shares, q["price"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), q.get("name", "N/A"))

        flash("Sold successfully!")
        return redirect("/")

    else:
        username = db.execute(
            "SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
        symbols = db.execute(
            "SELECT DISTINCT symbol FROM trades WHERE username = ?", username)
        return render_template("sell.html", symbols=symbols)


@app.route("/debug")
def debug():
    return render_template("debug.html")


@app.route("/test")
def test():
    return render_template("test.html", amount=1234.56)
