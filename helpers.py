import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol using Yahoo Finance API."""
    try:
        api_key = os.environ.get("RAPIDAPI_KEY")
        headers = {
            "x-rapidapi-host": "apidojo-yahoo-finance-v1.p.rapidapi.com",
            "x-rapidapi-key": api_key
        }
        url = f"https://apidojo-yahoo-finance-v1.p.rapidapi.com/stock/v2/get-summary?symbol={
            urllib.parse.quote_plus(symbol)}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Request exception: {e}")
        return None

    try:
        data = response.json()
        print(f"Response data: {data}")  # Debugging line
        quote = data["price"]
        return {
            "name": quote.get("shortName", "N/A"),
            "price": float(quote["regularMarketPrice"]["raw"]),
            "symbol": symbol.upper()
        }
    except (KeyError, TypeError, ValueError, IndexError) as e:
        print(f"Parsing exception: {e}")
        return None


def usd(value):
    """Format value as USD."""
    if isinstance(value, (int, float)):
        return f"${value:,.2f}"
    return "-"


def symbol_filter(table):
    """Remove duplicate symbols and add up duplicate shares corresponding to those."""
    sym_share_dict = {}
    for row in table:
        symbol = row["symbol"]
        shares = row["shares"]

        if symbol not in sym_share_dict:
            sym_share_dict[symbol] = 0

        if shares != "AMOUNT:":
            sym_share_dict[symbol] += int(shares)

    return sym_share_dict
