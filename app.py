import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)
app.secret_key = 'nah_brother_aint_playing110'

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Getting user id
    user_id = session.get("user_id")

    # Querying portfolio and storing it in list of dictionaries
    port_dict_list = db.execute("SELECT * FROM portfolio WHERE user_id = ?", user_id)

    # Querying lookup dynamically and storing the result in a temporary dictionary list
    tmp_dict = []
    for sym in port_dict_list:
        symbol = sym.get("symbol")
        if symbol:
            tmp_dict.append(lookup(symbol))

    # Storing the new price of the symbol to the tmp dictionary list
    for price1 in tmp_dict:
        for price2 in port_dict_list:
            if price1["symbol"] == price2["symbol"]:
                price2["price"] = price1["price"]

    his_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # Calculating total cash and prices
    grand_total = 0
    for total in port_dict_list:
        t_price = (total["price"] * total["shares"])
        grand_total += t_price

    grand_total += his_cash

    return render_template("index.html", portfolio=port_dict_list, cash=his_cash, GRAND_TOTAL=grand_total, usd=usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # POST
    if request.method == "POST":

        # Getting the share/stock symbol
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("missing symbol")

        # calling lookup for that symbol if it valid
        symbol_dict = lookup(symbol)
        if symbol_dict == None:
            return apology("invalid symbol")

        # getting shares/stocks
        shares_input = request.form.get("shares")

        # Check if input is numeric (from cs50 duck debugger)
        try:
            shares = float(shares_input)
        except ValueError:
            return apology("Invalid number of shares")

        # Check for fractional and negative shares
        if not shares.is_integer() or shares <= 0:
            return apology("Invalid number of shares")
        shares = int(shares)

        # user id
        user_id = session.get("user_id")

        # Stock current price
        price = round(int(symbol_dict["price"]), 2)

        # Current user
        user_row = db.execute("SELECT * FROM users WHERE id = ?", user_id)

        # Current user's cash
        cash = round(int(user_row[0]["cash"]), 2)
        id = user_row[0]["id"]

        # Purchase the stock if user can afford
        for _ in range(shares):
            if price >= cash:
                return apology("You can't afford")
            cash -= round(price, 2)

        # Update the cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", round(int(cash), 2), user_id)

        # Real time
        time = datetime.now()

        # transaction type 'buy'
        transaction_type = 'buy'

        # Track users purchases by storing in purchase table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, his_cash, transaction_type, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   id, symbol, shares, price, round(int(cash), 2), transaction_type, time)

        # Updating portfolio table if the symbol exist else inserting it
        rows = db.execute(
            "SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if len(rows) == 1:
            db.execute(
                "UPDATE portfolio SET shares = shares + ? WHERE user_id = ? AND symbol = ?", shares, user_id, symbol)
        else:
            db.execute("INSERT INTO portfolio (user_id, symbol, shares, prices) VALUES (?, ?, ?, ?)",
                       user_id, symbol, shares, round(int(price), 2))

        flash("Bought!")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # current user id
    user_id = session.get("user_id")

    # Querying transaction to get the list of transactions
    tran_dict = db.execute("SELECT * FROM transactions WHERE user_id = ?", user_id)

    return render_template("history.html", usd=usd, transactions=tran_dict)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""

    user_id = session.get("user_id")

    if request.method == "POST":

        # check if new passowrd was provided
        new_pass = request.form.get("password")
        if not new_pass:
            return apology("no password!")

        # check if the confirmation match new password
        conf = request.form.get("confirmation")
        if not conf or conf != new_pass:
            return apology("not matching!")

        # generate hash for that new password
        new_hash_pass = generate_password_hash(conf)

        # update the users hash to the new hash
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash_pass, user_id)

        flash("You have changed your password!".upper())
        return redirect("/")

    else:
        return render_template("password.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # POST
    if request.method == "POST":

        # Getting symbol from the name and validating
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing Symbol")

        # Passing symbol to the look up
        quote = lookup(symbol)
        if quote == None:
            return apology("Invalid Symbol")

        return render_template("quoted.html", quote=quote, usd=usd)

    # GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # POST
    if request.method == "POST":

        # checking valid username
        username = request.form.get("username")
        if not username:
            return apology("Username is required")

        # checking valid password
        password = request.form.get("password")
        if not password:
            return apology("Password is required")

        # checking valid confirmation and match
        confirmation = request.form.get("confirmation")
        if not confirmation or password != confirmation:
            return apology("Retype the password")

        # checking if the username already taken
        try:
            hashed_pass = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_pass)
        except ValueError:
            return apology("pick another username")

        # Remember the user
        rows = db.execute("SELECT id FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    # GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Getting current user id
    user_id = session.get("user_id")

    # Querying for that user's portfolio
    dict_symbols_shares = db.execute("SELECT * FROM portfolio WHERE user_id = ?", user_id)

    # via post
    if request.method == "POST":

        # Getting form symbol and validating it
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("you haven't selected a symbol")

        # Getting form shares input and validating it
        shares = request.form.get("shares")
        if not shares:
            return apology("missing shares")
        if not int(shares) >= 1:
            return apology("shares must be positive")

        # Storing the symbols in a temporary list to validate it and prevent client-side validation
        selected_symbols = []
        for sym in dict_symbols_shares:
            selected_symbols.append(sym["symbol"])
        if symbol not in selected_symbols:
            return apology("invalid symbol")

        # get the price before the row deleted
        price = db.execute("SELECT prices FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, symbol)[
            0]["prices"]

        # checking if the shares are less than users input shares
        rows = db.execute(
            "SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if len(rows) != 1 or int(shares) > int(rows[0]["shares"]):
            return apology("not enough shares")

        # updating the current users shares
        db.execute("UPDATE portfolio SET shares = shares - ? WHERE user_id = ? AND symbol = ?",
                   shares, user_id, symbol)

        # deleting the the symbol if it becomes zero
        db.execute("DELETE FROM portfolio WHERE user_id = ? AND symbol = ? AND shares = 0", user_id, symbol)

        # type selling stock
        transaction_type = 'sell'

        # current time
        time = datetime.now()

        # adding the selled shares to the users cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        price = price * int(shares)
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", price, user_id)

        shares = int(shares)

        # recording the users transactions sell
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, his_cash, transaction_type, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   user_id, symbol, -shares, price, cash, transaction_type, time)

        flash("Sold!")
        return redirect("/")

    else:
        return render_template("sell.html", symbols=dict_symbols_shares)
