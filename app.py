from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import sqlite3, re, hashlib, secrets
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
DB = os.environ.get("DATABASE_PATH", "parking.db")
DEFAULT_RATE = 20.0

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
    return salt + "$" + digest

def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
        return secrets.compare_digest(hash_password(password, salt).split("$", 1)[1], digest)
    except Exception:
        return False

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped

def customer_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("customer_id"):
            flash("Please log in with your customer account first.", "error")
            return redirect(url_for("customer_login", next=request.path))
        return fn(*a, **kw)
    return wrapped

def get_rate(c):
    row = c.execute("SELECT setting_value FROM settings WHERE setting_key='hourly_rate'").fetchone()
    return float(row["setting_value"]) if row else DEFAULT_RATE

def init():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS slots(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slot_number INTEGER UNIQUE NOT NULL,
        status TEXT DEFAULT 'Available')""")
    c.execute("""CREATE TABLE IF NOT EXISTS customers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        mobile TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS bookings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_code TEXT UNIQUE,
        customer_name TEXT NOT NULL,
        mobile TEXT NOT NULL,
        vehicle_number TEXT NOT NULL,
        slot_id INTEGER NOT NULL,
        booking_time TEXT NOT NULL,
        entry_time TEXT,
        exit_time TEXT,
        fee REAL DEFAULT 0,
        amount_paid REAL DEFAULT 0,
        payment_status TEXT DEFAULT 'Unpaid',
        status TEXT DEFAULT 'Booked',
        user_id INTEGER,
        FOREIGN KEY(slot_id) REFERENCES slots(id),
        FOREIGN KEY(user_id) REFERENCES customers(id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings(
        setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL)""")
    c.execute("INSERT OR IGNORE INTO settings VALUES('hourly_rate',?)", (str(DEFAULT_RATE),))
    columns = {r["name"] for r in c.execute("PRAGMA table_info(bookings)").fetchall()}
    if "user_id" not in columns:
        c.execute("ALTER TABLE bookings ADD COLUMN user_id INTEGER")
    for n in range(1, 101):
        c.execute("INSERT OR IGNORE INTO slots(slot_number,status) VALUES(?,'Available')", (n,))
    c.commit()
    c.close()

@app.context_processor
def inject_customer():
    customer = None
    if session.get("customer_id"):
        c = db()
        customer = c.execute("SELECT id,full_name,mobile,email FROM customers WHERE id=?", (session["customer_id"],)).fetchone()
        c.close()
    return {"current_customer": customer}

@app.route("/")
def home():
    c = db()
    slots = c.execute("SELECT * FROM slots ORDER BY slot_number").fetchall()
    r = get_rate(c)
    c.close()
    return render_template("index.html", slots=slots, rate=r)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        mobile = re.sub(r"\D", "", request.form.get("mobile", ""))
        email = request.form.get("email", "").strip().lower() or None
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not name or len(mobile) < 10 or len(mobile) > 13 or len(password) < 6:
            flash("Name, valid 10–13 digit mobile and password (at least 6 characters) are required.", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")
        c = db()
        try:
            cur = c.execute("""INSERT INTO customers(full_name,mobile,email,password_hash,created_at)
                VALUES(?,?,?,?,?)""", (name, mobile, email, hash_password(password), datetime.now().isoformat(timespec="seconds")))
            c.commit()
            session.clear()
            session["customer_id"] = cur.lastrowid
            flash("Your customer account has been created. You are now logged in.", "success")
            c.close()
            return redirect(url_for("home"))
        except sqlite3.IntegrityError:
            c.close()
            flash("This mobile number or email is already registered. Please log in.", "error")
    return render_template("register.html")

@app.route("/customer/login", methods=["GET", "POST"])
def customer_login():
    next_url = request.args.get("next") or request.form.get("next") or ""
    if request.method == "POST":
        identity = request.form.get("identity", "").strip().lower()
        password = request.form.get("password", "")
        c = db()
        customer = c.execute("SELECT * FROM customers WHERE mobile=? OR lower(email)=?", (identity, identity)).fetchone()
        c.close()
        if customer and verify_password(password, customer["password_hash"]):
            session.clear()
            session["customer_id"] = customer["id"]
            flash("Welcome back!", "success")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("home"))
        flash("Incorrect mobile/email or password.", "error")
    return render_template("customer_login.html", next_url=next_url)

@app.route("/customer/logout")
def customer_logout():
    session.pop("customer_id", None)
    flash("You have been logged out of your customer account.", "success")
    return redirect(url_for("home"))

@app.route("/my-bookings")
@customer_required
def my_bookings():
    c = db()
    customer = c.execute("SELECT * FROM customers WHERE id=?", (session["customer_id"],)).fetchone()
    rows = c.execute("""SELECT b.*,s.slot_number FROM bookings b JOIN slots s ON s.id=b.slot_id
        WHERE b.user_id=? ORDER BY b.id DESC""", (session["customer_id"],)).fetchall()
    c.close()
    return render_template("my_bookings.html", customer=customer, rows=rows)

@app.route("/book", methods=["POST"])
@customer_required
def book():
    name = request.form.get("customer_name", "").strip()
    mobile = re.sub(r"\D", "", request.form.get("mobile", ""))
    vehicle = request.form.get("vehicle_number", "").strip().upper()
    sid = request.form.get("slot_id", "")
    if not name or len(mobile) < 10 or not vehicle or not sid:
        flash("Please enter your name, valid mobile, vehicle number and slot.", "error")
        return redirect(url_for("home"))
    c = db()
    slot = c.execute("SELECT * FROM slots WHERE id=?", (sid,)).fetchone()
    duplicate = c.execute("""SELECT id FROM bookings WHERE vehicle_number=?
        AND status IN ('Booked','Parked')""", (vehicle,)).fetchone()
    if not slot or slot["status"] != "Available" or duplicate:
        c.close()
        flash("Slot unavailable or this vehicle already has an active booking.", "error")
        return redirect(url_for("home"))
    now = datetime.now().isoformat(timespec="seconds")
    cur = c.execute("""INSERT INTO bookings(booking_code,customer_name,mobile,vehicle_number,
        slot_id,booking_time,user_id) VALUES('TEMP',?,?,?,?,?,?)""",
        (name, mobile, vehicle, sid, now, session["customer_id"]))
    bid = cur.lastrowid
    code = f"APR-{datetime.now():%y%m%d}-{bid:04d}"
    c.execute("UPDATE bookings SET booking_code=? WHERE id=?", (code, bid))
    c.execute("UPDATE slots SET status='Reserved' WHERE id=?", (sid,))
    c.commit()
    b = c.execute("""SELECT b.*,s.slot_number FROM bookings b JOIN slots s ON s.id=b.slot_id
        WHERE b.id=?""", (bid,)).fetchone()
    c.close()
    return render_template("confirmation.html", b=b)

@app.route("/booking")
def lookup():
    code = request.args.get("code", "").strip().upper()
    b = None
    if code:
        c = db()
        b = c.execute("""SELECT b.*,s.slot_number FROM bookings b JOIN slots s ON s.id=b.slot_id
            WHERE booking_code=?""", (code,)).fetchone()
        c.close()
        if not b:
            flash("Booking ID not found.", "error")
    return render_template("lookup.html", b=b, code=code)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if (os.environ.get("ADMIN_USERNAME") and os.environ.get("ADMIN_PASSWORD")
            and request.form.get("username") == os.environ["ADMIN_USERNAME"]
            and request.form.get("password") == os.environ["ADMIN_PASSWORD"]):
            session.clear()
            session["admin"] = True
            return redirect(url_for("dashboard"))
        flash("Invalid admin login.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/admin")
@admin_required
def dashboard():
    c = db()
    rows = c.execute("""SELECT b.*,s.slot_number FROM bookings b JOIN slots s ON s.id=b.slot_id
        ORDER BY b.id DESC""").fetchall()
    paid = c.execute("SELECT COALESCE(SUM(amount_paid),0) FROM bookings").fetchone()[0]
    due = c.execute("""SELECT COALESCE(SUM(MAX(fee-amount_paid,0)),0) FROM bookings
        WHERE status IN ('Parked','Completed')""").fetchone()[0]
    available = c.execute("SELECT COUNT(*) FROM slots WHERE status='Available'").fetchone()[0]
    r = get_rate(c)
    c.close()
    return render_template("dashboard.html", rows=rows, paid=paid, due=due, available=available, rate=r)

@app.route("/admin/rate", methods=["POST"])
@admin_required
def update_rate():
    try:
        r = float(request.form["hourly_rate"])
        if r <= 0: raise ValueError
    except Exception:
        flash("Enter a valid charge greater than zero.", "error")
        return redirect(url_for("dashboard"))
    c = db()
    c.execute("UPDATE settings SET setting_value=? WHERE setting_key='hourly_rate'", (str(r),))
    c.commit()
    c.close()
    flash(f"Hourly charge updated to ₹{r:.2f}.", "success")
    return redirect(url_for("dashboard"))

@app.route("/admin/entry/<int:i>", methods=["POST"])
@admin_required
def entry(i):
    c = db()
    b = c.execute("SELECT * FROM bookings WHERE id=?", (i,)).fetchone()
    if b and b["status"] == "Booked":
        c.execute("UPDATE bookings SET status='Parked',entry_time=? WHERE id=?", (datetime.now().isoformat(timespec="seconds"), i))
        c.commit()
        flash("Vehicle entry confirmed.", "success")
    else:
        flash("Booking cannot be checked in.", "error")
    c.close()
    return redirect(url_for("dashboard"))

@app.route("/admin/checkout/<int:i>", methods=["POST"])
@admin_required
def checkout(i):
    c = db()
    b = c.execute("SELECT * FROM bookings WHERE id=?", (i,)).fetchone()
    if not b or b["status"] != "Parked":
        flash("Only parked vehicles can be billed.", "error")
    else:
        seconds = max(0, (datetime.now()-datetime.fromisoformat(b["entry_time"])).total_seconds())
        hours = max(1, int(seconds//3600)+(1 if seconds%3600 else 0))
        bill = round(hours*get_rate(c), 2)
        c.execute("UPDATE bookings SET fee=?,exit_time=? WHERE id=?", (bill, datetime.now().isoformat(timespec="seconds"), i))
        c.commit()
        flash(f"Bill generated: ₹{bill:.2f}. Record full payment before releasing vehicle.", "warning")
    c.close()
    return redirect(url_for("dashboard"))

@app.route("/admin/payment/<int:i>", methods=["POST"])
@admin_required
def payment(i):
    try:
        amount = round(float(request.form["amount"]), 2)
        if amount <= 0: raise ValueError
    except Exception:
        flash("Enter valid payment amount.", "error")
        return redirect(url_for("dashboard"))
    c = db()
    b = c.execute("SELECT * FROM bookings WHERE id=?", (i,)).fetchone()
    if not b or b["status"] != "Parked" or b["fee"] <= 0:
        flash("Generate bill first; payment is accepted for parked vehicles.", "error")
    else:
        total = round(b["amount_paid"]+amount, 2)
        status = "Paid" if total >= b["fee"] else "Partial"
        c.execute("UPDATE bookings SET amount_paid=?,payment_status=? WHERE id=?", (total, status, i))
        c.commit()
        flash(f"₹{amount:.2f} received. Total paid ₹{total:.2f}.", "success")
    c.close()
    return redirect(url_for("dashboard"))

@app.route("/admin/release/<int:i>", methods=["POST"])
@admin_required
def release(i):
    c = db()
    b = c.execute("SELECT * FROM bookings WHERE id=?", (i,)).fetchone()
    if b and b["status"] == "Parked" and b["fee"] > 0 and b["amount_paid"] >= b["fee"]:
        c.execute("UPDATE bookings SET status='Completed',payment_status='Paid' WHERE id=?", (i,))
        c.execute("UPDATE slots SET status='Available' WHERE id=?", (b["slot_id"],))
        c.commit()
        flash("Full payment received. Vehicle released; slot is available.", "success")
    else:
        flash("Cannot release vehicle until full bill is generated and paid.", "error")
    c.close()
    return redirect(url_for("dashboard"))

init()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
