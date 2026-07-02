from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import os
import random

app = Flask(__name__)

# Secret key
app.secret_key = "hybrid_waf_secret"

# --------------------------------
# Create logs folder automatically
# --------------------------------

if not os.path.exists('logs'):
    os.makedirs('logs')

LOG_FILE = 'logs/detections.log'


# --------------------------------
# Detect Attacks
# --------------------------------


def detect_attack(text):

    text = text.lower()

    sql_patterns = [
        "' or '1'='1",
        "' or 1=1 --",
        "' or 1=1#",
        "' or 'a'='a",
        "union select",
        "drop table",
        "insert into",
        "delete from",
        "update set",
        "select * from",
        "--",
        ";--",
        "xp_cmdshell",
        "admin' --",
        "'#",
        "' or 1=1",
        "\" or \"1\"=\"1"
    ]

    xss_patterns = [
        "<script>",
        "</script>",
        "javascript:",
        "alert(",
        "onerror=",
        "onload=",
        "<img",
        "<svg"
    ]

    command_patterns = [
        "&&",
        "||",
        "; rm",
        "shutdown",
        "wget",
        "curl",
        "powershell",
        "cmd.exe",
        "/etc/passwd"
    ]

    # SQL Injection Detection

    for pattern in sql_patterns:

        if pattern in text:

            return "SQL Injection"

    # XSS Detection

    for pattern in xss_patterns:

        if pattern in text:

            return "XSS Attack"

    # Command Injection Detection

    for pattern in command_patterns:

        if pattern in text:

            return "Command Injection"

    return None

# --------------------------------
# Write Logs
# --------------------------------

def write_log(message):

    with open(LOG_FILE, 'a') as file:
        file.write(message)


# --------------------------------
# Home Page
# --------------------------------

@app.route('/')
def home():

    return render_template('home.html')


# --------------------------------
# Login Page
# --------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():

    message = ""

    # Generate captcha
    if 'captcha_answer' not in session:

        num1 = random.randint(1, 10)
        num2 = random.randint(1, 10)

        session['captcha_question'] = f"{num1} + {num2}"
        session['captcha_answer'] = str(num1 + num2)

    if request.method == 'POST':

        username = request.form.get('username', '')
        password = request.form.get('password', '')
        captcha = request.form.get('captcha', '')

        combined_input = username + " " + password

        attack = detect_attack(combined_input)

        ip = request.remote_addr

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # --------------------------------
        # ATTACK DETECTED
        # --------------------------------

        if attack:

            attack_log = f"[{current_time}] IP: {ip} | ATTACK DETECTED: {attack} | Payload: {combined_input}\n"

            write_log(attack_log)

            return render_template(
                'blocked.html',
                attack=attack,
                payload=combined_input
            )

        # --------------------------------
        # CAPTCHA VERIFICATION
        # --------------------------------

        if captcha != session.get('captcha_answer'):

            message = "Human Verification Failed"

            return render_template(
                'login.html',
                message=message,
                captcha_question=session.get('captcha_question')
            )

        # --------------------------------
        # SUCCESSFUL LOGIN
        # --------------------------------

        if username == "admin" and password == "1234":

            success_log = f"[{current_time}] IP: {ip} | STATUS: SUCCESSFUL LOGIN | Username: {username}\n"

            write_log(success_log)

            session.pop('captcha_answer', None)

            return redirect(url_for('dashboard'))

        # --------------------------------
        # FAILED LOGIN
        # --------------------------------

        else:

            failed_log = f"[{current_time}] IP: {ip} | STATUS: FAILED LOGIN | Username: {username}\n"

            write_log(failed_log)

            message = "Invalid Credentials"

    return render_template(
        'login.html',
        message=message,
        captcha_question=session.get('captcha_question')
    )


# --------------------------------
# Products Page
# --------------------------------

@app.route('/products')
def products():

    products_list = [
        "Laptop",
        "Phone",
        "Headphones",
        "Keyboard",
        "Monitor"
    ]

    return render_template(
        'products.html',
        products=products_list
    )


# --------------------------------
# Search Page
# --------------------------------

@app.route('/search', methods=['GET', 'POST'])
def search():

    products = []

    if request.method == 'POST':

        search_query = request.form.get('search', '')

        attack = detect_attack(search_query)

        ip = request.remote_addr

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if attack:

            attack_log = f"[{current_time}] IP: {ip} | ATTACK DETECTED: {attack} | Search Payload: {search_query}\n"

            write_log(attack_log)

            return render_template(
                'blocked.html',
                attack=attack,
                payload=search_query
            )

        # --------------------------------
        # Laptops
        # --------------------------------

        if "laptop" in search_query.lower():

            products = [

                {
                    "name": "Dell XPS 15",
                    "price": "₹1,25,000",
                    "image": "https://images.unsplash.com/photo-1496181133206-80ce9b88a853"
                },

                {
                    "name": "HP Pavilion Gaming",
                    "price": "₹78,000",
                    "image": "https://images.unsplash.com/photo-1517336714739-489689fd1ca8"
                },

                {
                    "name": "MacBook Pro",
                    "price": "₹1,80,000",
                    "image": "https://images.unsplash.com/photo-1515879218367-8466d910aaa4"
                },

                {
                    "name": "Lenovo Legion",
                    "price": "₹95,000",
                    "image": "https://images.unsplash.com/photo-1525547719571-a2d4ac8945e2"
                },

                {
                    "name": "ASUS ROG",
                    "price": "₹1,45,000",
                    "image": "https://images.unsplash.com/photo-1509395176047-4a66953fd231"
                }

            ]

        # --------------------------------
        # Phones
        # --------------------------------

        elif "phone" in search_query.lower():

            products = [

                {
                    "name": "iPhone 15 Pro",
                    "price": "₹1,35,000",
                    "image": "https://images.unsplash.com/photo-1511707171634-5f897ff02aa9"
                },

                {
                    "name": "Samsung Galaxy S24",
                    "price": "₹95,000",
                    "image": "https://images.unsplash.com/photo-1580910051074-3eb694886505"
                },

                {
                    "name": "OnePlus 12",
                    "price": "₹69,000",
                    "image": "https://images.unsplash.com/photo-1598327105666-5b89351aff97"
                },

                {
                    "name": "Google Pixel 8",
                    "price": "₹82,000",
                    "image": "https://images.unsplash.com/photo-1565849904461-04a58ad377e0"
                },

                {
                    "name": "Nothing Phone 2",
                    "price": "₹48,000",
                    "image": "https://images.unsplash.com/photo-1510557880182-3d4d3cba35a5"
                }

            ]

        # --------------------------------
        # Headphones
        # --------------------------------

        elif "headphone" in search_query.lower():

            products = [

                {
                    "name": "Sony WH-1000XM5",
                    "price": "₹32,000",
                    "image": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e"
                },

                {
                    "name": "AirPods Max",
                    "price": "₹59,000",
                    "image": "https://images.unsplash.com/photo-1546435770-a3e426bf472b"
                },

                {
                    "name": "JBL Tune 760",
                    "price": "₹7,000",
                    "image": "https://images.unsplash.com/photo-1484704849700-f032a568e944"
                },

                {
                    "name": "Boat Rockerz",
                    "price": "₹2,500",
                    "image": "https://images.unsplash.com/photo-1507878866276-a947ef722fee"
                },

                {
                    "name": "Sennheiser HD 450",
                    "price": "₹12,000",
                    "image": "https://images.unsplash.com/photo-1487215078519-e21cc028cb29"
                }

            ]

        # --------------------------------
        # Keyboards
        # --------------------------------

        elif "keyboard" in search_query.lower():

            products = [

                {
                    "name": "Logitech G Pro",
                    "price": "₹11,000",
                    "image": "https://images.unsplash.com/photo-1511467687858-23d96c32e4ae"
                },

                {
                    "name": "Razer Huntsman",
                    "price": "₹14,000",
                    "image": "https://images.unsplash.com/photo-1517694712202-14dd9538aa97"
                },

                {
                    "name": "Corsair K95",
                    "price": "₹16,000",
                    "image": "https://images.unsplash.com/photo-1541140532154-b024d705b90a"
                },

                {
                    "name": "HP Mechanical Keyboard",
                    "price": "₹4,500",
                    "image": "https://images.unsplash.com/photo-1516321318423-f06f85e504b3"
                },

                {
                    "name": "ASUS TUF Keyboard",
                    "price": "₹6,000",
                    "image": "https://images.unsplash.com/photo-1519389950473-47ba0277781c"
                }

            ]

        # --------------------------------
        # Monitors
        # --------------------------------

        elif "monitor" in search_query.lower():

            products = [

                {
                    "name": "LG UltraGear",
                    "price": "₹28,000",
                    "image": "https://images.unsplash.com/photo-1527443154391-507e9dc6c5cc"
                },

                {
                    "name": "Samsung Curved Monitor",
                    "price": "₹22,000",
                    "image": "https://images.unsplash.com/photo-1498050108023-c5249f4df085"
                },

                {
                    "name": "Dell 4K Monitor",
                    "price": "₹35,000",
                    "image": "https://images.unsplash.com/photo-1496171367470-9ed9a91ea931"
                },

                {
                    "name": "Acer Nitro Display",
                    "price": "₹19,000",
                    "image": "https://images.unsplash.com/photo-1518770660439-4636190af475"
                },

                {
                    "name": "BenQ Gaming Monitor",
                    "price": "₹26,000",
                    "image": "https://images.unsplash.com/photo-1517430816045-df4b7de11d1d"
                }

            ]

    return render_template(
        'search.html',
        products=products
    )


# --------------------------------
# Feedback Page
# --------------------------------

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():

    message = ""

    if request.method == 'POST':

        feedback_text = request.form.get('feedback', '')

        attack = detect_attack(feedback_text)

        ip = request.remote_addr

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if attack:

            attack_log = f"[{current_time}] IP: {ip} | ATTACK DETECTED: {attack} | Feedback Payload: {feedback_text}\n"

            write_log(attack_log)

            return render_template(
                'blocked.html',
                attack=attack,
                payload=feedback_text
            )

        message = "Feedback Submitted Successfully"

    return render_template(
        'feedback.html',
        message=message
    )


# --------------------------------
# Dashboard
# --------------------------------

@app.route('/dashboard')
def dashboard():

    total_logs = 0

    if os.path.exists(LOG_FILE):

        with open(LOG_FILE, 'r') as file:

            total_logs = len(file.readlines())

    return render_template(
        'dashboard.html',
        total_attacks=total_logs
    )


# --------------------------------
# Logs Page
# --------------------------------

@app.route('/logs')
def logs():

    logs_data = []

    if os.path.exists(LOG_FILE):

        with open(LOG_FILE, 'r') as file:

            logs_data = file.readlines()

    return render_template(
        'logs.html',
        logs=logs_data
    )


# --------------------------------
# Logout
# --------------------------------

@app.route('/logout')
def logout():

    session.clear()

    return redirect(url_for('home'))


# --------------------------------
# Run Flask App
# --------------------------------

if __name__ == '__main__':

    app.run(debug=True)