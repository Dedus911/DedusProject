import os
import threading
import time

from flask import Flask, render_template, request, redirect, flash, url_for, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'eragbiuygraeiuboaergpihu'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    coins = db.Column(db.Integer, nullable=False)
    coinsM = db.Column(db.Integer, nullable=False)
    coinsT = db.Column(db.Integer, nullable=False)
    coinsQ = db.Column(db.Integer, nullable=False)
    autoLvl = db.Column(db.Integer, nullable=False)
    clickLvl = db.Column(db.Integer, nullable=False)

    def __init__(self, login, password):
        self.login = login
        self.password = password
        self.coins = 0
        self.coinsM = 0
        self.coinsT = 0
        self.coinsQ = 0
        self.autoLvl = 0
        self.clickLvl = 1

    def money(self):
        if self.coinsQ:
            return self.coinsQ
        if self.coinsT:
            return self.coinsT
        if self.coinsM:
            return self.coinsM
        if self.coins:
            return self.coins
        return None

    def add(self):
        self.coins += self.clickLvl

    def add_auto(self):
        self.coins += self.autoLvl

    def upgrade_buy(self):
        if self.coins >= self.clickLvl * self.clickLvl:
            self.coins -= self.clickLvl * self.clickLvl
            self.clickLvl += 1

    def auto_buy(self):
        if self.coins >= self.autoLvl * self.autoLvl:
            self.coins -= self.autoLvl * self.autoLvl
            self.autoLvl += 1


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login') + '?next=' + request.url)

    return response


@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template("index.html")
    return render_template("index.html")


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            redirect(next_page)
        else:
            flash("Неверный пароль или имя пользователя")
    else:
        flash("Заполните логин и пароль")
    return render_template('login.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['post', 'get'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    if request.method == 'POST':
        if not (login or password):
            flash("Заполните логин и пароль")
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/rating')
def rating():
    us = User.query.order_by(desc(User.coinsQ), desc(User.coinsT), desc(User.coinsM), desc(User.coins)).all()
    return render_template("rating.html", users=us[:min(10, len(us))])


@app.route('/state')
@login_required
def get_state():
    return jsonify({"coins": current_user.money(),
                    "auto": current_user.autoLvl,
                    "upgrade": current_user.clickLvl})


@app.route('/buy_upgrade', methods=['POST'])
@login_required
def buy_upgrade():
    current_user.upgrade_buy()
    db.session.commit()
    return ""


@app.route('/buy_autoclicker', methods=['POST'])
@login_required
def buy_autoclicker():
    current_user.auto_buy()
    db.session.commit()
    return ""


@app.route('/click', methods=['POST'])
@login_required
def click():
    current_user.add()
    db.session.commit()
    return ""


def autoclicker_worker():
    while True:
        time.sleep(1)
        with app.app_context():
            for i in User.query:
                i.add_auto()
                db.session.commit()


threading.Thread(target=autoclicker_worker, daemon=True).start()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=80)
