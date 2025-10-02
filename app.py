from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from decimal import Decimal
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/stock_trading_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "650a5cb8a4e921d0f8a4bb24d0bc30cc53304f3ccf1d8486e90e0b52218d4ee4b0c6c277c3e47834964cc7b04cf150685e86fff261c8db0285a367d209b75f63"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('customer', 'admin'),
                     nullable=False, default='customer')
    full_name = db.Column(db.String(100), nullable=False)
    cash_balance = db.Column(db.Numeric(15, 2), nullable=False, default=0.00)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)

    def deposit_funds(self, amount):
        if amount > 0:
            self.cash_balance += Decimal(str(amount))
            db.session.commit()
            return True
        return False


class Stock(db.Model):
    __tablename__ = 'stock'

    stock_id = db.Column(db.BigInteger, primary_key=True)
    ticker = db.Column(db.String(10), unique=True, nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    current_price = db.Column(db.Numeric(15, 2), nullable=False)
    volume = db.Column(db.BigInteger, nullable=False, default=0)
    day_high = db.Column(db.Numeric(15, 2), nullable=False)
    day_low = db.Column(db.Numeric(15, 2), nullable=False)
    opening_price = db.Column(db.Numeric(15, 2), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)

    def update_price(self, new_price):
        if new_price > 0:
            self.current_price = Decimal(str(new_price))
            if new_price > self.day_high:
                self.day_high = Decimal(str(new_price))
            if new_price < self.day_low:
                self.day_low = Decimal(str(new_price))
            db.session.commit()
            return True
        return False


class Portfolio(db.Model):
    __tablename__ = 'portfolio'

    portfolio_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.id'), nullable=False)
    stock_id = db.Column(db.BigInteger, db.ForeignKey(
        'stock.stock_id'), nullable=False)
    shares_owned = db.Column(db.BigInteger, nullable=False, default=0)

    __table_args__ = (db.UniqueConstraint(
        'user_id', 'stock_id', name='unique_user_stock'),)


class Transaction(db.Model):
    __tablename__ = 'transaction'

    transaction_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.id'), nullable=False)
    stock_id = db.Column(db.BigInteger, db.ForeignKey(
        'stock.stock_id'), nullable=False)
    type = db.Column(db.Enum('buy', 'sell'), nullable=False)
    quantity = db.Column(db.BigInteger, nullable=False)
    price = db.Column(db.Numeric(15, 2), nullable=False)
    transaction_date = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow)


class Order(db.Model):
    __tablename__ = 'order'

    order_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey(
        'user.id'), nullable=False)
    stock_id = db.Column(db.BigInteger, db.ForeignKey(
        'stock.stock_id'), nullable=False)
    type = db.Column(db.Enum('buy', 'sell'), nullable=False)
    quantity = db.Column(db.BigInteger, nullable=False)
    order_type = db.Column(db.Enum('market', 'limit'), nullable=False)
    limit_price = db.Column(db.Numeric(15, 2), nullable=True)
    status = db.Column(db.Enum('pending', 'completed',
                       'cancelled'), nullable=False, default='pending')
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow)


with app.app_context():
    db.create_all()


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Logged in successfully!', 'success')
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        if not full_name or not username or not email or not password:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('register'))

        try:
            passwd_hash = bcrypt.generate_password_hash(
                password).decode('utf-8')

            new_user = User(full_name=full_name, username=username,
                            email=email, password=passwd_hash)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('register'))
        except Exception as e:
            flash(f'Error adding user: {str(e)}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/market')
@login_required
def market():
    return render_template('market.html')

@app.route('/trade/<ticker>', methods=['GET', 'POST'])
@login_required
def trade(ticker):
    
    stock = Stock.query.filter_by(ticker=ticker).first()
    if not stock:
        flash('Stock not found', 'error')
        return redirect(url_for('market'))

    user = current_user

    portfolio_item = Portfolio.query.filter_by(user_id=user.id, stock_id=stock.stock_id).first()
    user_shares = portfolio_item.shares_owned if portfolio_item else 0

    if request.method == 'POST':
        action = request.form['action']
        shares = int(request.form['shares'])

        if shares <= 0:
            flash('Enter a valid number of shares', 'error')
            return redirect(url_for('trade', ticker=ticker))

        if action == 'buy':
            total_cost = shares * stock.current_price
            if user.cash_balance < total_cost:
                flash('Insufficient funds', 'error')
            else:
                new_transaction = Transaction(
                    user_id=user.id,
                    stock_id=stock.stock_id,
                    type='buy',
                    quantity=shares,
                    price=stock.current_price
                )

                user.cash_balance -= total_cost

                if portfolio_item:
                    portfolio_item.shares_owned += shares
                else:
                    portfolio_item = Portfolio(
                        user_id=user.id,
                        stock_id=stock.stock_id,
                        shares_owned=shares
                    )
                    db.session.add(portfolio_item)

                db.session.add(new_transaction)
                db.session.commit()

                flash(f'Successfully bought {shares} shares of {stock.ticker}', 'success')
                return redirect(url_for('dashboard'))

        elif action == 'sell':
            if not portfolio_item or portfolio_item.shares_owned < shares:
                flash('Not enough shares to sell', 'error')
            else:
                total_value = shares * stock.current_price

                new_transaction = Transaction(
                    user_id=user.id,
                    stock_id=stock.stock_id,
                    type='sell',
                    quantity=shares,
                    price=stock.current_price
                )

                user.cash_balance += total_value

                portfolio_item.shares_owned -= shares
                if portfolio_item.shares_owned == 0:
                    db.session.delete(portfolio_item)

                db.session.add(new_transaction)
                db.session.commit()

                flash(f'Successfully sold {shares} shares of {stock.ticker}', 'success')
                return redirect(url_for('dashboard'))

    return render_template('trade.html', stock=stock, user=user, user_shares=user_shares)

@app.route('/transaction_history')
@login_required
def transaction_history():
    return render_template('transaction_history.html')


@app.route('/cash_management')
@login_required
def cash_management():
    return render_template('cash_management.html')


@app.route('/admin/dashboard')
@admin_required
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')


if __name__ == '__main__':
    app.run(debug=True)
