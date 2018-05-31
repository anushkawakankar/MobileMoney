from flask import Flask, render_template, request,session, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import TextField, SubmitField, PasswordField, BooleanField, IntegerField, RadioField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Length, Email, Required, NumberRange
from passlib.hash import sha256_crypt
from random import randint
import datetime
from functools import wraps
from flask_login import LoginManager,login_user, login_required, logout_user, current_user


app = Flask(__name__)
csrf = CSRFProtect(app)

app.secret_key = 'hello_world'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

db = SQLAlchemy(app)
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'
# login_manager = LoginManager()

#Models
class User(db.Model):
    uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    phone = db.Column(db.Integer, unique=True)
    password = db.Column(db.String(30))
    email = db.Column(db.String(50), unique=True, index=True)
    username = db.Column(db.String(50), unique=True, index=True)
    usertype = db.Column(db.String(15))
    balance = db.Column(db.Float(precision=2))

    def __init__(self, phone, username, password, email, usertype, balance):
        self.username = username
        self.email = email
        self.phone = phone
        self.password = password
        self.usertype = usertype
        self.balance = balance


class Transactions(db.Model):
    tid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    from_user = db.Column(db.String(50))
    to_user = db.Column(db.String(50))
    amount = db.Column(db.Float(precision=2))
    date = db.Column(db.DateTime, default=datetime.datetime.now)

    def __init__(self,from_user,to_user,amount):
        self.from_user=from_user
        self.to_user=to_user
        self.amount=amount

#Forms
class SignUpForm(FlaskForm):
    phone = TextField('Phone',validators=[DataRequired(),Length(10)])
    email = EmailField('Email', validators=[DataRequired(), Email(message='Please enter a valid email Id')])
    username = TextField('Username', validators=[DataRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
    usertype = RadioField('Usertype',choices=[('personal','Personal'),('business','Business')],validators = [Required(message="Hello")])

class SignInForm(FlaskForm):
    username = TextField('Username', validators=[DataRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=30)])
    remember_me = BooleanField('Keep me logged in')

class PayForm(FlaskForm):
    amount = TextField('Amount', validators=[DataRequired(), NumberRange(min=1, max=10000)])
    to = TextField('To', validators=[DataRequired(), ])

class AddMoneyForm(FlaskForm):
    amount = TextField('Amount', validators=[DataRequired(), NumberRange(min=1, max=10000)])

class PasswordForm(FlaskForm):
    original = PasswordField('Original', validators=[DataRequired(),Length(min=8, max=20)])
    new = PasswordField('new', validators=[DataRequired(),Length(min=8, max=20)])

# class SearchForm(FlaskForm):
#Views
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(session)
        if not session['user_available']:
            return redirect(url_for('signin', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signupform = SignUpForm(request.form)
    #print(signupform.data)
    # print(signupform.validate())
    print(signupform.errors)
    if request.method == 'POST' and signupform.validate():
        #print(signupform)

        hash_pass = sha256_crypt.encrypt(signupform.password.data)
        reg = User(signupform.phone.data, signupform.username.data,
                   hash_pass, signupform.email.data, signupform.usertype.data, randint(100,1000))
        current_user=signupform.username.data
        flash('Welcome to Chillar')
        db.session.add(reg)
        db.session.commit()
        return redirect(url_for('signin'))
    else:
        print("Failed")
    return render_template('signup.html', signupform=signupform)

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    signinform = SignInForm(request.form) #why no request.form here?
    print(signinform.errors)
    if request.method == 'POST' and signinform.validate():
        un = signinform.username.data 
        #check username exists
        log = User.query.filter_by(username=un).first()
        if sha256_crypt.verify(str(signinform.password.data) , log.password):
            print("something")
            current_user = log.username
            session['current_user'] = current_user
            session['user_available'] = True
            flash('You were successfully logged in')
            return redirect(url_for('home'))
        else:
            flash('Invalid password provided')
    return render_template('signin.html', signinform=signinform)

@app.route('/home')
@login_required
def home():
    user = User.query.filter_by(username=session['current_user']).first()
    if user.usertype == "personal":
        return render_template('home.html')
    else:
        # print(signupform.errors)
        return render_template('home2.html')

@app.route('/pay', methods=['GET', 'POST'])
@login_required
def pay():
    payform = PayForm()
    print(payform.errors)
    if request.method == 'POST':
        if session['user_available']:
            to_ = payform.to.data
            amt = float(payform.amount.data)
            user = User.query.filter_by(username=session['current_user']).first()
            userto = User.query.filter_by(phone=to_).first()

            # print(userto.balance)
            # print(user.balance)
            # print(amt)
            if user.balance >= amt:
                # print("hatup")
                user.balance -= amt
                userto.balance += amt
                # print(user.balance)
                # print(amt)

                transaction = Transactions(user.username,userto.username,amt)
                db.session.add(transaction)
                db.session.commit()
                flash('Paid!')
                return redirect(url_for('home'))
                # print("Completed")
        else:
            flash('User is not Authenticated')
            return redirect(url_for('index'))
    else:
        flash('Enter a valid amount')
    return render_template('pay.html', payform=payform)

@app.route('/passbook')
@login_required
def passbook():
    if session['user_available']:

        all_user = Transactions.query.order_by(Transactions.tid.desc()).all()
        debit_list = []
        credit_list = []
        passbook = []
        added = []
        now_user = User.query.filter_by(username=session['current_user']).first()

        for x in all_user:
            if x.from_user == session['current_user'] and x.to_user != session['current_user']:
                debit_list.append(x)
                passbook.append(x)
            elif x.to_user == session['current_user'] and x.from_user != session['current_user']:
                passbook.append(x)
                credit_list.append(x)
            elif x.from_user == session['current_user'] and x.to_user == session['current_user']:
                passbook.append(x)
                added.append(x)

        if now_user.usertype == "personal":
            return render_template('passbook2.html',passbook=passbook, debit_list=debit_list, credit_list=credit_list,now_user=now_user,added=added)

        else:
            return render_template('passbook.html',passbook=passbook, credit_list=credit_list,now_user=now_user)
    else:
        flash('User not Authenticated')
        return redirect(url_for('index'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_money():
    addmoneyform = AddMoneyForm()
    print(addmoneyform.errors)
    if request.method == 'POST':
        if session['user_available']:
            amt = float(addmoneyform.amount.data)
            now_user = User.query.filter_by(username=session['current_user']).first()
            now_user.balance += amt
            transaction = Transactions(now_user.username,now_user.username,amt)
            db.session.add(transaction)
            db.session.commit()
            flash('Money Added')
            return redirect(url_for('home'))

    return render_template('add.html', addmoneyform=addmoneyform)

# @app.route('/about_user')
# def about_user():
#     if session['user_available']:
#         user=User.query.filter_by(username=session['current_user']).first()
#     return render_template('about.html',user=user)

@app.route('/change', methods=["GET","POST"])
@login_required
def change():
    form = PasswordForm()
    if request.method == 'POST':
        if session['user_available']:
            user = User.query.filter_by(username=session['current_user']).first()
            print(user.password)
            if sha256_crypt.verify(str(form.original.data), user.password):
                print(":P")
                user.password = sha256_crypt.encrypt(form.new.data)                
                db.session.add(user)
                db.session.commit()
                flash('Password has been updated!')
            else:
                flash('Invalid password provided')
            return redirect(url_for('home'))
 
    return render_template('change.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    session['current_user'] = None
    session['user_available'] = False
    return redirect(url_for('index'))

if(__name__) == '__main__' :
    app.run(debug=True)


# ddcrfrf           
    # blahhhh
