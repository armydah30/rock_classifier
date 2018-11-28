from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
import os
from data import Rules
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, TextAreaField, IntegerField, PasswordField, SelectField, validators
from flask_bcrypt import Bcrypt
from functools import wraps
import requests
import json
import geocoder
import time
from datetime import datetime, timedelta
import math
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.debug = False
app.config['SECRET_KEY'] = '12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rock_app.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

#add Database Views
class Rock(db.Model):
    id =db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=True)
    location = db.Column(db.Integer, nullable=False)
    ucs = db.Column(db.Integer, nullable=False)
    acv = db.Column(db.Integer, nullable=False)
    pl = db.Column(db.Integer, nullable=False)
    av = db.Column(db.Integer, nullable=False)
    brit = db.Column(db.Integer, nullable=False)
    bwi = db.Column(db.Integer, nullable=False)
    dri = db.Column(db.Integer, nullable=False)
    create_date = db.Column(db.DateTime, nullable=False)


class Users(db.Model):
    id =db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    create_date = db.Column(db.DateTime, nullable=False)


#Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unathorized! Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

#Registration form class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
        ])
    confirm = PasswordField('Confirm Password')


#User Register
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        #execute commands
        user = Users(name=name, email=email, username=username, password=hashed_password, create_date=datetime.now())
        db.session.add(user)
        db.session.commit()

        flash('You are now registered and can log in', 'success')

        redirect(url_for('login'))

    return render_template('add_user.html', form=form)


#Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@is_logged_in
def dashboard():

    #get rules
    rocks = Rock.query.all()

    if len(rocks) > 0:
        return render_template('dashboard.html', rocks=rocks)
    else:
        msg = 'No Data Found'
        return render_template('dashboard.html', msg=msg)

#Dashboard
@app.route('/rocks', methods=['GET', 'POST'])
def rocks():

    #get rules
    rocks = Rock.query.all()

    if len(rocks) > 0:
        return render_template('rocks.html', rocks=rocks)
    else:
        msg = 'No Data Found'
        return render_template('rocks.html', msg=msg)

#Rock registration form
class RockForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    phone = StringField('Phone', [validators.Length(min=4, max=25)])
    location = StringField('Location', [validators.Length(min=4, max=25)])
    ucs = IntegerField('Uniaxial Compressive Strength', [validators.NumberRange(min=1)])
    acv = IntegerField('Aggregate Crushing Value', [validators.NumberRange(min=1)])
    pl = IntegerField('Point Load', [validators.NumberRange(min=1)])
    av = IntegerField('Abrasion', [validators.NumberRange(min=10)])
    brit = IntegerField('Brittleness', [validators.NumberRange(min=1)])
    bwi = IntegerField('Bit Wear Index', [validators.NumberRange(min=1)])
    dri = IntegerField('Drilling Rate Index', [validators.NumberRange(min=0)])


#Rock registration
@app.route('/', methods=['GET', 'POST'])
def home():
    form = RockForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        phone = form.phone.data
        location = form.location.data
        ucs = form.ucs.data
        acv = form.acv.data
        pl = form.pl.data
        av = form.av.data
        brit = form.brit.data
        bwi = form.bwi.data
        dri = form.dri.data

    #execute commands
        rock = Rock(name=name, phone=phone, location=location, ucs=ucs, acv=acv, pl=pl, av=av, brit=brit, bwi=bwi, dri=dri, create_date=datetime.now().date())
        db.session.add(rock)
        db.session.commit()

        flash('Information Collected!', 'success')

        return redirect(url_for('home'))

    return render_template('home.html', form=form)

#Rock Entry
@app.route('/rock/<string:id>/')
def rock(id):

    #get post
    rock = Rock.query.filter_by(id=id).one()

    return render_template('rock.html', rock=rock)

#User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        #Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']
        user = Users.query.filter_by(username=username).first()
        if user.id > 0:
            #compare passwords
            if user and bcrypt.check_password_hash(user.password, password_candidate):
             #Passed
                session['logged_in'] = True
                session['username'] = username
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Wrong Password. Please Try Again'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

#Manage user
@app.route('/users')
@is_logged_in
def users():
    #get users
    users = Users.query.all()

    if len(users) > 0:
        return render_template('users.html', users=users)
    else:
        msg = 'No Users Found'
        return render_template('users.html', msg=msg)


#LogOut
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out!', 'success')
    return redirect(url_for('login'))




if __name__ == '__main__':
    	port = int(os.environ.get('PORT', 5000))
    	app.run(host='0.0.0.0', port=port)
