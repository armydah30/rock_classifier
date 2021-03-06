from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
import os
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, TextAreaField, FloatField, IntegerField, DecimalField, PasswordField, SelectField, validators
from flask_bcrypt import Bcrypt
from functools import wraps
import requests
import json
import geocoder
import time
from datetime import datetime, timedelta
import math
from werkzeug.utils import secure_filename
from sqlalchemy import desc



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
    ucs_class = db.Column(db.String(100), nullable=True)
    acv_class = db.Column(db.String(100), nullable=True)
    pl_class = db.Column(db.String(100), nullable=True)
    av_class = db.Column(db.String(100), nullable=True)
    brit_class = db.Column(db.String(100), nullable=True)
    bwi_class = db.Column(db.String(100), nullable=True)
    dri_class = db.Column(db.String(100), nullable=True)
    create_date = db.Column(db.DateTime, nullable=False)


class Users(db.Model):
    id =db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    create_date = db.Column(db.DateTime, nullable=False)

2
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
@is_logged_in
def add_user():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        #execute commands to insert into db
        user = Users(name=name, email=email, username=username, password=hashed_password, create_date=datetime.now())
        db.session.add(user)
        db.session.commit()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))

    return render_template('add_user.html', form=form)


#Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@is_logged_in
def dashboard():

    #get rock entries
    rocks = Rock.query.order_by(Rock.id.desc()).all()

    if len(rocks) > 0:
        return render_template('dashboard.html', rocks=rocks)
    else:
        msg = 'No Data Found'
        return render_template('dashboard.html', msg=msg)

#Dashboard
@app.route('/rocks', methods=['GET', 'POST'])
def rocks():

    #get rules
    rocks = Rock.query.order_by(Rock.id.desc()).all()

    if len(rocks) > 0:
        return render_template('rocks.html', rocks=rocks)
    else:
        msg = 'No Data Found'
        return render_template('rocks.html', msg=msg)

#Rock registration form
class RockForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    phone = StringField('Phone', [validators.Length(min=4, max=25)])
    location = SelectField('Select a Location', choices=[(' ', ' '), ('Abia', 'Abia'), ('Adamawa', 'Adamawa'), ('Akwa Ibom', 'Akwa Ibom'), ('Anambra', 'Anambra'), ('Bauchi', 'Bauchi'), ('Bayelsa', 'Bayelsa'), ('Benue', 'Benue'), ('Borno', 'Borno'), ('Cross River', 'Cross River'), ('Delta', 'Delta'), ('Ebonyi', 'Ebonyi'), ('Enugu', 'Enugu'), ('Edo', 'Edo'), ('Ekiti', 'Ekiti'), ('FCT', 'FCT'), ('Gombe', 'Gombe'), ('Imo', 'Imo'), ('Jigawa', 'Jigawa'), ('Kaduna', 'Kaduna'), ('Kano', 'Kano'), ('Katsina', 'Katsina'), ('Kebbi', 'Kebbi'), ('Kogi', 'Kogi'), ('Kwara', 'Kwara'), ('Lagos', 'Lagos'), ('Nasarawa', 'Nasarawa'), ('Niger', 'Niger'), ('Ogun', 'Ogun'), ('Ondo', 'Ondo'), ('Osun', 'Osun'), ('Oyo', 'Oyo'), ('Plateau', 'Plateau'), ('Rivers', 'Rivers'), ('Sokoto', 'Sokoto'), ('Taraba', 'Taraba'), ('Yobe', 'Yobe'), ('Zamfara', 'Zamfara')], validators=[validators.DataRequired()] )
    ucs = FloatField('Uniaxial Compressive Strength', [validators.DataRequired()])
    acv = FloatField('Aggregate Crushing Value', [validators.DataRequired()])
    pl = FloatField('Point Load', [validators.DataRequired()])
    av = FloatField('Abrasion', [validators.DataRequired()])
    brit = FloatField('Brittleness', [validators.DataRequired()])
    bwi = FloatField('Bit Wear Index', [validators.DataRequired()])


@app.route('/delete_entry/<string:id>', methods=['POST'])
@is_logged_in
def delete_entry(id):

    rock = Rock.query.filter_by(id=id).one()
    db.session.delete(rock)
    db.session.commit()

    flash('Entry Deleted', 'success')

    return redirect(url_for('dashboard'))

@app.route('/delete_user/<string:id>', methods=['POST'])
@is_logged_in
def delete_user(id):

    user = Users.query.filter_by(id=id).one()
    db.session.delete(user)
    db.session.commit()

    flash('User Deleted', 'success')

    return redirect(url_for('users'))

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

        r_ucs = (-(ucs * 0.4247) + (91.464))
        r_bwi = (-(0.8828 * bwi) + (87.439))
        r_pl = (-(13.627 * pl) + (125.95))
        r_acv = ((2.7041 * acv) - (28.643))
        r_brit = ((0.971 * brit) - (14.581))
        r_av = ((1.2779 * av) - (7.6605))
        dri = round(((r_ucs + r_pl + r_bwi + r_av + r_acv + r_brit) / 6), 2)


        if dri > 82:
            dri_class = "Extremely High"
        elif 70 <= dri <= 82:
            dri_class = "Very High"
        elif 58 <= dri <= 69:
            dri_class = "High"
        elif 43 <= dri <= 57:
            dri_class = "Medium"
        elif 33 <= dri <= 42:
            dri_class = "Low"
        elif 26 <= dri <= 32:
            dri_class = "Very Low"
        elif 0 <= dri <= 25:
            dri_class = "Extremely Low"

        if ucs >= 250:
            ucs_class = "Very High"
        elif 100 <= ucs < 250:
            ucs_class = "High"
        elif 50 <= ucs < 100:
            ucs_class = "Moderate"
        elif 25 <= ucs < 50:
            ucs_class = "Medium"
        elif 5 <= ucs < 25:
            ucs_class = "Low"
        elif ucs < 5:
            ucs_class = "Very Low"

        if acv >= 50:
            acv_class = "Extremely High"
        elif 10 < acv <= 19.99:
            acv_class = "Very Low"
        elif 20 <= acv <= 29.99:
            acv_class = "Low"
        elif 30 <= acv <= 39.99:
            acv_class = "Medium"
        elif 40 <= acv <= 49.99:
            acv_class = "High"
        elif 1 <= acv <= 9.99:
            acv_class = "Extremely Low"

        if pl >= 7:
            pl_class = "Extremely High"
        elif 3 < pl <= 3.99:
            pl_class = "Very Low"
        elif 4 <= pl <= 4.99:
            pl_class = "Low"
        elif 5 <= pl <= 5.99:
            pl_class = "Medium"
        elif 6 <= pl <= 6.99:
            pl_class = "High"
        elif 1 <= pl <= 3:
            pl_class = "Extremely Low"

        if av >= 60:
            av_class = "Extremely High"
        elif 20 < av <= 29.99:
            av_class = "Very Low"
        elif 30 <= av <= 39.99:
            av_class = "Low"
        elif 40 <= av <= 49.99:
            av_class = "Medium"
        elif 50 <= av <= 59.99:
            av_class = "High"
        elif av <= 19.99:
            av_class = "Extremely Low"

        if brit >= 50:
            brit_class = "Extremely High"
        elif 10 < brit <= 19.99:
            brit_class = "Very Low"
        elif 20 <= brit <= 29.99:
            brit_class = "Low"
        elif 30 <= brit <= 39.99:
            brit_class = "Medium"
        elif 40 <= brit <= 49.99:
            brit_class = "High"
        elif 1 <= brit <= 9.99:
            brit_class = "Extremely Low"

        if bwi >= 50:
            bwi_class = "Extremely High"
        elif 10 < bwi <= 19.99:
            bwi_class = "Very Low"
        elif 20 <= bwi <= 29.99:
            bwi_class = "Low"
        elif 30 <= bwi <= 39.99:
            bwi_class = "Medium"
        elif 40 <= bwi <= 49.99:
            bwi_class = "High"
        elif 1 <= bwi <= 9.99:
            bwi_class = "Extremely Low"







        #insert into db
        rock = Rock(name=name, phone=phone, location=location, ucs=ucs, acv=acv, pl=pl, av=av, brit=brit, bwi=bwi, acv_class=acv_class, ucs_class=ucs_class, pl_class=pl_class, brit_class=brit_class, bwi_class=bwi_class, av_class=av_class, dri_class=dri_class, dri=dri, create_date=datetime.now().date())
        db.session.add(rock)
        db.session.commit()


        rock = Rock.query.order_by(Rock.id.desc()).first()

        id = rock.id

        return redirect(url_for('rock', id=id))

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
