from flask_app import app
from flask import render_template, redirect, flash, session, request
from .. models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)


@app.route('/')
def show_form():
    return render_template('form.html')


@app.route('/register', methods=['post'])
def register():
    if not User.validate_register(request.form):
        return redirect('/')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': pw_hash
    }
    user_id = User.create_user(data)
    session['user_id'] = user_id
    return redirect('/dashboard')


@app.route('/login', methods=['post'])
def login():
    if not User.validate_login(request.form):
        return redirect('/')

    data = {
        'email': request.form['email']
    }
    user1 = User.get_user_email(data)
    if not user1:
        flash('invalid email/password')
        return redirect('/')
    if not bcrypt.check_password_hash(user1.password, request.form['password']):
        return redirect('/')

    session['user_id'] = user1.id

    return redirect('/dashboard')


@app.route('/logout', methods=['post'])
def logout():
    session.clear()
    return redirect('/')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')

    data = {
        'id': session["user_id"]
    }
    return render_template('dashboard.html', logged_user=User.get_user_id(data))
