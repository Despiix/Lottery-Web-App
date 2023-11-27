# IMPORTS
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import logout_user, login_user, current_user, login_required
from markupsafe import Markup
from datetime import datetime
from functools import wraps

from app import db, logging
from models import User
from users.forms import RegisterForm, LoginForm, ChangePassword
from templates import admin


# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')

# Access Control
def requires_roles(*role):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user or current_user.role not in role:
                # Log the unauthorized access attempt
                logging.warning(f'Unauthorized Access [%s, %s, %s, %s]',
                                current_user.id,
                                current_user.email,
                                current_user.role,
                                request.remote_addr)
                return render_template('error_handlers/403.html')
            return f(*args, **kwargs)
        return wrapped
    return wrapper

# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user',
                        postcode=form.postcode.data,
                        dateOfBirth=form.dateOfBirth.data
                        )

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        logging.warning('SECURITY - New User Registration [%s, %s]', form.email.data, request.remote_addr)

        session['email']= new_user.email

        # sends user to login page
        return redirect(url_for('users.setup_2fa'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)

@users_blueprint.route('/change password', methods=['GET', 'POST'])
@login_required
@requires_roles('user')
def change_password():
    form = ChangePassword()

    if form.validate_on_submit():

        # Verify current password
        if current_user.verify_password(form.current_password.data):

            if current_user.password != form.new_password.data:

                # Update user's password
                current_user.password = form.new_password.data
                db.session.commit()

                flash('Your password has been updated.')
                return redirect(url_for('users.account'))

            flash('New password cannot be the same as previous one')
            return render_template('users/change_password.html', form=form)

        flash('Current password is incorrect.')
        return render_template('users/change_password.html', form=form)

    return render_template('users/change_password.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.username.data).first()
        if not user or not user.verify_password(form.password.data) or not user.verify_post_code(form.postcode.data) or not user.verify_pin(form.auth_pin.data):
            logging.warning('SECURITY - LogIn Attempt [%s, %s]', form.username.data, request.remote_addr)
            session['authentication_attempts'] += 1
            if session.get('authentication_attempts') >= 3:
                flash(Markup('Number of incorrect login attempts exceeded.'
                             ' Please click <a href="/reset">here</a> to reset.'))
                return render_template('users/login.html')
            attempts_remaining = 3 - session.get('authentication_attempts')
            flash('Please check your login details and try again, '
                  '{} login attempts remaining'.format(3 - session.get('authentication_attempts')))
            return render_template('users/login.html', form=form)
        login_user(user)
        current_user.successfulLogins = 0
        logging.warning('SECURITY - New LogIn [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)
        current_user.prevLoginDateTime = current_user.logInDateTime
        current_user.logInDateTime = datetime.now()
        current_user.ipLast = current_user.ipCurrent
        current_user.ipCurrent = request.remote_addr
        current_user.successfulLogins += 1
        db.session.commit()
        if current_user.role != 'admin':
            return redirect(url_for('lottery.lottery'))
        else:
            return redirect(url_for('admin.admin'))
    return render_template('users/login.html', form=form)

@users_blueprint.route('/logout')
@login_required
@requires_roles('user', 'admin')
def logout():
    logging.warning('SECURITY - User Log Out [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)
    logout_user()
    return redirect(url_for('index'))

# view user account
@users_blueprint.route('/account')
@login_required
@requires_roles('user', 'admin')
def account():
    return render_template('users/account.html',
                           acc_no="PLACEHOLDER FOR USER ID",
                           email="PLACEHOLDER FOR USER EMAIL",
                           firstname="PLACEHOLDER FOR USER FIRSTNAME",
                           lastname="PLACEHOLDER FOR USER LASTNAME",
                           phone="PLACEHOLDER FOR USER PHONE",
                           postcode="PLACEHOLDER FOR POST CODE",
                           dateOfBirth="PLACEHOLDER FOR DATE OF BIRTH")

@users_blueprint.route('/setup_2fa')
def setup_2fa():
    # Check if username is in the app session
    if 'email' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('index'))

    del session['email']

    return render_template('users/setup_2fa.html', email=user.email, uri=user.get_2fa_uri())

@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))