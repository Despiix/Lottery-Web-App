# IMPORTS
import random
import secrets

from flask import Blueprint, render_template, flash, redirect, url_for
from sqlalchemy.orm import make_transient

from app import db
from models import User, Draw
from users.forms import RegisterForm
from flask_login import current_user, login_required
from users.views import requires_roles

# CONFIG
admin_blueprint = Blueprint('admin', __name__, template_folder='templates')


# VIEWS

@admin_blueprint.route('/admin_registration', methods=['GET', 'POST'])
@requires_roles('admin')
@login_required
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
            return render_template('admin/admin_registration.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='admin',
                        postcode=form.postcode.data,
                        dateOfBirth=form.dateOfBirth.data
                        )

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # sends user to login page
        return redirect(url_for('admin.admin'))
    # if request method is GET or form not valid re-render signup page
    return render_template('admin/admin_registration.html', form=form)


# view admin homepage
@admin_blueprint.route('/admin')
@requires_roles('admin')
@login_required
def admin():
    return render_template('admin/admin.html', name="PLACEHOLDER FOR FIRSTNAME")


# create a new winning draw
@admin_blueprint.route('/generate_winning_draw')
@requires_roles('admin')
@login_required
def generate_winning_draw():

    # get current winning draw
    current_winning_draw = Draw.query.filter_by(master_draw=True, user_id= current_user.id).first()
    lottery_round = 1

    # if a current winning draw exists
    if current_winning_draw:
        # update lottery round by 1
        lottery_round = current_winning_draw.lottery_round + 1

        # delete current winning draw
        db.session.delete(current_winning_draw)
        db.session.commit()

    # get new winning numbers for draw
    winning_numbers_string = ''
    winning_numbers_string = ' '.join(str(secrets.choice(range(1, 61))) for x in range(6))

    # create a new draw object.
    new_winning_draw = Draw(user_id=current_user.id, numbers=winning_numbers_string, master_draw=True,
                            lottery_round=lottery_round, public_key=current_user.public_key) # (..., postkey=current_user.postkey)

    # add the new winning draw to the database
    db.session.add(new_winning_draw)
    db.session.commit()

    # re-render admin page
    flash("New winning draw %s added." % winning_numbers_string)
    return redirect(url_for('admin.admin'))


# view current winning draw
@admin_blueprint.route('/view_winning_draw')
@requires_roles('admin')
@login_required
def view_winning_draw():

    # get winning draw from DB
    current_winning_draw = Draw.query.filter_by(master_draw=True,been_played=False).first()

    # if a winning draw exists
    if current_winning_draw:
        make_transient(current_winning_draw)
        current_winning_draw.numbers = current_winning_draw.view_draws(current_user.public_key) # view_draws(current_user.postkey)
        # re-render admin page with current winning draw and lottery round
        return render_template('admin/admin.html', winning_draw=current_winning_draw, name="PLACEHOLDER FOR FIRSTNAME")

    # if no winning draw exists, rerender admin page
    flash("No valid winning draw exists. Please add new winning draw.")
    return redirect(url_for('admin.admin'))


# view lottery results and winners
@admin_blueprint.route('/run_lottery')
@requires_roles('admin')
@login_required
def run_lottery():

    # get current un-played winning draw
    current_winning_draw = Draw.query.filter_by(master_draw=True, been_played=False).first()

    # if current un-played winning draw exists
    if current_winning_draw:

        # get all un-played user draws
        user_draws = Draw.query.filter_by(master_draw=False, been_played=False).all()
        results = []

        # if at least one un-played user draw exists
        if user_draws:

            # update current winning draw as played
            current_winning_draw.been_played = True
            db.session.add(current_winning_draw)
            db.session.commit()

            # for each un-played user draw
            for draw in user_draws:

                # get the owning user (instance/object)
                user = User.query.filter_by(id=draw.user_id).first()

                # if user draw matches current un-played winning draw
                if draw.numbers == current_winning_draw.numbers:

                    # add details of winner to list of results
                    results.append((current_winning_draw.lottery_round, draw.numbers, draw.user_id, user.email))

                    # update draw as a winning draw (this will be used to highlight winning draws in the user's
                    # lottery page)
                    draw.matches_master = True

                # update draw as played
                draw.been_played = True

                # SYMMETRIC ENCRYPTION
                # all draw numbers decrypted for matching against winning draw can remain decrypted in the database
                """
                draw.numbers = draw.view_draws(user.postkey)
                current_winning_draw.numbers = current_winning_draw.view_draws(current_user.postkey)
                """
                draw.numbers = draw.view_draws(user.private_key)
                current_winning_draw.numbers = current_winning_draw.view_draws(current_user.private_key)


                # update draw with current lottery round
                draw.lottery_round = current_winning_draw.lottery_round

                # commit draw changes to DB
                db.session.add(draw)
                db.session.commit()

            # if no winners
            if len(results) == 0:
                flash("No winners.")

            return render_template('admin/admin.html', results=results, name="PLACEHOLDER FOR FIRSTNAME")

        flash("No user draws entered.")
        return admin()

    # if current un-played winning draw does not exist
    flash("Current winning draw expired. Add new winning draw for next round.")
    return redirect(url_for('admin.admin'))


# view all registered users
@admin_blueprint.route('/view_all_users')
@requires_roles('admin')
@login_required
def view_all_users():
    current_users = User.query.filter_by(role='user').all()

    return render_template('admin/admin.html', name="PLACEHOLDER FOR FIRSTNAME", current_users=current_users)


# view last 10 log entries
@admin_blueprint.route('/logs')
@requires_roles('admin')
@login_required
def logs():
    with open("lottery.log", "r") as f:
        content = f.read().splitlines()[-10:]
        content.reverse()

    return render_template('admin/admin.html', logs=content, name="PLACEHOLDER FOR FIRSTNAME")

# View User Activity
@admin_blueprint.route('/view_user_activity', methods=['POST'])
@requires_roles('admin')
@login_required
def view_user_activity():

    current_users = User.query.filter_by(role='user').all()
    return render_template('admin/admin.html', name="PLACEHOLDER FOR FIRSTNAME", users=current_users)