# IMPORTS
from flask import Blueprint, render_template, flash, redirect, url_for
from app import db
from lottery.forms import DrawForm
from models import Draw
from flask_login import current_user, login_required
from users.views import requires_roles
from sqlalchemy.orm import make_transient

# CONFIG
lottery_blueprint = Blueprint('lottery', __name__, template_folder='templates')


# VIEWS
# view lottery page
@lottery_blueprint.route('/lottery')
@requires_roles('user')
@login_required
def lottery():
    return render_template('lottery/lottery.html', name="PLACEHOLDER FOR FIRSTNAME")


# view all draws that have not been played
@lottery_blueprint.route('/create_draw', methods=['POST'])
@login_required
@requires_roles('user')
def create_draw():
    form = DrawForm()

    if form.validate_on_submit():
        submitted_numbers = (str(form.number1.data) + ' '
                          + str(form.number2.data) + ' '
                          + str(form.number3.data) + ' '
                          + str(form.number4.data) + ' '
                          + str(form.number5.data) + ' '
                          + str(form.number6.data))
        draw_numbers = submitted_numbers.split(' ')
        for i in draw_numbers:
            if int(i) < 1 or int(i) > 60:
                flash("The numbers must be between 1 and 60")
                return render_template('lottery/lottery.html', form=form)

        # Each number must be unique
        if len(draw_numbers) != len(set(draw_numbers)):
            flash('Each number must be unique')
            return render_template('lottery/lottery.html', form=form)
        # create a new draw with the form data.
        new_draw = Draw(user_id=current_user.id, numbers=submitted_numbers, master_draw=False,
                        lottery_round=0, public_key=current_user.public_key) # (..., postkey=current_user.postkey)
        # add the new draw to the database
        db.session.add(new_draw)
        db.session.commit()

        # re-render lottery.page
        flash('Draw %s submitted.' % submitted_numbers)
        return redirect(url_for('lottery.lottery'))
    flash("You must enter 6 numbers!")
    return render_template('lottery/lottery.html', name="PLACEHOLDER FOR FIRSTNAME", form=form)


# view all draws that have not been played
@lottery_blueprint.route('/view_draws', methods=['POST'])
@requires_roles('user')
@login_required
def view_draws():
    # get all draws that have not been played [played=0]
    playable_draws = Draw.query.filter_by(been_played=False, user_id=current_user.id).all()

    for draw in playable_draws:
        make_transient(draw)
        # Uses the current user's post key to decrypt the data
        draw.numbers = draw.view_draws(current_user.public_key) # (current_user.postkey)

    # if playable draws exist
    if len(playable_draws) != 0:
        # re-render lottery page with playable draws
        return render_template('lottery/lottery.html', playable_draws=playable_draws)
    else:
        flash('No playable draws.')
        return lottery()


# view lottery results
@lottery_blueprint.route('/check_draws', methods=['POST'])
@requires_roles('user')
@login_required
def check_draws():
    # get played draws
    played_draws = Draw.query.filter_by(been_played=True, user_id=current_user.id).all()

    # if played draws exist
    if len(played_draws) != 0:
        return render_template('lottery/lottery.html', results=played_draws, played=True)

    # if no played draws exist [all draw entries have been played therefore wait for next lottery round]
    else:
        flash("Next round of lottery yet to play. Check you have playable draws.")
        return lottery()


# delete all played draws
@lottery_blueprint.route('/play_again', methods=['POST'])
@requires_roles('user')
@login_required
def play_again():
    Draw.query.filter_by(been_played=True, master_draw=False).delete(synchronize_session=False)
    db.session.commit()

    flash("All played draws deleted.")
    return lottery()


