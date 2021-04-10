from flask import Flask, render_template, redirect, request, url_for, flash
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_url_path='/static')

db = SQLAlchemy()

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


class Feedback(db.Model):
    game_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, primary_key=True)
    feedback = db.Column(db.String(1000))
    rating = db.Column(db.Integer)


@app.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()
    if user:
        return redirect(url_for('login', error="Email id already exists."))

    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))


@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')

    print(email, password, generate_password_hash(password, method='sha256'))

    user = User.query.filter_by(email=email).first()
    print(user.email, user.name, user.password)
    if not user or not check_password_hash(user.password, password):
        return redirect(url_for('login', error='Please check your login details and try again.'))

    login_user(user)
    return redirect(url_for('home'))


@app.route('/feedback', methods=['POST'])
def feedback_post():
    if current_user is None or not hasattr(current_user, 'name'):
        return redirect(url_for('login', error='Login to give feedback'))

    game_id = request.form.get('id')
    feedback_text = request.form.get('feedback')
    user_id = current_user.id
    rating = 0

    new_feedback = Feedback(game_id=game_id, user_id=user_id, feedback=feedback_text, rating=rating)
    db.session.add(new_feedback)
    db.session.commit()

    return redirect(url_for('feedback'))


@app.route('/')
@app.route('/home')
def home():
    if current_user is None or not hasattr(current_user, 'name'):
        return render_template('index-2.html', name='')

    return render_template('index-2.html', name=current_user.name)


@app.route('/login')
def login():
    if current_user is not None and hasattr(current_user, 'name'):
        return redirect(url_for('home'))

    error = request.args.get('error')
    if error is None:
        error = ''
    return render_template('login.html', error=error)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/feedback')
def feedback():
    if current_user is None or not hasattr(current_user, 'name'):
        return redirect(url_for('login', error='Login to give feedback'))

    feedbacks = Feedback.query.all()

    details = []

    for f in feedbacks:
        print(f.game_id, f.user_id, f.feedback)
        details.append({
            'user': User.query.filter_by(id=f.user_id).first().name,
            'game': f.game_id,
            'link': f.game_id.replace(' ', ''),
            'feedback': f.feedback
        })

    return render_template('Feedback.html', feedbacks=reversed(details))


@app.route('/games/<game>')
def run_game(game):
    return render_template('/games/' + game + '/index.html', game=game)


app.run()
