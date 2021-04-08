from flask import Flask, render_template, send_from_directory
from flask_login import login_required, LoginManager

app = Flask(__name__, static_url_path='/static')


@app.route('/')
def hello_world():
    return render_template('index-2.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/feedback')
def feedback():
    return render_template('Feedback.html')


@app.route('/games/<game>')
def run_game(game):
    return render_template('/games/' + game + '/index.html', game=game)


app.run()
