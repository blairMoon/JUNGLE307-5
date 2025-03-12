from flask import Blueprint, render_template

routes = Blueprint('routes', __name__)

@app.route("/")
def home():
    return render_template("login.html", title="week00", message="MainPage")

# @routes.route('/register')
# def register_render():
#     return render_template('register.html')