from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
from extensions import db
from models import User, Monument


def create_app():
    app = Flask(__name__)
    app.secret_key = 'your-secret-key'
    db_user = os.getenv("DB_USERNAME", "db_name")
    db_name = os.getenv("DB_NAME", "st_backend")
    db_pass = os.getenv("DB_PASSWORD", "abdj24AfwF#$1cw#4fq3d")
    db_host = os.getenv("DB_HOST", "localhost")

    # Configure the SQLAlchemy database URI
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_pass}@{db_host}/{db_name}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('monuments'))
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            login = request.form.get('login')
            password = request.form.get('password')
            existing_user = User.query.filter_by(login=login).first()
            if existing_user:
                flash('Username already exists', 'danger')
                return redirect(url_for('register'))
            new_user = User(login=login, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            login = request.form.get('login')
            password = request.form.get('password')
            user = User.query.filter_by(login=login, password=password).first()
            if user:
                session['user_id'] = user.id
                return redirect(url_for('monuments'))
            else:
                flash('Invalid login credentials', 'danger')
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        return redirect(url_for('login'))

    @app.route('/monuments', methods=['GET', 'POST'])
    def monuments():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if request.method == 'POST':
            selected_city = request.form.get('city')
            monuments = Monument.query.filter_by(city=selected_city).all()
        else:
            monuments = []
        cities = db.session.query(Monument.city).distinct().order_by(Monument.city).all()
        return render_template('monuments.html', monuments=monuments, cities=cities)

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
