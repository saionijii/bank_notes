import os
from datetime import timedelta
from flask import Flask, render_template, redirect, url_for, session, abort, flash, request
from models import db, Note, User
from forms import NoteForm, EditForm, DeleteForm, LoginForm, RegisterForm
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text

# Загрузка .env
load_dotenv()

# Глобальная CSRF защита
csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)

    # SECRET_KEY из окружения
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        raise RuntimeError("SECRET_KEY должен быть задан в окружении (.env)")

    # База данных
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///bank_notes.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Продакшн флаг
    is_production = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('FLASK_DEBUG', '0') == '0'

    # Сессии и cookie
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = True if is_production else False

    # Инициализация ORM и CSRF
    db.init_app(app)
    csrf.init_app(app)

    # --- Безопасные заголовки ---
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
        # CSP без inline-стилей/скриптов
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "media-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none';"
        )
        if is_production:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
        response.headers['Server'] = 'SecureServer'
        return response

    return app

# ---- Приложение ----
app = create_app()

with app.app_context():
    db.create_all()

# ---- Сессия ----
@app.before_request
def ensure_session():
    session.permanent = True
    if 'note_ids' not in session:
        session['note_ids'] = []

# ---- Маршруты ----
@app.route('/', methods=['GET', 'POST'])
def index():
    form = NoteForm()
    delete_form = DeleteForm()
    if form.validate_on_submit():
        title = form.title.data.strip()
        content = form.content.data.strip()
        note = Note(title=title, content=content)
        db.session.add(note)
        db.session.commit()
        note_ids = session.get('note_ids', [])
        note_ids.append(note.id)
        session['note_ids'] = note_ids
        flash('Заметка успешно создана', 'success')
        return redirect(url_for('index'))
    notes = Note.query.order_by(Note.created_at.desc()).all()
    return render_template('index.html', notes=notes, form=form, delete_form=delete_form)

@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note_id not in session.get('note_ids', []):
        abort(403)
    form = EditForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data.strip()
        note.content = form.content.data.strip()
        db.session.commit()
        flash('Заметка обновлена', 'success')
        return redirect(url_for('index'))
    return render_template('edit.html', form=form, note=note)

@app.route('/delete/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    form = DeleteForm()
    if not form.validate_on_submit():
        abort(400)
    note = Note.query.get_or_404(note_id)
    if note_id not in session.get('note_ids', []):
        abort(403)
    db.session.delete(note)
    db.session.commit()
    note_ids = session.get('note_ids', [])
    if note_id in note_ids:
        note_ids.remove(note_id)
        session['note_ids'] = note_ids
    flash('Заметка удалена', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже существует', 'error')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        user = User(username=username, password=hashed)
        db.session.add(user)
        db.session.commit()
        flash('Пользователь создан', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Успешный вход', 'success')
            return redirect(url_for('index'))
        flash('Неверные учетные данные', 'error')
    return render_template('login.html', form=form)

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

debug = os.environ.get('FLASK_DEBUG', '0') == '1'

if __name__ == '__main__':
    try:
        from waitress import serve
        if debug:
            print("Запуск Flask (dev)")
            app.run(debug=True)
        else:
            print("Запуск через waitress 0.0.0.0:5000")
            serve(app, host='0.0.0.0', port=5000)
    except Exception as e:
        print("Waitress не доступен, запуск через Flask:", e)
        app.run(debug=debug)

