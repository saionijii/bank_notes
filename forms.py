from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length

class NoteForm(FlaskForm):
    # Валидация заголовка и содержания заметки
    title = StringField('Заголовок', validators=[
        DataRequired(message="Поле обязательно"),  # Не допускаем пустое значение
        Length(max=100, message="Максимум 100 символов")  # Ограничение длины
    ])
    content = TextAreaField('Содержание', validators=[
        DataRequired(message="Поле обязательно"),
        Length(max=2000, message="Максимум 2000 символов")
    ])
    submit = SubmitField('Сохранить')  # CSRF токен встроен через FlaskForm

class EditForm(FlaskForm):
    # Форма редактирования с аналогичными ограничениями
    title = StringField('Заголовок', validators=[
        DataRequired(message="Поле обязательно"),
        Length(max=100, message="Максимум 100 символов")
    ])
    content = TextAreaField('Содержимое', validators=[
        DataRequired(message="Поле обязательно"),
        Length(max=2000, message="Максимум 2000 символов")
    ])
    submit = SubmitField('Сохранить')

class DeleteForm(FlaskForm):
    # Минимальная форма для удаления с CSRF защитой
    submit = SubmitField('Удалить')

class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(max=150)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=4, max=200)])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')