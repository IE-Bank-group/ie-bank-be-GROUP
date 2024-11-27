from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from wtforms.meta import DefaultMeta

from iebank_api.models import User

class RegisterForm(FlaskForm):
    class Meta(DefaultMeta):
        csrf = False
    username = StringField(
        'username', validators=[DataRequired(),Length(min=3, max=20, message="Username must be between 3 and 20 characters.")]
    )
    password = PasswordField(
        "password", validators=[DataRequired(), Length(min=6, max=25)]
    )
    confirm = PasswordField(
        "Repeat password",
        validators=[
        DataRequired(),EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Register")
    
    def validate(self):
        initial_validation = super(RegisterForm, self).validate()
        if not initial_validation:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("Username already registered")
            return False
        if self.password.data != self.confirm.data:
            self.password.errors.append("Passwords must match")
            return False
        return True
    
    
class LoginForm(FlaskForm):
    class Meta(DefaultMeta):
        csrf = False
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])