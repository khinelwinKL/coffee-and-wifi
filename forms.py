from flask_wtf import FlaskForm
from wtforms.fields import StringField, SelectField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email


class CafeForm(FlaskForm):
    name = StringField("Cafe Name", validators=[DataRequired()])
    map_url = StringField("Cafe Location Link", validators=[DataRequired(), URL()])
    img_url = StringField("Image Link", validators=[DataRequired(), URL()])
    location = StringField("Cafe Location", validators=[DataRequired()])
    has_sockets = SelectField("Power Socket Availability",
                              choices=[("0", "❌"), ("1", "🔌")],
                              validators=[DataRequired()])
    has_toilet = SelectField("Toilet Availability",
                             choices=[("0", "Nope"), ("1", "Yes")],
                             validators=[DataRequired()])
    has_wifi = SelectField("Wifi Availability",
                           choices=[("0", "❌"), ("1", "💪️")],
                           validators=[DataRequired()])
    can_take_calls = SelectField("Can Take Calls?",
                                 choices=[("0", "Nope"), ("1", "Yes")],
                                 validators=[DataRequired()])
    seats = StringField("Number of Seats", validators=[DataRequired()])
    coffee_price = StringField("Coffee Price", validators=[DataRequired()])
    submit = SubmitField("Done")


class CommentForm(FlaskForm):
    comment_text = StringField("Enter your comment", validators=[DataRequired()])
    submit = SubmitField("Post Comment")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    name = StringField("Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField('Login')