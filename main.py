from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from sqlalchemy.orm import relationship
from forms import CafeForm, CommentForm, RegisterForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
bootstrap = Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes_list.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


gravatar = Gravatar(app,
                    size=50,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


class Cafe(db.Model):
    __tablename__ = "cafes"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    map_url = db.Column(db.String(700), nullable=False)
    img_url = db.Column(db.String(700), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    seats = db.Column(db.String(255), nullable=False)
    coffee_price = db.Column(db.String(255), nullable=False)

    comments = relationship("Comment", back_populates="cafe")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    comment = relationship("Comment", back_populates="user")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment_text = db.Column(db.String(500), nullable=False)

    cafe_id = db.Column(db.Integer, db.ForeignKey("cafes.id"))
    cafe = relationship("Cafe", back_populates="comments")

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = relationship("User", back_populates="comment")


# db.create_all()


def boolean_converter(bool_value):
    if bool_value == "1":
        return bool(bool_value)
    else:
        return 0


def get_boolean_value(saved_bool):
    if saved_bool == 1:
        return "1"
    else:
        return "0"


def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        else:
            return func(*args, **kwargs)
    return decorated_function


@app.route("/")
def home():
    return render_template("index.html", current_user=current_user)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            flash("User already exists. Please try login instead.")
            return redirect(url_for("login"))
        else:
            salted_and_hash_password = generate_password_hash(
                password=form.password.data,
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                email=form.email.data,
                name=form.name.data,
                password=salted_and_hash_password
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("all_cafes"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This user doesn't exist. Please register first.")
            return redirect(url_for("register"))
        elif not check_password_hash(user.password, password):
            flash("Incorrect password. Please retry again.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("all_cafes"))
    return render_template("login.html", form=form, current_user=current_user)


@app.route("/all-cafes")
def all_cafes():
    cafes = Cafe.query.all()
    return render_template("cafes.html", all_cafes=cafes, current_user=current_user)


@app.route("/cafe/<int:cafe_id>", methods=["GET", "POST"])
def get_cafe_detail(cafe_id):
    cafe = Cafe.query.get(cafe_id)
    return render_template("cafe_detail.html", cafe=cafe, cafe_detail=True, current_user=current_user)


@login_required
@app.route("/comment/<int:cafe_id>", methods=["GET", "POST"])
def comment(cafe_id):
    if current_user.is_authenticated:
        cafe = Cafe.query.get(cafe_id)
        comment_form = CommentForm()
        if comment_form.validate_on_submit():
            new_comment = Comment(
                comment_text=comment_form.comment_text.data,
                user=current_user,
                cafe=cafe
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("get_cafe_detail", cafe_id=cafe.id))
        return render_template("comment.html", cafe=cafe, form=comment_form, cafe_detail=True, current_user=current_user)
    else:
        flash("You need to login to leave a comment.")
        return redirect(url_for("login"))


@login_required
@app.route("/add-cafe", methods=["GET", "POST"])
def add_new_cafe():
    if current_user.is_authenticated:
        form = CafeForm()
        if form.validate_on_submit():
            new_cafe = Cafe(
                name=form.name.data,
                map_url=form.map_url.data,
                img_url=form.img_url.data,
                location=form.location.data,
                has_sockets=boolean_converter(form.has_sockets.data),
                has_toilet=boolean_converter(form.has_toilet.data),
                has_wifi=boolean_converter(form.has_wifi.data),
                can_take_calls=boolean_converter(form.can_take_calls.data),
                seats=form.seats.data,
                coffee_price=form.coffee_price.data
            )
            db.session.add(new_cafe)
            db.session.commit()
            return redirect(url_for("all_cafes"))
        return render_template("add_cafe.html", form=form, current_user=current_user)
    else:
        flash("You need to login to add a new cafe.")
        return redirect(url_for("login"))


@login_required
@app.route("/update-cafe/<int:cafe_id>", methods=["GET", "POST"])
def update_cafe(cafe_id):
    if current_user.is_authenticated:
        cafe = Cafe.query.get(cafe_id)
        update_form = CafeForm(
            name=cafe.name,
            map_url=cafe.map_url,
            img_url=cafe.img_url,
            location=cafe.location,
            has_sockets=get_boolean_value(cafe.has_sockets),
            has_toilet=get_boolean_value(cafe.has_toilet),
            has_wifi=get_boolean_value(cafe.has_wifi),
            can_take_calls=get_boolean_value(cafe.can_take_calls),
            seats=cafe.seats,
            coffee_price=cafe.coffee_price
        )
        if update_form.validate_on_submit():
            cafe.name = update_form.name.data
            cafe.map_url = update_form.map_url.data
            cafe.img_url = update_form.img_url.data
            cafe.location = update_form.location.data
            cafe.has_sockets = boolean_converter(update_form.has_sockets.data)
            cafe.has_toilet = boolean_converter(update_form.has_toilet.data)
            cafe.has_wifi = boolean_converter(update_form.has_wifi.data)
            cafe.can_take_calls = boolean_converter(update_form.can_take_calls.data)
            cafe.seats = update_form.seats.data
            cafe.coffee_price = update_form.coffee_price.data
            db.session.commit()
            return redirect(url_for("get_cafe_detail", cafe_id=cafe.id))
        return render_template("add_cafe.html", form=update_form, update=True, current_user=current_user)
    else:
        flash("You need to login to update the cafe features.")
        return redirect(url_for("login"))


@login_required
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("all_cafes"))


@login_required
@admin_only
@app.route("/delete-cafe/<int:cafe_id>")
def delete_cafe(cafe_id):
    cafe_to_delete = Cafe.query.get(cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for("all_cafes", current_user=current_user))


if __name__ == "__main__":
    app.run(debug=True)