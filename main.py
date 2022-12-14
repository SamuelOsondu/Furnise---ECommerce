import os
import random
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, abort, g
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, EmailField, TextAreaField
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import DataRequired, URL
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'static/item_image'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'pass'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///users.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
Bootstrap(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class SignUp(FlaskForm):
    id = db.Column(db.Integer, primary_key=True)
    name = StringField('Full Name', validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField('Submit')


class AddItem(FlaskForm):

    id = db.Column(db.Integer, primary_key=True)
    item_name = StringField('Item Name', validators=[DataRequired()])
    amount = StringField('Amount', validators=[DataRequired()])
    item_description = TextAreaField('Item Description', render_kw={"rows": 10, "cols": 11}, validators=[DataRequired()])
    file = FileField('File', validators=[FileRequired()])
    submit = SubmitField('Add Item')


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    items = relationship("Item", back_populates="user_item")

    cart = relationship("Cart", back_populates="user_cart")


class Item(db.Model):
    __tablename__ = "items"
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(250),  nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    item_description = db.Column(db.String(100), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    user_item = relationship("User", back_populates="items")


class Cart(db.Model):
    __tablename__ = "cart"
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(250), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    user_cart = relationship("User", back_populates="cart")


db.create_all()


@app.route("/")
def home():
    all_items = db.session.query(Item).all()
    display = random.sample(all_items, 3)
    return render_template("index.html", items=display, logged_in=current_user.is_authenticated)


@app.route("/sign_up", methods=['GET', 'POST'])
def sign_up():
    signup_form = SignUp()

    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(request.form.get('password'),
                                                          method='pbkdf2:sha256', salt_length=8)

        new_user = User(
            name=signup_form.name.data,
            email=signup_form.email.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for("home"))
    return render_template('sign_up.html', form=signup_form, logged_in=current_user.is_authenticated)


@app.route("/login", methods=['GET', 'POST'])
def login():
    signup_form = SignUp()
    if request.method == "POST":

        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        # Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for('home'))

    return render_template('login.html', form=signup_form, logged_in=current_user.is_authenticated)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/add_item", methods=["GET", "POST"])
@login_required
@admin_only
def add_item():
    form = AddItem()
    item_name = request.form.get('item_name')
    amount = request.form.get('amount')
    description = request.form.get('item_description')

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files.get('file')
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            new_item = Item(
                item_name=item_name,
                amount=amount,
                img_url=file_path,
                item_description=description,
            )
            db.session.add(new_item)
            db.session.commit()
            return redirect(url_for('shop'))
    return render_template("add_item.html", form=form, current_user=current_user)


@app.route("/delete_cart_item")
@login_required
@admin_only
def delete_cart_item():
    cart_item_id = request.args.get('id')
    cart_item_to_delete = Cart.query.get(cart_item_id)
    db.session.delete(cart_item_to_delete)
    db.session.commit()
    return redirect(url_for('cart'))


@app.route("/delete_item")
@login_required
@admin_only
def delete_item():
    item_id = request.args.get('id')
    item_to_delete = Item.query.get(item_id)
    db.session.delete(item_to_delete)
    db.session.commit()
    return redirect(url_for('shop'))


@app.route("/item",  methods=["GET", "POST"])
def individual_item():
    item_id = request.args.get('id')
    item_clicked = Item.query.get(item_id)

    return render_template("individual_item.html", item=item_clicked, current_user=current_user,
                           logged_in=current_user.is_authenticated)


@app.route("/cart", methods=["GET", "POST"])
@login_required
def cart():
    all_items_in_cart = db.session.query(Cart).all()

    price_list = []
    for each_item in all_items_in_cart:
        each_price = each_item.amount
        price_int = float(each_price.replace("$", ""))
        price_list.append(price_int)
    total_amount = sum(price_list)

    # Add the calculations
    # Integrate stripe

    if request.method == "POST":
        item_id = request.args.get('id')
        item_clicked = Item.query.get(item_id)
        add_to_cart = Cart(
            item_name=item_clicked.item_name,
            amount=item_clicked.amount,
            img_url=item_clicked.img_url,
        )
        db.session.add(add_to_cart)
        db.session.commit()
        return redirect(request.url)

    return render_template("cart.html", items_added=all_items_in_cart, current_user=current_user,
                           logged_in=current_user.is_authenticated, total_amount=total_amount)


@app.route("/payment")
@login_required
def make_payment():
    user_email = current_user.email
    total_amount = request.args.get('total_amount')

    return render_template("payment.html", total_amount=total_amount)


@app.route("/thank_you")
@login_required
def thank_you():
    transaction = request.args.get('transaction')
    return render_template("thank_you.html", status=transaction)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/shop")
def shop():
    all_items = db.session.query(Item).all()
    return render_template("shop.html", items=all_items, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True, threaded=True)
