import os

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY').replace('postgres', 'postgresql')
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=200,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None,
                    )

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")


##LOGIN AND DB
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False


login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


##ADMIN ACCESS
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            logout_user()
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html",
                           all_posts=posts,
                           current_user=current_user,
                           )


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_user = User(
            email=register_form.email.data,
            password=generate_password_hash(register_form.password.data,
                                            salt_length=8,
                                            ),
            name=register_form.name.data,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html",
                           form=register_form,
                           current_user=current_user,
                           )


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        form_email = login_form.email.data
        form_password = login_form.password.data
        user_to_login = db.session.query(User).filter_by(email=form_email).first()
        if user_to_login is not None:
            if check_password_hash(user_to_login.password, form_password):
                login_user(user_to_login)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Wrong password')
        else:
            flash(f'There is no {form_email} user registered'
                  f'Follow registration process for that ({url_for("register")})')
    return render_template("login.html",
                           form=login_form,
                           current_user=current_user,
                           )


@app.route('/logout')
def logout():
    print(current_user.is_authenticated)
    current_user.is_logged = False
    logout_user()
    print(current_user.is_authenticated)
    return redirect(url_for('get_all_posts',
                            current_user=current_user,
                            ))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.session.get(BlogPost, post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Authorization required')
            return redirect(url_for('login'))
        db.session.add(Comment(
            text=comment_form.body.data,
            comment_author=current_user,
            parent_post=db.session.get(BlogPost, post_id),
        ))
        print('added')
        db.session.commit()
    comments = db.session.query(Comment).all()
    return render_template("post.html",
                           post=requested_post,
                           comment_form=comment_form,
                           comments=comments,
                           current_user=current_user,
                           )


@app.route("/about")
def about():
    return render_template("about.html",
                           current_user=current_user,
                           )


@app.route("/contact")
def contact():
    return render_template("contact.html",
                           current_user=current_user,
                           )


@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        with app.app_context():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=str(date.today().strftime("%B %d, %Y"))
            )
            db.session.add(new_post)
            db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html",
                           form=form,
                           current_user=current_user,
                           )


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    post = db.session.get(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html",
                           form=edit_form,
                           current_user=current_user,
                           )


@app.route("/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post_to_delete = db.session.get(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts',
                            current_user=current_user,
                            ))


if __name__ == "__main__":
    app.run(host='127.0.0.1',
            port=5000,
            debug=True,
            )
