# app.py - Main application file

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
import os
from PIL import Image
import secrets
import uuid
from flask_mail import Mail, Message

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///photoshare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['PROFILE_PICS'] = 'static/profile_pics'

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER', '')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER', '')

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROFILE_PICS'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
migrate = Migrate(app, db)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Models
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    photos = db.relationship('Photo', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)
            return self

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)
            return self

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def followed_photos(self):
        return Photo.query.join(followers, (followers.c.followed_id == Photo.user_id)).filter(
            followers.c.follower_id == self.id).order_by(Photo.date_posted.desc())

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_file = db.Column(db.String(100), nullable=False)
    caption = db.Column(db.Text)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='photo', lazy=True, cascade="all, delete")
    likes = db.relationship('Like', backref='photo', lazy=True, cascade="all, delete")

    def __repr__(self):
        return f"Photo('{self.image_file}', '{self.date_posted}')"

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'), nullable=False)

    def __repr__(self):
        return f"Comment('{self.content}', '{self.date_posted}')"

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey('photo.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'photo_id'),)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    
    def validate_password(self, password):
        """Validate password strength."""
        if not any(char.isdigit() for char in password.data):
            raise ValidationError('Password must contain at least one number.')
        if not any(char.isupper() for char in password.data):
            raise ValidationError('Password must contain at least one uppercase letter.')

    def validate_username(self, username):
        # Case-insensitive username check
        user = User.query.filter(User.username.ilike(username.data)).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please choose a different one or login.')

from wtforms import StringField, PasswordField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data.lower()).first()
            if user:
                raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is already registered. Please choose a different one.')

class PhotoForm(FlaskForm):
    picture = FileField('Upload Photo', validators=[DataRequired(), FileAllowed(['jpg', 'png', 'jpeg'])])
    caption = TextAreaField('Caption')
    submit = SubmitField('Post')

class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post')

class SearchForm(FlaskForm):
    search = StringField('Search', validators=[DataRequired()])
    submit = SubmitField('Search')

# Helper functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def save_picture(form_picture, folder):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, folder, picture_fn)
    
    # Resize image
    output_size = (800, 800)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return picture_fn

def generate_confirmation_token(email):
    return s.dumps(email, salt='email-confirm')

def confirm_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='email-confirm', max_age=expiration)
        return email
    except:
        return False

def send_confirmation_email(user):
    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Please confirm your email"
    html = render_template('activate.html', confirm_url=confirm_url)
    msg = Message(subject=subject, recipients=[user.email], html=html)
    mail.send(msg)

# Routes
@app.route("/")
@app.route("/home")
def home():
    if current_user.is_authenticated:
        photos = current_user.followed_photos().all()
        # Add own photos to feed
        own_photos = Photo.query.filter_by(user_id=current_user.id).all()
        photos = list(set(photos + own_photos))
        photos.sort(key=lambda x: x.date_posted, reverse=True)
    else:
        photos = Photo.query.order_by(Photo.date_posted.desc()).all()
    return render_template('home.html', photos=photos, title='Home')

@app.route("/explore")
def explore():
    photos = Photo.query.order_by(Photo.date_posted.desc()).all()
    return render_template('explore.html', photos=photos, title='Explore')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data.lower(), email=form.email.data, password=hashed_password, confirmed=False)
        db.session.add(user)
        db.session.commit()
        
        # Send confirmation email
        try:
            send_confirmation_email(user)
            flash('A confirmation email has been sent to your email address. Please check your inbox.', 'info')
        except Exception as e:
            flash('Could not send confirmation email. Please contact support.', 'warning')
            app.logger.error(f"Email sending error: {str(e)}")
            
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data, app.config['PROFILE_PICS'])
            # Delete old profile picture if not default
            if current_user.image_file != 'default.jpg':
                old_file = os.path.join(app.root_path, app.config['PROFILE_PICS'], current_user.image_file)
                if os.path.exists(old_file):
                    os.remove(old_file)
            current_user.image_file = picture_file
        current_user.username = form.username.data.lower()
        current_user.email = form.email.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    photos = Photo.query.filter_by(user_id=current_user.id).order_by(Photo.date_posted.desc()).all()
    return render_template('profile.html', title='Profile', image_file=image_file, form=form, photos=photos)

@app.route("/user/<string:username>")
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    photos = Photo.query.filter_by(user_id=user.id).order_by(Photo.date_posted.desc()).all()
    image_file = url_for('static', filename='profile_pics/' + user.image_file)
    is_following = False
    if current_user.is_authenticated:
        is_following = current_user.is_following(user)
    return render_template('user_profile.html', title=username, user=user, photos=photos, 
                          image_file=image_file, is_following=is_following)

@app.route("/photo/new", methods=['GET', 'POST'])
@login_required
def new_photo():
    form = PhotoForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data, app.config['UPLOAD_FOLDER'])
            photo = Photo(image_file=picture_file, caption=form.caption.data, author=current_user)
            db.session.add(photo)
            db.session.commit()
            flash('Your photo has been posted!', 'success')
            return redirect(url_for('home'))
    return render_template('create_photo.html', title='New Photo', form=form)

@app.route("/photo/<int:photo_id>", methods=['GET', 'POST'])
def photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    form = CommentForm()
    
    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment = Comment(content=form.content.data, author=current_user, photo=photo)
            db.session.add(comment)
            db.session.commit()
            flash('Your comment has been posted!', 'success')
            return redirect(url_for('photo', photo_id=photo.id))
        else:
            flash('You need to login to comment.', 'info')
            return redirect(url_for('login'))
            
    comments = Comment.query.filter_by(photo_id=photo.id).order_by(Comment.date_posted.desc()).all()
    likes_count = Like.query.filter_by(photo_id=photo.id).count()
    has_liked = False
    if current_user.is_authenticated:
        has_liked = Like.query.filter_by(user_id=current_user.id, photo_id=photo.id).first() is not None
    
    return render_template('photo.html', title=f"Photo by {photo.author.username}", 
                          photo=photo, comments=comments, form=form, likes_count=likes_count, 
                          has_liked=has_liked)

@app.route("/photo/<int:photo_id>/delete", methods=['POST'])
@login_required
def delete_photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    if photo.author != current_user:
        abort(403)
    # Delete the image file from the filesystem
    photo_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], photo.image_file)
    if os.path.exists(photo_path):
        os.remove(photo_path)
    db.session.delete(photo)
    db.session.commit()
    flash('Your photo has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route("/photo/<int:photo_id>/like", methods=['POST'])
@login_required
def like_photo(photo_id):
    photo = Photo.query.get_or_404(photo_id)
    like = Like.query.filter_by(user_id=current_user.id, photo_id=photo.id).first()
    
    if like:
        db.session.delete(like)
        db.session.commit()
    else:
        like = Like(user_id=current_user.id, photo_id=photo.id)
        db.session.add(like)
        db.session.commit()
        
    return redirect(request.referrer or url_for('photo', photo_id=photo.id))

@app.route("/follow/<int:user_id>", methods=['POST'])
@login_required
def follow(user_id):
    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash('You cannot follow yourself!', 'danger')
        return redirect(url_for('user_profile', username=user.username))
    
    current_user.follow(user)
    db.session.commit()
    flash(f'You are now following {user.username}!', 'success')
    return redirect(url_for('user_profile', username=user.username))

@app.route("/unfollow/<int:user_id>", methods=['POST'])
@login_required
def unfollow(user_id):
    user = User.query.get_or_404(user_id)
    if user == current_user:
        flash('You cannot unfollow yourself!', 'danger')
        return redirect(url_for('user_profile', username=user.username))
    
    current_user.unfollow(user)
    db.session.commit()
    flash(f'You have unfollowed {user.username}.', 'info')
    return redirect(url_for('user_profile', username=user.username))

@app.route("/search", methods=['GET', 'POST'])
def search():
    form = SearchForm()
    results = []
    
    if form.validate_on_submit() or request.args.get('search'):
        search_term = form.search.data or request.args.get('search')
        results = User.query.filter(User.username.ilike(f'%{search_term}%')).all()
    
    return render_template('search.html', title='Search', form=form, results=results)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
        
        if not email:
            flash('The confirmation link is invalid or has expired.', 'danger')
            return redirect(url_for('login'))
            
        user = User.query.filter_by(email=email).first_or_404()
        
        if user.confirmed:
            flash('Account already confirmed. Please login.', 'success')
        else:
            user.confirmed = True
            user.confirmed_on = datetime.utcnow()
            db.session.add(user)
            db.session.commit()
            flash('You have confirmed your account. Thanks!', 'success')
            
        return redirect(url_for('login'))
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))


    return render_template('search.html', title='Search', form=form, results=results)

# Create database tables
with app.app_context():
    # If using Flask-Migrate, don't call db.create_all()
    # Instead, use the migration commands:
    # flask db init (first time)
    # flask db migrate -m "Initial migration"
    # flask db upgrade
    # But for simplicity, we'll keep this for now:
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
