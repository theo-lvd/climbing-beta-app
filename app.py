import os
from flask import Flask, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf.file import FileField, FileAllowed
from flask import request
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, FloatField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from thefuzz import fuzz


# --- App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-secret-key-you-should-change'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads' # Folder for images

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Database Models ---

# NEW association table for the many-to-many relationship
likes = db.Table('likes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('beta_id', db.Integer, db.ForeignKey('beta.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    height = db.Column(db.Integer, nullable=True)
    ape_index = db.Column(db.Float, nullable=True)
    betas = db.relationship('Beta', backref='author', lazy=True)
    # NEW relationship to access the betas a user has liked
    liked_betas = db.relationship('Beta', secondary=likes, backref=db.backref('likers', lazy='dynamic'))

class Beta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    grade = db.Column(db.String(20), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # We don't need to add anything here, the backref in User handles it

# --- Web Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# BetaForm
class BetaForm(FlaskForm):
    name = StringField('Boulder/Route Name', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    grade = StringField('Grade', validators=[DataRequired()])
    picture = FileField('Main Picture of the Climb', validators=[DataRequired(), FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Submit') # Changed text to be more generic

# EditBetaForm
class EditBetaForm(FlaskForm):
    name = StringField('Boulder/Route Name', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    grade = StringField('Grade', validators=[DataRequired()])
    # The picture field is now optional because we removed DataRequired()
    picture = FileField('Upload New Picture (Optional)', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update Beta')

# UptdateProfilForm
class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    height = IntegerField('Height (in cm)')
    ape_index = FloatField('Ape Index (e.g., 1.05)')
    submit = SubmitField('Update Profile')

    # Custom validation to check if the new username is already taken
    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is already taken. Please choose a different one.')

    # Custom validation to check if the new email is already taken
    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is already in use. Please choose a different one.')


# --- Routes ---
# ... (home, login, logout, register routes remain the same)
@app.route('/')
def home():
    return render_template('home.html')
# (login route)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        else: flash('Login unsuccessful. Please check email and password.')
    return render_template('login.html', form=form)
# (logout route)
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))
# (register route)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)
# (dashboard route)
@app.route('/dashboard')
@login_required
def dashboard():
    # Because of the 'backref' in our model, we can easily get all betas
    # created by the current user with `current_user.betas`.
    user_betas = current_user.betas
    return render_template('dashboard.html', betas=user_betas)


# --- New Route for Creating Betas ---
@app.route('/create_beta', methods=['GET', 'POST'])
@login_required
def create_beta():
    form = BetaForm()
    if form.validate_on_submit():
        # Save the picture
        picture_file = secure_filename(form.picture.data.filename)
        picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_file)
        form.picture.data.save(picture_path)

        # Create new beta entry in the database
        beta = Beta(name=form.name.data,
                    location=form.location.data,
                    grade=form.grade.data,
                    image_file=picture_file,
                    author=current_user)
        db.session.add(beta)
        db.session.commit()
        flash('Your beta has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_beta.html', title='New Beta', form=form)


# --- New Route to display all betas ---
@app.route('/betas')
def betas():
    # Query the database to get all beta entries
    all_betas = Beta.query.all()
    return render_template('betas.html', betas=all_betas)

# --- New Route for a single beta's detail page ---
@app.route('/beta/<int:beta_id>')
def beta_detail(beta_id):
    # Get the specific beta from the database using its ID.
    # get_or_404 is a helpful function that will show a 404 error if the ID doesn't exist.
    beta = Beta.query.get_or_404(beta_id)
    return render_template('beta_detail.html', beta=beta)

# --- New Route for deleting a beta ---
@app.route('/beta/<int:beta_id>/delete', methods=['POST'])
@login_required
def delete_beta(beta_id):
    beta_to_delete = Beta.query.get_or_404(beta_id)

    # Security Check: Ensure the current user is the author of the beta
    if beta_to_delete.author != current_user:
        # Abort with a 403 Forbidden error if they are not the author
        from flask import abort
        abort(403)

    # --- Delete the image file from the server ---
    try:
        image_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], beta_to_delete.image_file)
        if os.path.exists(image_path):
            os.remove(image_path)
    except Exception as e:
        # Log the error if the file can't be deleted, but continue
        app.logger.error(f"Error deleting file {beta_to_delete.image_file}: {e}")

    # --- Delete the beta from the database ---
    db.session.delete(beta_to_delete)
    db.session.commit()

    flash('Your beta has been deleted!', 'success')
    return redirect(url_for('betas'))

# --- New Route for editing a beta ---
@app.route('/beta/<int:beta_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_beta(beta_id):
    beta_to_edit = Beta.query.get_or_404(beta_id)

    if beta_to_edit.author != current_user:
        from flask import abort
        abort(403)

    form = EditBetaForm() # Use the new EditBetaForm here

    if form.validate_on_submit():
        beta_to_edit.name = form.name.data
        beta_to_edit.location = form.location.data
        beta_to_edit.grade = form.grade.data

        if form.picture.data: # Only update the picture if a new one was uploaded
            picture_file = secure_filename(form.picture.data.filename)
            picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_file)
            form.picture.data.save(picture_path)
            beta_to_edit.image_file = picture_file
        
        db.session.commit()
        flash('Your beta has been updated!', 'success')
        return redirect(url_for('beta_detail', beta_id=beta_to_edit.id))

    elif request.method == 'GET':
        form.name.data = beta_to_edit.name
        form.location.data = beta_to_edit.location
        form.grade.data = beta_to_edit.grade

    return render_template('edit_beta.html', title='Edit Beta', form=form)

#Edit Profile route
@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.height = form.height.data
        current_user.ape_index = form.ape_index.data
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        # Pre-populate the form with the user's current data
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.height.data = current_user.height
        form.ape_index.data = current_user.ape_index
    return render_template('edit_profile.html', title='Edit Profile', form=form)

# --- New Route for public user profiles ---
@app.route('/profile/<string:username>')
def profile(username):
    # Find the user by their username, or show a 404 error if not found
    user = User.query.filter_by(username=username).first_or_404()
    # The user's betas are automatically available via the relationship
    return render_template('profile.html', user=user, betas=user.betas)

# --- New Routes for Liking/Unliking Betas ---
@app.route('/like/<int:beta_id>')
@login_required
def like_beta(beta_id):
    beta = Beta.query.get_or_404(beta_id)
    if beta not in current_user.liked_betas:
        current_user.liked_betas.append(beta)
        db.session.commit()
        flash('You have liked this beta!', 'success')
    else:
        flash('You have already liked this beta.', 'info')
    return redirect(url_for('beta_detail', beta_id=beta.id))

@app.route('/unlike/<int:beta_id>')
@login_required
def unlike_beta(beta_id):
    beta = Beta.query.get_or_404(beta_id)
    if beta in current_user.liked_betas:
        current_user.liked_betas.remove(beta)
        db.session.commit()
        flash('You have unliked this beta.', 'success')
    else:
        flash('You have not liked this beta yet.', 'info')
    return redirect(url_for('beta_detail', beta_id=beta.id))

# --- New Route for Search ---
@app.route('/search', methods=['POST'])
def search():
    query = request.form['searched']
    # Get all betas to search through
    all_betas = Beta.query.all()
    results = []
    # A threshold for how similar the strings should be (0-100)
    # You can adjust this value to make the search more or less strict.
    similarity_threshold = 60

    for beta in all_betas:
        # Compare the beta's name to the search query
        ratio = fuzz.ratio(beta.name.lower(), query.lower())
        if ratio >= similarity_threshold:
            results.append(beta)

    return render_template('search_results.html', query=query, results=results)

if __name__ == '__main__':
    app.run(debug=True)