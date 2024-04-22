from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory,abort,session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from werkzeug.utils import secure_filename
from flask import send_file
import hashlib 

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'  
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB maximum file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}



db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#one class of the db
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # Define the relationship with the uploaded files
    uploaded_files = db.relationship('UploadedFile', backref='user', lazy=True)

# another class for the db
class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"<UploadedFile {self.filename}>"



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)
    

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if User.query.count() >= 100:
            flash("The maximum user limit has been reached. Please try again later.")
            return redirect(url_for('login'))

        if User.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("This email already exists, please try logging in")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_and_salted_password
        )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)



@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_to_delete = UploadedFile.query.get_or_404(file_id)

    if file_to_delete.user_id != current_user.id:
        abort(403)  

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_to_delete.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    
    db.session.delete(file_to_delete)
    db.session.commit()

    flash('File deleted successfully.')
    return redirect(url_for('secrets'))



@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
    
        email = request.form.get('email')
        password = request.form.get('password')

        
        user = User.query.filter_by(email=email).first()

        
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
       
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
        else:
            login_user(user)
            return redirect(url_for('secrets'))
        
    return render_template("login.html", logged_in=current_user.is_authenticated)

@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    uploaded_files = request.files.getlist('file[]')
    user = current_user
    
    if len(uploaded_files) > 8:
        flash('You can only upload up to 8 files.')
        return redirect(url_for('secrets'))
    
    for file in uploaded_files:

        if file and allowed_file(file.filename) and file.content_length <= app.config['MAX_CONTENT_LENGTH']:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            uploaded_file = UploadedFile(filename=filename, user_id=user.id)
            db.session.add(uploaded_file)
        else:
            flash('Invalid file format or size.')

    db.session.commit()
    flash('Files uploaded successfully.')
    return redirect(url_for('secrets'))


@app.route('/hash_and_download/<int:file_id>', methods=['GET'])
@login_required
def hash_and_download(file_id):
    user = current_user
    uploaded_file = UploadedFile.query.filter_by(id=file_id, user_id=user.id).first()
    if uploaded_file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        hashed_filename = f"hashed_{uploaded_file.filename}"
        hashed_file_path = os.path.join(app.config['UPLOAD_FOLDER'], hashed_filename)
        with open(file_path, 'rb') as f:
            file_contents = f.read()
            hashed_content = hashlib.sha256(file_contents).hexdigest()
        with open(hashed_file_path, 'w') as f:
            f.write(hashed_content)
        return send_file(hashed_file_path, as_attachment=True)
    else:
        abort(404)
 
@app.route('/hash_and_download_md5/<int:file_id>', methods=['GET'])
@login_required
def hash_and_download_md5(file_id):
    user = current_user
    uploaded_file = UploadedFile.query.filter_by(id=file_id, user_id=user.id).first()
    if uploaded_file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        hashed_filename = f"hashed_md5_{uploaded_file.filename}"
        hashed_file_path = os.path.join(app.config['UPLOAD_FOLDER'], hashed_filename)
        with open(file_path, 'rb') as f:
            file_contents = f.read()
            hashed_content = hashlib.md5(file_contents).hexdigest()
        with open(hashed_file_path, 'w') as f:
            f.write(hashed_content)
        return send_file(hashed_file_path, as_attachment=True)
    else:
        abort(404)


@app.route('/secrets')
@login_required
def secrets():
    uploaded_files = current_user.uploaded_files
    return render_template("secrets.html", name=current_user.name, logged_in=True, uploaded_files=uploaded_files)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/<filename>')
def download(filename):
    user = current_user
    uploaded_file = UploadedFile.query.filter_by(filename=filename, user_id=user.id).first()
    if uploaded_file:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    else:
        flash('File not found or you do not have permission to access it.')
        return redirect(url_for('secrets'))
    

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        user = current_user

        if not check_password_hash(user.password, current_password):
            flash('Current password entered incorrectly.')
            return redirect(url_for('change_password'))

        user.password = generate_password_hash(
            new_password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        db.session.commit()
        flash('Password changed successfully.')
        return redirect(url_for('secrets'))

    return render_template('change_password.html')

@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        user = current_user

        uploaded_files = UploadedFile.query.filter_by(user_id=user.id).all()
        for file in uploaded_files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            db.session.delete(file)

        db.session.delete(user)
        db.session.commit()

        logout_user()
        flash('Your account has been deleted.')
        return redirect(url_for('home'))

    return render_template('delete_account.html')



if __name__ == "__main__":
    # creating an application centext, 
    # necessary to allow use to perform necessary operations 
    with app.app_context():
        # creating the database once the app runs (only the first time)
        db.create_all()
    app.run(debug=True)