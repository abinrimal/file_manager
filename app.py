from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, send_file
from werkzeug.utils import secure_filename
import os
import uuid
from models import db, User, Folder, File
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
import zipfile
import io
from datetime import timedelta
app = Flask(__name__)
app.config.from_object(Config)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB max file size
app.permanent_session_lifetime = timedelta(days=7)




ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db.init_app(app)

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(username=request.form['username'],
                    password=generate_password_hash(request.form['password']))
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id

            # Handle remember me
            if 'remember' in request.form:
                session.permanent = True 
            else:
                session.permanent = False

            return redirect(url_for('dashboard'))
        flash("Invalid credentials")
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    folders = Folder.query.filter_by(user_id=user.id).all()

    folders_with_size = []
    for folder in folders:
        files = File.query.filter_by(folder_id=folder.id).all()
        total_size = sum(f.size for f in files)
        folder_data = {
            'id': folder.id,
            'name': folder.name,
            'total_size': round(total_size / (1024 * 1024), 2),
            'file_count': len(files),
            'usage_percent': round((total_size / (100 * 1024 * 1024)) * 100, 2)
        }
        folders_with_size.append(folder_data)

    return render_template('dashboard.html', folders=folders_with_size, username=user.username)


@app.route('/folder/<int:folder_id>/download')
def download_folder_zip(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    files = File.query.filter_by(folder_id=folder.id).all()

    memory_file = io.BytesIO()

    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
            if os.path.exists(file_path):
                zf.write(file_path, arcname=f.filename)

    memory_file.seek(0)

    return send_file(
        memory_file,
        as_attachment=True,
        download_name=f"{folder.name}.zip",
        mimetype='application/zip'
    )


@app.route('/folder/create', methods=['POST'])
def create_folder():
    name = request.form['folder_name']
    folder = Folder(name=name, user_id=session['user_id'])
    db.session.add(folder)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/folder/<int:folder_id>', methods=['GET', 'POST'])
def folder_view(folder_id):
    folder = Folder.query.get(folder_id)
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            size = os.path.getsize(file_path)
            public_url = url_for('serve_file', filename=filename, _external=True)

            new_file = File(filename=filename, size=size, folder_id=folder.id, public_url=public_url)
            db.session.add(new_file)
            db.session.commit()
        else:
            flash("Invalid file type.")
    files = File.query.filter_by(folder_id=folder.id).all()
    return render_template('folder.html', folder=folder, files=files)

@app.route('/files/<filename>')
def serve_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/file/<int:file_id>/delete/<int:folder_id>', methods=['POST'])
def delete_file(file_id, folder_id):
    file = File.query.get_or_404(file_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(file)
    db.session.commit()
    return redirect(url_for('folder_view', folder_id=folder_id))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

def create_tables():
    with app.app_context():
        db.create_all()
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

if __name__ == "__main__":
    create_tables()
    app.secret_key = Config.SECRET_KEY
    app.run(debug=True)
