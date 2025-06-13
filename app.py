from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_from_directory, flash, send_file
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.utils import secure_filename
import os
import uuid
from models import db, User, Folder, File, Setting
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
import zipfile
import io
from datetime import timedelta
from flask_migrate import Migrate

app = Flask(__name__)
app.config.from_object(Config)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.permanent_session_lifetime = timedelta(days=7)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

# Set up login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    if current_user.is_authenticated:
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
            login_user(user, remember='remember' in request.form)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash("Invalid credentials")
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    folders = Folder.query.filter_by(user_id=current_user.id, parent_id=None).all()

    folders_with_size = []
    user_limit_mb = current_user.max_storage_mb or 100  # fallback to 100 MB

    for folder in folders:
        files = File.query.filter_by(folder_id=folder.id).all()
        total_size = sum(f.size for f in files)
        folders_with_size.append({
            'id': folder.id,
            'name': folder.name,
            'created_at': folder.created_at,
            'total_size': round(total_size / (1024 * 1024), 2),
            'file_count': len(files),
            'usage_percent': round((total_size / (user_limit_mb * 1024 * 1024)) * 100, 2)
        })

    return render_template('dashboard.html', folders=folders_with_size, username=current_user.username, max_storage=current_user.max_storage_mb)

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
    folder = Folder(name=name, user_id=current_user.id)
    db.session.add(folder)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/folder/<int:folder_id>', methods=['GET', 'POST'])
def folder_view(folder_id):
    folder = Folder.query.get(folder_id)

    if request.method == 'POST':
        user = current_user

        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                # Get max upload size from settings
                setting = Setting.query.filter_by(key='max_file_size').first()
                max_file_size = int(setting.value) * 1024 * 1024 if setting else 10 * 1024 * 1024

                # Calculate file size
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)

                # Check file size limit
                if file_size > max_file_size:
                    flash(f"File exceeds the maximum allowed size of {int(max_file_size / (1024 * 1024))}MB.")
                    return redirect(request.url)

                # Check user's total used storage
                user_folders = Folder.query.filter_by(user_id=user.id).all()
                folder_ids = [f.id for f in user_folders]
                used_storage = db.session.query(db.func.sum(File.size)).filter(File.folder_id.in_(folder_ids)).scalar() or 0

                if user.max_storage_mb and (used_storage + file_size > user.max_storage_mb * 1024 * 1024):
                    flash(f"You have exceeded your total storage limit of {user.max_storage_mb}MB.")
                    return redirect(request.url)

                # Save the file
                ext = os.path.splitext(file.filename)[1]
                filename = f"{uuid.uuid4()}{ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                public_url = url_for('serve_file', filename=filename, _external=True)

                new_file = File(filename=filename, size=file_size, folder_id=folder.id, public_url=public_url)
                db.session.add(new_file)
                db.session.commit()
            else:
                flash("Invalid file type.")

        elif 'subfolder_name' in request.form:
            subfolder = Folder(name=request.form['subfolder_name'], user_id=current_user.id, parent_id=folder.id)
            db.session.add(subfolder)
            db.session.commit()

    files = File.query.filter_by(folder_id=folder.id).all()
    subfolders = Folder.query.filter_by(parent_id=folder.id).all()
    return render_template('folder.html', folder=folder, files=files, subfolders=subfolders)

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

def delete_folder_and_contents(folder):
    files = File.query.filter_by(folder_id=folder.id).all()
    for file in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(file)

    subfolders = Folder.query.filter_by(parent_id=folder.id).all()
    for subfolder in subfolders:
        delete_folder_and_contents(subfolder)

    db.session.delete(folder)

@app.route('/folder/<int:folder_id>/delete', methods=['POST'])
def delete_folder(folder_id):
    if not current_user.is_authenticated:
        return {'success': False}, 401

    folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first()
    if not folder:
        return {'success': False}, 404

    def delete_recursive(folder):
        subfolders = Folder.query.filter_by(parent_id=folder.id).all()
        for sub in subfolders:
            delete_recursive(sub)

        files = File.query.filter_by(folder_id=folder.id).all()
        for f in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            db.session.delete(f)

        db.session.delete(folder)

    delete_recursive(folder)
    db.session.commit()
    return {'success': True}

@app.route('/folder/<int:folder_id>/rename', methods=['POST'])
def rename_folder(folder_id):
    if not current_user.is_authenticated:
        return {'success': False}, 401
    
    folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first()
    if not folder:
        return {'success': False}, 404

    if request.is_json:
        data = request.get_json()
        new_name = data.get('new_name', '').strip()
    else:
        new_name = request.form.get('new_name', '').strip()

    if new_name:
        folder.name = new_name
        db.session.commit()
        return {'success': True}

    return {'success': False}, 400

@app.route('/file/<int:file_id>/rename', methods=['POST'])
def rename_file(file_id):
    data = request.get_json()
    new_base = data.get('new_name', '').strip()
    file = File.query.get(file_id)

    if file and new_base:
        ext = os.path.splitext(file.filename)[1]
        file.filename = f"{new_base}{ext}"
        db.session.commit()
        return jsonify(success=True)
    return jsonify(success=False), 400

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = current_user
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        user = User.query.get(current_user.id)

        if not check_password_hash(user.password, current):
            flash('Current password is incorrect.')
        elif new != confirm:
            flash('New passwords do not match.')
        else:
            user.password = generate_password_hash(new)
            db.session.commit()
            flash('Password updated successfully.')

    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def create_tables():
    with app.app_context():
        db.create_all()
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


@app.route('/admin/dashboard')
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    users = User.query.all()
    files = File.query.all()
    total_users = len(users)
    total_files = len(files)
    total_size = round(sum(f.size for f in files) / (1024 * 1024), 2)
    recent_files = File.query.order_by(File.id.desc()).limit(5).all()

    return render_template('admin/dashboard.html', total_users=total_users,
                           total_files=total_files, total_size=total_size,
                           recent_files=recent_files)

@app.route('/admin/users')
def admin_users():
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    users = User.query.order_by(User.id.asc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>/folders')
def admin_user_folders(user_id):
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    folders = Folder.query.filter_by(user_id=user.id, parent_id=None).all()

    folders_with_info = []
    for folder in folders:
        files = File.query.filter_by(folder_id=folder.id).all()
        total_size = sum(f.size for f in files)
        folders_with_info.append({
            'id': folder.id,
            'name': folder.name,
            'created': folder.created_at.strftime('%Y-%m-%d') if folder.created_at else '',
            'file_count': len(files),
            'total_size': round(total_size / (1024 * 1024), 2),
            'usage_percent': round((total_size / (100 * 1024 * 1024)) * 100, 2)
        })

    return render_template('admin/user_folders.html', user=user, folders=folders_with_info)


@app.route('/admin/files')
def admin_all_files():
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    sort_by = request.args.get('sort', 'created_at')  # default sort
    direction = request.args.get('dir', 'desc')

    sort_attr = getattr(File, sort_by, File.created_at)
    if direction == 'desc':
        sort_attr = sort_attr.desc()
    else:
        sort_attr = sort_attr.asc()

    files = File.query.order_by(sort_attr).all()
    file_list = []

    for f in files:
        folder = Folder.query.get(f.folder_id) if f.folder_id else None
        user = User.query.get(folder.user_id) if folder else None
        file_list.append({
            'id': f.id,
            'filename': f.filename,
            'size': round(f.size / (1024 * 1024), 2),
            'folder_id': f.folder_id,
            'public_url': f.public_url,
            'uploaded': f.created_at.strftime('%Y-%m-%d %H:%M') if f.created_at else '',
            'user': user.username if user else 'N/A'
        })

    return render_template('admin/all_files.html', files=file_list, sort=sort_by, direction=direction)

@app.route('/admin/storage')
def admin_storage_stats():
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    total_files = File.query.count()
    total_folders = Folder.query.count()
    total_users = User.query.count()
    total_storage = db.session.query(db.func.sum(File.size)).scalar() or 0
    total_storage_mb = round(total_storage / (1024 * 1024), 2)

    users = User.query.all()
    user_stats = []

    for user in users:
        user_folders = Folder.query.filter_by(user_id=user.id).all()
        folder_ids = [f.id for f in user_folders]
        files = File.query.filter(File.folder_id.in_(folder_ids)).all()
        file_count = len(files)
        folder_count = len(user_folders)
        size_total = sum(f.size for f in files)
        size_mb = round(size_total / (1024 * 1024), 2)

        user_stats.append({
            'username': user.username,
            'file_count': file_count,
            'folder_count': folder_count,
            'storage_mb': size_mb
        })

    return render_template('admin/storage_stats.html',
                           total_files=total_files,
                           total_folders=total_folders,
                           total_users=total_users,
                           total_storage_mb=total_storage_mb,
                           user_stats=user_stats)

@app.route('/admin/users/add', methods=['POST'])
def admin_add_user():
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    username = request.form['username'].strip()
    password = request.form['password'].strip()

    if username and password:
        user = User(username=username, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash("User added successfully.")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
def admin_edit_user(user_id):
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        max_storage_mb = request.form.get('max_storage_mb')
        if username:
            user.username = username
        if password:
            user.password = generate_password_hash(password)
        if max_storage_mb:
            user.max_storage_mb = int(max_storage_mb)
        db.session.commit()
        flash("User updated.")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user and user.id != 1:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted.")
    return redirect(url_for('admin_users'))

@app.route('/admin/scan-files')
@login_required
def admin_scan_files():
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    files = File.query.all()
    flagged = []

    for f in files:
        flags = []
        if f.size > 5 * 1024 * 1024:  # > 5 MB
            flags.append("Large file")
        if f.filename.lower().endswith(('.exe', '.bat', '.sh')):
            flags.append("Executable file")
        if flags:
            flagged.append({
                'id': f.id,
                'filename': f.filename,
                'size': round(f.size / (1024 * 1024), 2),
                'flags': flags
            })

    return render_template('admin/scan_files.html', flagged=flagged)

def get_setting(key, default=None):
    setting = Setting.query.filter_by(key=key).first()
    return setting.value if setting else default

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if current_user.role != 'admin':
        flash("Unauthorized access.")
        return redirect(url_for('login'))

    max_file_size = get_setting('max_file_size', '10')  # default 10MB

    if request.method == 'POST':
        new_size = request.form.get('max_file_size', '10')
        setting = Setting.query.filter_by(key='max_file_size').first()
        if not setting:
            setting = Setting(key='max_file_size', value=new_size)
            db.session.add(setting)
        else:
            setting.value = new_size
        db.session.commit()
        flash("Max file size updated.")
        return redirect(url_for('admin_settings'))

    return render_template('admin/settings.html', max_file_size=max_file_size)


if __name__ == "__main__":
    create_tables()
    app.secret_key = Config.SECRET_KEY
    app.run(debug=True)
