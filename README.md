
# File Manager App

A secure, user-friendly file manager web application built using Python Flask, with support for folder creation, file uploads, public access links, and user-specific dashboards.

---

## Features Implemented

### User Authentication
- User registration and login with hashed passwords
- Session-based authentication
- Redirect to dashboard if already logged in

### Folder & File Management
- Create folders per user
- Upload files to specific folders
- Allowed file types: images (JPG, PNG, GIF), PDFs, Word documents (DOC, DOCX)
- File previews (images and PDFs)
- Public URL generation for sharing files
- File deletion with confirmation

### Dashboard Enhancements
- Displays total size of each folder in MB
- Shows number of files per folder
- Progress bar to visualize storage usage (based on 100 MB quota)
- "Download ZIP" button to download all files in a folder
- Displays logged-in username next to Logout button

### Download Features
- ZIP download of folder contents
- In-memory generation using `io.BytesIO` and `zipfile`

### UI/UX
- Fully responsive layout using Bootstrap 5
- Bootstrap icons for folder and file types
- Clean login, register, dashboard, and folder pages

---

##  Setup Instructions

### 1. Install requirements
```bash
pip install -r requirements.txt
```

### 2. Initialize the database
```bash
python3 init_db.py
```

### 3. Run the App
```bash
python3 app.py
```

### 4. Visit in browser
```
http://127.0.0.1:5000/
```

---

##  Project Structure
```
flask_file_app/
├── app.py
├── config.py
├── models.py
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   └── folder.html
├── static/uploads/
├── database.db (auto-created)
```

---

##  Future Improvements
- Expiring public URLs
- Admin dashboard to monitor users
- Email-based account verification
- Cloud file storage (S3, Cloudinary)
