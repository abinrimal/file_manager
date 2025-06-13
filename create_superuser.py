from werkzeug.security import generate_password_hash
from models import db, User
from app import app

with app.app_context():
    if not User.query.filter_by(username='abin').first():
        admin = User(username='prabidhilabs', password=generate_password_hash('abinrimal7@gmail.com'))
        db.session.add(admin)
        db.session.commit()
        print("✅ Superuser 'ABIN' created with password 'abinrimal7@gmail.com'")
    else:
        print("⚠️ Superuser already exists.")
