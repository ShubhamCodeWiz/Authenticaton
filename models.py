from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz
db = SQLAlchemy()


class Registration(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(50),unique=True,nullable=False,index=True)
    password = db.Column(db.String(128),nullable=False)
    created_at = db.Column(db.DateTime,default=lambda: datetime.now(pytz.utc))

    def __repr__(self):
        return f"User {self.username}"
    
    