from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    stripe_customer_id = db.Column(db.String(120))
    stripe_subscription_id = db.Column(db.String(120))
    plan = db.Column(db.String(50))
    credits = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "plan": self.plan,
            "credits": self.credits
        }

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    platform = db.Column(db.String(20), nullable=False)  # 'youtube', 'tiktok', 'reel'
    video_data = db.Column(db.JSON, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

    user = db.relationship('User', backref=db.backref('history', lazy=True, cascade="all, delete-orphan"))

