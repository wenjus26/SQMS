from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

# Initialize SQLAlchemy
db = SQLAlchemy()

# Define your models
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(3), nullable=False)
    location = db.Column(db.String(3), nullable=False)
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))
    profile_photo = db.Column(db.String(100)) 

    # Implement UserMixin properties
    @property
    def is_active(self):
        # For simplicity, assume all users are active
        return True

    @property
    def is_authenticated(self):
        # For simplicity, assume all users are authenticated
        return True

    @property
    def is_anonymous(self):
        # We assume that users are not anonymous in this system
        return False

    # Required for Flask-Login to get user by id
    def get_id(self):
        return str(self.id)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class LogAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('actions', lazy=True))
    username = db.Column(db.String(100), nullable=False)
    time = db.Column(db.DateTime, nullable=False, default=datetime.now) 
    action = db.Column(db.String(100), nullable=False)
    entry_code = db.Column(db.String(20), nullable=True) 

class TruckSample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    in_date = db.Column(db.String(20), nullable=False)
    in_time = db.Column(db.String(20), nullable=False)
    entry_code = db.Column(db.String(20), unique=True, nullable=False)
    truck_number = db.Column(db.String(255))
    driver_name = db.Column(db.String(255))
    driver_phone_number = db.Column(db.String(255))
    variety = db.Column(db.String(255))
    seed_origin = db.Column(db.String(255))
    sample_type = db.Column(db.String(255))
    unloading_location = db.Column(db.String(255))
    bags_received = db.Column(db.Integer)
    bags_rejected = db.Column(db.Integer)
    peripheral_sample = relationship('PeripheralSample', back_populates='truck_sample')
    master_sample = relationship('MasterSample', back_populates='truck_sample')
    first_decision = relationship('FirstDecision', back_populates='truck_sample')
    final_decision = relationship('FinalDecision', back_populates='truck_sample')

class PeripheralSample(db.Model):
    __tablename__ = 'peripheral_sample'
    id = db.Column(db.Integer, primary_key=True)
    in_date = db.Column(db.String(20), nullable=False)
    in_time = db.Column(db.String(20), nullable=False)
    truck_entry_code = db.Column(db.Integer, db.ForeignKey('truck_sample.entry_code'), unique=True)
    damage_g = db.Column(db.Integer)
    ofm_g = db.Column(db.Integer)
    humidity_percent = db.Column(db.Float)  
    damage_percent = db.Column(db.Float)
    ofm_percent = db.Column(db.Float)
    truck_sample = relationship("TruckSample", back_populates="peripheral_sample")
    def __repr__(self):
        return f"PeripheralSample('{self.truck_entry_code}')"
    
class MasterSample(db.Model):
    __tablename__ = 'master_sample'
    id = db.Column(db.Integer, primary_key=True)
    in_date = db.Column(db.String(20), nullable=False)
    in_time = db.Column(db.String(20), nullable=False)
    truck_entry_code = db.Column(db.Integer, db.ForeignKey('truck_sample.entry_code'), unique=True)
    damage_g = db.Column(db.Integer)
    ofm_g = db.Column(db.Integer)
    green_seed_g = db.Column(db.Integer)
    small_seed_g = db.Column(db.Integer)
    split_g = db.Column(db.Integer)
    humidity_percent = db.Column(db.Float)   
    green_seed_percent = db.Column(db.Float)
    small_seed_percent = db.Column(db.Float)
    split_percent = db.Column(db.Float)
    damage_percent = db.Column(db.Float)
    ofm_percent = db.Column(db.Float)
    sample_code = db.Column(db.String(20), nullable=False, unique=True)
    truck_sample = relationship("TruckSample", back_populates="master_sample")
    def __repr__(self):
        return f"MasterSample('{self.truck_entry_code}')"
    
class FirstDecision(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    in_date_first = db.Column(db.String(20), nullable=False)
    in_time_first = db.Column(db.String(20), nullable=False)
    truck_entry_code = db.Column(db.Integer, db.ForeignKey('truck_sample.entry_code'), unique=True)
    decision_first = db.Column(db.String(255))  # Décision initiale
    reason_first = db.Column(db.String(255), nullable=False)  # Motif de la décision initiale
    truck_sample = relationship("TruckSample", back_populates="first_decision")
    def __repr__(self):
        return f"FirstDecision('{self.truck_entry_code}')"

class FinalDecision(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    truck_entry_code = db.Column(db.Integer, db.ForeignKey('truck_sample.entry_code'), unique=True)
    in_date_final = db.Column(db.String(20), nullable=False)
    in_time_final = db.Column(db.String(20), nullable=False)
    decision_final = db.Column(db.String(255),nullable=False)  
    reason_final = db.Column(db.String(255),nullable=False) 
    truck_sample = relationship("TruckSample", back_populates="final_decision")
    def __repr__(self):
        return f"FinalDecision('{self.truck_entry_code}')"
