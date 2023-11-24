from sqlalchemy import Column, Integer, String,Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext

from auth.config import Config


DATABASE_URL = Config.DATABASE_URL
Base = declarative_base()

# Create the database engine and bind it to the session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    firstname = Column(String, index=True)
    lastname = Column(String)
    email = Column(String)
    password = Column(String)
    is_activated = Column(Boolean, default=False)
    refresh_token = Column(String, nullable=True)

    def __init__(self, firstname, lastname, email, password):
        self.firstname = firstname,
        self.lastname = lastname
        self.email = email
        self.set_password(password)

    def set_password(self, password):
        self.password = password_context.hash(password)

    def to_dict(self):
        return {
            'id': self.id,
            'firstname': self.firstname,
            'lastname': self.lastname,
            'email': self.email,
            'is_activated': self.is_activated,
        }
 