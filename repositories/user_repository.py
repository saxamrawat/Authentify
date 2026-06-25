# User Repository

# Libraries

from sqlalchemy.orm import Session
from models import Users

class UserRepository:

    @staticmethod
    def get_all_users(db: Session):
        users = db.query(Users).all()
        return users

    @staticmethod
    def get_by_username(db: Session, username: str):
        return (
            db.query(Users).filter(Users.username == username).first()
        )

    @staticmethod
    def get_by_email(db: Session, email: str):
        return (
            db.query(Users).filter(Users.email == email).first()
        )

    @staticmethod
    def get_by_id(db: Session, user_id: int):
        return (
            db.query(Users).filter(Users.id == user_id).first())

    @staticmethod
    def create(db: Session,user: Users):
        db.add(user)

        return user