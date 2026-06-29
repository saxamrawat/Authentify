# Password Reset Repository

# Libraries

from sqlalchemy.orm import Session
from models.models import PasswordReset

class PasswordResetRepository:

    @staticmethod
    def create(db: Session, password_reset_model: PasswordReset):
        db.add(password_reset_model)

        return password_reset_model

    @staticmethod
    def get_user_tokens( db: Session, user_id: int):
        return db.query(PasswordReset).filter(PasswordReset.user_id == user_id).all()


    @staticmethod
    def delete_user_tokens(db: Session, user_id: int):
        db.query(PasswordReset).filter(PasswordReset.user_id == user_id).delete()