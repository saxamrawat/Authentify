# Email Verification Repository

# Libraries

from sqlalchemy.orm import Session
from models import EmailVerification

class EmailVerificationRepository:

    @staticmethod
    def create(db: Session, verification_model: EmailVerification):
        db.add(verification_model)
        db.commit()
        db.refresh(verification_model)

        return verification_model

    @staticmethod
    def get_user_tokens(db: Session, user_id: int):
        return db.query(EmailVerification).filter(EmailVerification.user_id == user_id).all()

    @staticmethod
    def delete_user_tokens(db: Session, user_id: int):
        db.query(EmailVerification).filter(EmailVerification.user_id == user_id).delete()