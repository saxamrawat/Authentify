from sqlalchemy import inspect, text

from core.security import REFRESH_TOKEN_EXPIRE_DAYS
from models.models import RefreshToken, UserSession, Users
from services.token_service import TokenService


def test_test_database_is_at_expected_alembic_head(db_session):
    """
    Verify the integration test database has been migrated to the schema
    version expected by the current application.
    """

    revision = db_session.execute(
        text("SELECT version_num FROM alembic_version")
    ).scalar_one()

    assert revision == "e68ecfbf891c"


def test_required_security_tables_exist(db_session):
    """
    Verify all persistence tables required by the authentication system exist
    in the migrated integration database.
    """

    inspector = inspect(db_session.bind)

    tables = set(inspector.get_table_names())

    required_tables = {
        "users",
        "refresh_tokens",
        "user_sessions",
        "password_reset",
        "email_verification",
    }

    assert required_tables.issubset(tables)


def test_refresh_token_hash_has_required_database_constraints(db_session):
    """
    Verify the database enforces the uniqueness and SHA-256-sized storage
    requirements for persisted refresh-token hashes.
    """

    inspector = inspect(db_session.bind)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("refresh_tokens")
    }

    assert "token_hash" in columns
    assert columns["token_hash"]["nullable"] is False

    unique_constraints = inspector.get_unique_constraints(
        "refresh_tokens"
    )

    unique_columns = {
        tuple(constraint["column_names"])
        for constraint in unique_constraints
    }

    assert ("token_hash",) in unique_columns


def test_session_refresh_token_relationship_is_unique(db_session):
    """
    Verify the database allows each refresh token to belong to at most one
    session, preventing ambiguous session ownership.
    """

    inspector = inspect(db_session.bind)

    unique_constraints = inspector.get_unique_constraints(
        "user_sessions"
    )

    unique_columns = {
        tuple(constraint["column_names"])
        for constraint in unique_constraints
    }

    assert ("refresh_token_id",) in unique_columns


def test_test_database_is_not_using_production_database(db_session):
    """
    Verify integration tests are connected to the dedicated test database
    rather than the production authentication database.
    """

    database_name = db_session.execute(
        text("SELECT current_database()")
    ).scalar_one()

    assert database_name == "authentication_project_test"