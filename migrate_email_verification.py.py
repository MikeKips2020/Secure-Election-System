import os
from sqlalchemy import create_engine, text

database_url = os.environ["DATABASE_URL"]

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

engine = create_engine(database_url)

with engine.begin() as connection:

    connection.execute(text("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE
    """))

    connection.execute(text("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(500)
    """))

    connection.execute(text("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS email_verification_expires_at TIMESTAMP
    """))

    connection.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        ix_users_email_verification_token
        ON users (email_verification_token)
        WHERE email_verification_token IS NOT NULL
    """))

print("Email verification database migration completed successfully.")