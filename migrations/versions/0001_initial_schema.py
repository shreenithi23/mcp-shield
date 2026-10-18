"""Initial schema for users, clients, oauth_sessions, and issued_tokens

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-15 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.types import JSON


# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('provider', sa.String(length=64), nullable=False),
        sa.Column('provider_sub', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Clients table
    op.create_table(
        'clients',
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('client_secret', sa.String(length=255), nullable=True),
        sa.Column('client_name', sa.String(length=255), nullable=False),
        sa.Column('redirect_uris', JSON, nullable=False),
        sa.Column('grant_types', JSON, nullable=False),
        sa.Column('response_types', JSON, nullable=False),
        sa.Column('token_endpoint_auth_method', sa.String(length=64), nullable=False),
        sa.Column('scope', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('client_id')
    )

    # OAuth Sessions table
    op.create_table(
        'oauth_sessions',
        sa.Column('session_id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=True),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('auth_code', sa.String(length=128), nullable=True),
        sa.Column('code_challenge', sa.String(length=128), nullable=False),
        sa.Column('code_challenge_method', sa.String(length=32), nullable=False),
        sa.Column('redirect_uri', sa.String(length=512), nullable=False),
        sa.Column('scope', sa.String(length=255), nullable=False),
        sa.Column('resource', sa.String(length=512), nullable=False),
        sa.Column('task_id', sa.String(length=1024), nullable=False),
        sa.Column('state', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.ForeignKeyConstraint(['client_id'], ['clients.client_id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('session_id')
    )
    op.create_index(op.f('ix_oauth_sessions_auth_code'), 'oauth_sessions', ['auth_code'], unique=True)

    # Issued Tokens table
    op.create_table(
        'issued_tokens',
        sa.Column('jti', sa.String(length=64), nullable=False),
        sa.Column('client_id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('token_type', sa.String(length=32), nullable=False),
        sa.Column('audience', sa.String(length=512), nullable=False),
        sa.Column('task_id', sa.String(length=1024), nullable=False),
        sa.Column('act', JSON, nullable=True),
        sa.Column('scope', sa.String(length=255), nullable=False),
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['clients.client_id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('jti')
    )
    op.create_index('idx_issued_tokens_audience', 'issued_tokens', ['audience'], unique=False)
    op.create_index('idx_issued_tokens_client_user', 'issued_tokens', ['client_id', 'user_id'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_issued_tokens_client_user', table_name='issued_tokens')
    op.drop_index('idx_issued_tokens_audience', table_name='issued_tokens')
    op.drop_table('issued_tokens')
    op.drop_index(op.f('ix_oauth_sessions_auth_code'), table_name='oauth_sessions')
    op.drop_table('oauth_sessions')
    op.drop_table('clients')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
