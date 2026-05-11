"""initial schema

Revision ID: 20260511_0001
Revises:
Create Date: 2026-05-11
"""

from alembic import op
import sqlalchemy as sa

revision = "20260511_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.Text(), nullable=False, unique=True),
        sa.Column("password_salt", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("plan", sa.Text(), nullable=False, server_default="free"),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )

    op.create_table(
        "tokens",
        sa.Column("token", sa.Text(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("revoked", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "generations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
    )

    op.create_table(
        "orders",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("plan", sa.Text(), nullable=False),
        sa.Column("amount", sa.Integer(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("paid_at", sa.Text(), nullable=True),
    )

    op.create_table(
        "templates",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )

    op.create_table(
        "favorites",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("generation_id", sa.Integer(), sa.ForeignKey("generations.id"), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )

    op.create_table(
        "schedules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("date", sa.Text(), nullable=False),
        sa.Column("theme", sa.Text(), nullable=False),
        sa.Column("time", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
    )

    op.create_index("ix_generations_user_created_at", "generations", ["user_id", "created_at"])
    op.create_index("ix_orders_status", "orders", ["status"])
    op.create_index("ix_schedules_user_date", "schedules", ["user_id", "date"])


def downgrade() -> None:
    op.drop_index("ix_schedules_user_date", table_name="schedules")
    op.drop_index("ix_orders_status", table_name="orders")
    op.drop_index("ix_generations_user_created_at", table_name="generations")
    op.drop_table("schedules")
    op.drop_table("favorites")
    op.drop_table("templates")
    op.drop_table("orders")
    op.drop_table("generations")
    op.drop_table("tokens")
    op.drop_table("users")
