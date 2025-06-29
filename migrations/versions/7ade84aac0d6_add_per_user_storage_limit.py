"""Add per-user storage limit

Revision ID: 7ade84aac0d6
Revises: 5e0b45011333
Create Date: 2025-06-13 21:29:51.887387

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7ade84aac0d6'
down_revision = '5e0b45011333'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('max_storage_mb', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('max_storage_mb')

    # ### end Alembic commands ###
