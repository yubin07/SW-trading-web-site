"""empty message

Revision ID: e26857a6f16b
Revises: 
Create Date: 2022-06-12 00:14:09.352040

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e26857a6f16b'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('products', sa.Column('pimag', sa.String(length=100), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('products', 'pimag')
    # ### end Alembic commands ###
