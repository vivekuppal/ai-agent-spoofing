import pytest
import os
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)

# IMPORTANT: import ALL models that define tables
import app.models            # registers customers table
import app.model_features    # registers feature tables

from app.model_features import Base


@pytest.fixture(scope="session")
async def async_engine():
    db_url = os.environ["TEST_DATABASE_URL"]

    engine = create_async_engine(
        db_url,
        echo=False,
        future=True,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    await engine.dispose()


@pytest.fixture
async def async_session(async_engine):
    Session = async_sessionmaker(
        async_engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )

    async with Session() as session:
        yield session
        await session.rollback()
