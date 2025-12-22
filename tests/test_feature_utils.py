import pytest
from unittest.mock import AsyncMock, MagicMock

from app.feature_utils import (
    find_feature_id_by_subfeature,
    is_feature_enabled_for_customer,
    is_subfeature_enabled_for_customer,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mock_result(value):
    """Mock SQLAlchemy Result with scalar_one_or_none()."""
    res = MagicMock()
    res.scalar_one_or_none.return_value = value
    return res


def make_session(*results):
    """
    Create a mock AsyncSession where each execute() call
    returns the next result in `results`.
    """
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=results)
    return session


# ---------------------------------------------------------------------------
# find_feature_id_by_subfeature
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_find_feature_id_by_subfeature_by_id():
    subf = MagicMock()
    subf.feature_id = 10

    session = make_session(mock_result(subf))

    feature_id = await find_feature_id_by_subfeature(
        session,
        subfeature_id=1,
        sub_feature_key=None,
    )

    assert feature_id == 10
    session.execute.assert_called_once()


@pytest.mark.asyncio
async def test_find_feature_id_by_subfeature_by_key():
    subf = MagicMock()
    subf.feature_id = 20

    session = make_session(mock_result(subf))

    feature_id = await find_feature_id_by_subfeature(
        session,
        subfeature_id=None,
        sub_feature_key="weekly_digest",
    )

    assert feature_id == 20


@pytest.mark.asyncio
async def test_find_feature_id_by_subfeature_not_found():
    session = make_session(mock_result(None))

    feature_id = await find_feature_id_by_subfeature(
        session,
        subfeature_id=999,
        sub_feature_key=None,
    )

    assert feature_id is None


@pytest.mark.asyncio
async def test_find_feature_id_by_subfeature_no_inputs():
    session = AsyncMock()

    feature_id = await find_feature_id_by_subfeature(
        session,
        subfeature_id=None,
        sub_feature_key=None,
    )

    assert feature_id is None
    session.execute.assert_not_called()


# ---------------------------------------------------------------------------
# is_feature_enabled_for_customer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_feature_enabled_true():
    feature = MagicMock()
    feature.id = 5

    session = make_session(
        mock_result(feature),   # FeatureCatalog lookup
        mock_result(True),      # CustomerFeatureFlags.enabled
    )

    enabled = await is_feature_enabled_for_customer(
        session,
        customer_id=123,
        feature_id=5,
    )

    assert enabled is True


@pytest.mark.asyncio
async def test_feature_enabled_false():
    feature = MagicMock()
    feature.id = 5

    session = make_session(
        mock_result(feature),
        mock_result(False),
    )

    enabled = await is_feature_enabled_for_customer(
        session,
        customer_id=123,
        feature_id=5,
    )

    assert enabled is False


@pytest.mark.asyncio
async def test_feature_not_found():
    session = make_session(mock_result(None))

    enabled = await is_feature_enabled_for_customer(
        session,
        customer_id=123,
        feature_key="EMAILS",
    )

    assert enabled is False


@pytest.mark.asyncio
async def test_feature_no_flag_row():
    feature = MagicMock()
    feature.id = 5

    session = make_session(
        mock_result(feature),
        mock_result(None),
    )

    enabled = await is_feature_enabled_for_customer(
        session,
        customer_id=123,
        feature_id=5,
    )

    assert enabled is False


@pytest.mark.asyncio
async def test_feature_no_identifier():
    session = AsyncMock()

    enabled = await is_feature_enabled_for_customer(
        session,
        customer_id=123,
    )

    assert enabled is False
    session.execute.assert_not_called()


# ---------------------------------------------------------------------------
# is_subfeature_enabled_for_customer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subfeature_specific_flag_true():
    subf = MagicMock()
    subf.id = 7
    subf.feature_id = 99

    session = make_session(
        mock_result(subf),     # SubfeatureCatalog
        mock_result(True),     # CustomerFeatureFlags (subfeature)
    )

    enabled = await is_subfeature_enabled_for_customer(
        session,
        customer_id=1,
        subfeature_id=7,
    )

    assert enabled is True


@pytest.mark.asyncio
async def test_subfeature_specific_flag_false():
    subf = MagicMock()
    subf.id = 7
    subf.feature_id = 99

    session = make_session(
        mock_result(subf),
        mock_result(False),
    )

    enabled = await is_subfeature_enabled_for_customer(
        session,
        customer_id=1,
        subfeature_id=7,
    )

    assert enabled is False


@pytest.mark.asyncio
async def test_subfeature_falls_back_to_feature_true():
    subf = MagicMock()
    subf.id = 7
    subf.feature_id = 99

    feature = MagicMock()
    feature.id = 99

    session = make_session(
        mock_result(subf),     # 1) subfeature lookup
        mock_result(None),     # 2) subfeature-specific flag
        mock_result(subf),     # 3) find_feature_id_by_subfeature() lookup
        mock_result(feature),  # 4) FeatureCatalog lookup
        mock_result(True),     # 5) feature flag enabled
    )

    enabled = await is_subfeature_enabled_for_customer(
        session,
        customer_id=1,
        subfeature_id=7,
    )

    assert enabled is True


@pytest.mark.asyncio
async def test_subfeature_not_found():
    session = make_session(mock_result(None))

    enabled = await is_subfeature_enabled_for_customer(
        session,
        customer_id=1,
        subfeature_key="does_not_exist",
    )

    assert enabled is False


@pytest.mark.asyncio
async def test_subfeature_no_identifier():
    session = AsyncMock()

    enabled = await is_subfeature_enabled_for_customer(
        session,
        customer_id=1,
    )

    assert enabled is False
    session.execute.assert_not_called()
