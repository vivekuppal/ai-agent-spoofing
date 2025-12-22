import pytest

from app.feature_utils import (
    find_feature_id_by_subfeature,
    is_feature_enabled_for_customer,
    is_subfeature_enabled_for_customer,
)
from app.model_features import (
    FeatureCatalog,
    SubfeatureCatalog,
    CustomerFeatureFlags,
)

from app.models import Customer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def seed_feature(session, *, feature_id, key, name) -> FeatureCatalog:
    feature = FeatureCatalog(id=feature_id, key=key, name=name)
    session.add(feature)
    await session.flush()
    return feature


async def seed_subfeature(session, *, id, key, feature_id, name) -> SubfeatureCatalog:
    subf = SubfeatureCatalog(
        id=id,
        key=key,
        feature_id=feature_id,
        name=name,
    )
    session.add(subf)
    await session.flush()
    return subf


async def seed_flag(
    session,
    *,
    customer_id,
    feature_id=None,
    sub_feature_id=None,
    enabled,
    modified_by=2
) -> CustomerFeatureFlags:
    flag = CustomerFeatureFlags(
        customer_id=customer_id,
        feature_id=feature_id,
        sub_feature_id=sub_feature_id,
        enabled=enabled,
        modified_by=modified_by,
    )
    session.add(flag)
    await session.flush()
    return flag


async def seed_customer(
    session,
    *,
    id: int,
    name: str = "Test Customer",
    status: str = "active",
    tier: str = "free",
) -> Customer:
    customer = Customer(
        id=id,
        name=name,
        status=status,
        tier=tier,
    )
    session.add(customer)
    await session.flush()
    return customer

# ---------------------------------------------------------------------------
# find_feature_id_by_subfeature
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.asyncio
async def test_find_feature_id_by_subfeature_real_db(async_session):
    feature = await seed_feature(
        async_session,
        feature_id=1,
        key="EMAILS",
        name="Emails",
    )
    await seed_subfeature(
        async_session,
        id=10,
        key="WEEKLY_DIGEST",
        feature_id=feature.id,
        name="Weekly digest",
    )

    feature_id = await find_feature_id_by_subfeature(
        async_session,
        subfeature_id=10,
        sub_feature_key=None,
    )

    assert feature_id == 1


# ---------------------------------------------------------------------------
# is_feature_enabled_for_customer
# ---------------------------------------------------------------------------
@pytest.mark.integration
@pytest.mark.asyncio
async def test_feature_enabled_for_customer_real_db(async_session):

    await seed_customer(
        async_session,
        id=123,
        name="Acme Corp",
    )

    feature = await seed_feature(
        async_session,
        feature_id=2,
        key="DNS_MONITORING",
        name="DNS Monitoring",
    )

    await seed_flag(
        async_session,
        customer_id=123,
        feature_id=feature.id,
        enabled=True,
    )

    enabled = await is_feature_enabled_for_customer(
        async_session,
        customer_id=123,
        feature_key="DNS_MONITORING",
    )

    assert enabled is True


@pytest.mark.integration
@pytest.mark.asyncio
async def test_feature_disabled_when_no_flag(async_session):

    await seed_customer(
        async_session,
        id=123,
        name="Acme Corp",
    )

    await seed_feature(
        async_session,
        feature_id=3,
        key="ALERTS",
        name="Alerts",
    )

    enabled = await is_feature_enabled_for_customer(
        async_session,
        customer_id=123,
        feature_key="ALERTS",
    )

    assert enabled is False


# # ---------------------------------------------------------------------------
# # is_subfeature_enabled_for_customer
# # ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.asyncio
async def test_subfeature_specific_flag_takes_precedence(async_session):

    await seed_customer(
        async_session,
        id=1,
        name="Wall Corp",
    )

    feature = await seed_feature(
        async_session,
        feature_id=4,
        key="EMAILS",
        name="Emails",
    )
    subf = await seed_subfeature(
        async_session,
        id=40,
        key="SPOOF_ALERT",
        feature_id=feature.id,
        name="Spoof alert",
    )

    # Feature disabled
    await seed_flag(
        async_session,
        customer_id=1,
        feature_id=feature.id,
        enabled=False,
    )

    # Subfeature explicitly enabled
    await seed_flag(
        async_session,
        customer_id=1,
        feature_id=feature.id,
        sub_feature_id=subf.id,
        enabled=True,
    )

    enabled = await is_subfeature_enabled_for_customer(
        async_session,
        customer_id=1,
        subfeature_key="SPOOF_ALERT",
    )

    assert enabled is True


@pytest.mark.asyncio
@pytest.mark.integration
async def test_subfeature_falls_back_to_feature_flag(async_session):
    await seed_customer(
        async_session,
        id=99,
        name="Wall Corp",
    )

    feature = await seed_feature(
        async_session,
        feature_id=5,
        key="EMAILS",
        name="Emails",
    )
    await seed_subfeature(
        async_session,
        id=50,
        key="WEEKLY_DIGEST",
        feature_id=feature.id,
        name="Weekly digest",
    )

    # Only feature-level flag exists
    await seed_flag(
        async_session,
        customer_id=99,
        feature_id=feature.id,
        enabled=True,
    )

    enabled = await is_subfeature_enabled_for_customer(
        async_session,
        customer_id=99,
        subfeature_key="WEEKLY_DIGEST",
    )

    assert enabled is True


@pytest.mark.asyncio
@pytest.mark.integration
async def test_subfeature_disabled_when_no_flags(async_session):
    await seed_customer(
        async_session,
        id=42,
        name="Wall Corp",
    )
    feature = await seed_feature(
        async_session,
        feature_id=6,
        key="EMAILS",
        name="Emails",
    )
    await seed_subfeature(
        async_session,
        id=60,
        key="ARC_OVERRIDE",
        feature_id=feature.id,
        name="Arc override",
    )

    enabled = await is_subfeature_enabled_for_customer(
        async_session,
        customer_id=42,
        subfeature_key="ARC_OVERRIDE",
    )

    assert enabled is False
