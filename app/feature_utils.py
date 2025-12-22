# /app/feature_utils.py

from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.model_features import FeatureCatalog, SubfeatureCatalog, CustomerFeatureFlags


async def find_feature_id_by_subfeature(session: AsyncSession,
                                        subfeature_id: Optional[int],
                                        sub_feature_key: Optional[str]) -> int:
    """
    Find the feature_id for a given subfeature.
    """
    res = None
    if subfeature_id is not None:
        res = await session.execute(
            select(SubfeatureCatalog).where(SubfeatureCatalog.id == subfeature_id)
        )
        subf = res.scalar_one_or_none()
    elif sub_feature_key is not None:
        res = await session.execute(
            select(SubfeatureCatalog).where(SubfeatureCatalog.key == sub_feature_key)
        )
        subf = res.scalar_one_or_none()
    else:
        return None

    if subf is None:
        return None

    return subf.feature_id


async def is_feature_enabled_for_customer(
    session: AsyncSession,
    *,
    customer_id: int,
    feature_key: Optional[str] = None,
    feature_id: Optional[int] = None,
) -> bool:
    """
    Is a FEATURE enabled for this customer?

    Is this feature enabled for the given customer? This checks the following:
      1) Customer-specific feature flag (customer, feature)
      2) False
    """
    # Resolve feature
    if feature_id is not None:
        res = await session.execute(
            select(FeatureCatalog).where(FeatureCatalog.id == feature_id)
        )
    elif feature_key is not None:
        res = await session.execute(
            select(FeatureCatalog).where(FeatureCatalog.key == feature_key)
        )
    else:
        return False

    feature = res.scalar_one_or_none()
    if feature is None:
        return False

    # Feature-level (ALL) flag
    res = await session.execute(
        select(CustomerFeatureFlags.enabled)
        .where(
            CustomerFeatureFlags.customer_id == customer_id,
            CustomerFeatureFlags.feature_id == feature.id,
            CustomerFeatureFlags.sub_feature_id.is_(None),
        )
        .limit(1)
    )
    all_row = res.scalar_one_or_none()
    if all_row is not None:
        return bool(all_row)

    return False


async def is_subfeature_enabled_for_customer(
    session: AsyncSession,
    *,
    customer_id: int,
    # identify by key or id (id takes precedence if both provided)
    subfeature_key: Optional[str] = None,
    subfeature_id: Optional[int] = None,
) -> bool:
    """
    Is a SUB-FEATURE enabled for this customer?

    Precedence:
      1) Customer-specific sub-feature flag (customer, feature, subfeature)
      2) Customer feature-level flag
      3) False

    Notes:
      - If `respect_is_active=True`, inactive features/subfeatures are treated as disabled.
      - Ensures the given subfeature belongs to the resolved feature.
    """
    # print(f"Resolving subfeature {subfeature_key}")
    res = None

    # Find subfeature_id (and ensure it belongs to the feature)
    if subfeature_id is not None:
        res = await session.execute(
            select(SubfeatureCatalog).where(
                SubfeatureCatalog.id == subfeature_id,
            )
        )
    elif subfeature_key is not None:
        print(f"Resolving subfeature {subfeature_key}")
        res = await session.execute(
            select(SubfeatureCatalog).where(
                SubfeatureCatalog.key == subfeature_key,
            )
        )
    else:
        # subfeature_key or subfeature_id must be provided
        return False

    subf = res.scalar_one_or_none()
    if subf is None:
        # This subfeature does not exist
        return False

    # Find the sub feature flag in customer_feature_flags table
    res = await session.execute(
        select(CustomerFeatureFlags.enabled).where(
            CustomerFeatureFlags.customer_id == customer_id,
            CustomerFeatureFlags.sub_feature_id == subf.id,
        ).limit(1)
    )
    specific = res.scalar_one_or_none()
    if specific is not None:
        return bool(specific)

    # If no row for subfeature in customer_feature_flags, delegate to feature-level check
    return await is_feature_enabled_for_customer(
        session,
        customer_id=customer_id,
        feature_id=await find_feature_id_by_subfeature(
            session,
            sub_feature_key=subfeature_key,
            subfeature_id=subfeature_id),
    )
