import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.models import ModerationAction


async def test_moderation_actions_are_append_only(db, make_user):
    moderator = await make_user(keys=False)
    action_id = uuid.uuid4()
    db.add(
        ModerationAction(
            id=action_id,
            moderator_id=moderator.id,
            action_type="warn_user",
            target_type="user",
            target_id=str(moderator.id),
            reason="test action",
        )
    )
    await db.commit()

    with pytest.raises(DBAPIError):
        await db.execute(
            text("UPDATE moderation_actions SET reason = :reason WHERE id = :id"),
            {"reason": "changed", "id": action_id},
        )
        await db.commit()
    await db.rollback()

    with pytest.raises(DBAPIError):
        await db.execute(
            text("DELETE FROM moderation_actions WHERE id = :id"),
            {"id": action_id},
        )
        await db.commit()
    await db.rollback()
