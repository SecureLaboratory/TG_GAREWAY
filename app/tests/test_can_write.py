"""The message box is shown only where this account may post."""
from telethon.tl.types import (Channel, ChannelForbidden, Chat, ChatAdminRights, ChatBannedRights, ChatPhotoEmpty,
                               User)

from tgviewer.telegram import can_write


def channel(**kw):
    return Channel(id=1, title="c", photo=ChatPhotoEmpty(), date=None, **kw)


def test_channels_only_for_admins_who_may_post():
    assert not can_write(channel(broadcast=True))
    assert can_write(channel(broadcast=True, creator=True))
    assert can_write(channel(broadcast=True, admin_rights=ChatAdminRights(post_messages=True)))
    assert not can_write(channel(broadcast=True, admin_rights=ChatAdminRights(edit_messages=True)))


def test_groups_respect_restrictions():
    banned = ChatBannedRights(until_date=None, send_messages=True)
    assert can_write(channel(megagroup=True))
    assert not can_write(channel(megagroup=True, default_banned_rights=banned))
    assert not can_write(channel(megagroup=True, banned_rights=banned))
    assert can_write(channel(megagroup=True, default_banned_rights=banned, admin_rights=ChatAdminRights()))
    assert not can_write(channel(megagroup=True, left=True))
    assert can_write(Chat(id=2, title="g", photo=ChatPhotoEmpty(), participants_count=3, date=None, version=1))
    assert not can_write(Chat(id=2, title="g", photo=ChatPhotoEmpty(), participants_count=3, date=None, version=1,
                              deactivated=True))


def test_people_and_forbidden_chats():
    assert can_write(User(id=3))
    assert not can_write(User(id=4, deleted=True))
    assert not can_write(ChannelForbidden(id=5, access_hash=0, title="x"))
