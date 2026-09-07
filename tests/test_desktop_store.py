"""Reads served from Signal Desktop's own database.

The bug these exist for: the private store this replaced never recorded who an OUTGOING message went
to, so a two-sided conversation read back as the half somebody else wrote. Measured on a live account,
one contact held 76 messages in Signal Desktop (36 in, 39 out) and 7 in the copy, all inbound.

The fixture is a plaintext SQLite database with Signal Desktop's own column names, so nothing here
touches a real account or needs a key.
"""

import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from signal_mcp import desktop_store as ds

OWN = "+15550000001"
THEM = "+15550000002"
THEIR_UUID = "c418538f-494b-46f3-865a-6102106b834f"
CONV = "ed2eae75-995e-4746-bc20-1ecd4bc6c7f2"
GROUP_CONV = "aa11bb22-0000-4746-bc20-1ecd4bc6c7f2"


def _at(day, hour=12):
    return int(datetime(2026, 3, day, hour).timestamp() * 1000)


@pytest.fixture
def desktop_db(tmp_path, monkeypatch):
    """A stand-in for Signal Desktop's decrypted database, with one exchange and one group."""
    path = tmp_path / "plain.sqlite"
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE conversations (
        id TEXT PRIMARY KEY, json TEXT, active_at INT, type TEXT, members TEXT, name TEXT,
        profileName TEXT, profileFamilyName TEXT, profileFullName TEXT, e164 TEXT, serviceId TEXT,
        groupId TEXT, profileLastFetchedAt INT, expireTimerVersion INT)""")
    con.execute("""CREATE TABLE messages (
        rowid INTEGER, id TEXT PRIMARY KEY, json TEXT, readStatus INT, expires_at INT, sent_at INT,
        schemaVersion INT, conversationId TEXT, received_at INT, hasAttachments INT, type TEXT,
        body TEXT, source TEXT, sourceServiceId TEXT, isErased INT)""")
    con.execute("INSERT INTO conversations (id, type, profileName, e164, serviceId) VALUES (?,?,?,?,?)",
                (CONV, "private", "theirhandle", THEM, THEIR_UUID))
    con.execute("INSERT INTO conversations (id, type, name, groupId) VALUES (?,?,?,?)",
                (GROUP_CONV, "group", "The Family", "Z3JvdXA="))
    rows = [
        ("m1", CONV, "incoming", "how are you keeping", THEM, _at(1)),
        ("m2", CONV, "outgoing", "all well here, thanks", None, _at(1, 13)),
        ("m3", CONV, "incoming", "glad to hear it", THEM, _at(2)),
        ("m4", CONV, "outgoing", "speak soon", None, _at(3)),
        ("g1", GROUP_CONV, "outgoing", "dinner on sunday", None, _at(4)),
    ]
    for mid, conv, kind, body, source, when in rows:
        con.execute("""INSERT INTO messages
            (id, conversationId, type, body, source, sent_at, received_at, hasAttachments, readStatus)
            VALUES (?,?,?,?,?,?,?,0,0)""", (mid, conv, kind, body, source, when, when))
    # NOT A MESSAGE. Signal Desktop keeps call history and empty rows in the same table, and they are
    # not somebody's writing: a corpus built from them learns punctuation from a placed call.
    con.execute("""INSERT INTO messages (id, conversationId, type, body, sent_at, hasAttachments)
                   VALUES ('c1', ?, 'call-history', NULL, ?, 0)""", (CONV, _at(5)))
    con.execute("""INSERT INTO messages (id, conversationId, type, body, sent_at, hasAttachments)
                   VALUES ('e1', ?, 'incoming', '   ', ?, 0)""", (CONV, _at(6)))
    con.commit()
    con.close()
    monkeypatch.setattr(ds, "_plain_db", lambda: path)
    return path


def test_a_conversation_holds_both_sides(desktop_db):
    """THE WHOLE POINT. The store this replaced returned only what the other person wrote."""
    msgs = ds.get_conversation(THEM, limit=50, own_number=OWN)
    assert [m.body for m in msgs] == [
        "how are you keeping", "all well here, thanks", "glad to hear it", "speak soon",
    ]
    assert [m.sender for m in msgs] == [THEM, OWN, THEM, OWN]


def test_an_outgoing_message_records_who_it_went_to(desktop_db):
    """The defect exactly: `recipient` was never set, so an outgoing message had no conversation."""
    mine = [m for m in ds.get_conversation(THEM, own_number=OWN) if m.sender == OWN]
    assert mine, "the person's own messages are in their own conversation"
    assert all(m.recipient == THEM for m in mine)


def test_it_answers_to_a_number_a_uuid_or_a_conversation_id(desktop_db):
    """A handle arrives spelled whichever way the caller happens to hold it."""
    for handle in (THEM, THEIR_UUID, CONV):
        assert len(ds.get_conversation(handle, own_number=OWN)) == 4, handle


def test_a_call_and_an_empty_message_are_not_writing(desktop_db):
    bodies = [m.body for m in ds.get_conversation(THEM, own_number=OWN)]
    assert all(b.strip() for b in bodies)
    assert len(bodies) == 4


def test_messages_come_back_oldest_last(desktop_db):
    stamps = [m.timestamp for m in ds.get_conversation(THEM, own_number=OWN)]
    assert stamps == sorted(stamps)


def test_a_limit_keeps_the_most_recent(desktop_db):
    msgs = ds.get_conversation(THEM, limit=2, own_number=OWN)
    assert [m.body for m in msgs] == ["glad to hear it", "speak soon"]


def test_since_drops_what_came_before(desktop_db):
    msgs = ds.get_conversation(THEM, own_number=OWN, since=datetime(2026, 3, 2))
    assert [m.body for m in msgs] == ["glad to hear it", "speak soon"]


def test_an_unknown_handle_is_no_conversation_not_an_error(desktop_db):
    assert ds.get_conversation("+15559999999", own_number=OWN) == []


def test_search_finds_both_sides(desktop_db):
    assert [m.body for m in ds.search_messages("well", own_number=OWN)] == ["all well here, thanks"]
    assert len(ds.search_messages("o", own_number=OWN)) >= 2


def test_search_can_be_narrowed_to_one_writer(desktop_db):
    out = ds.search_messages("e", sender=OWN, own_number=OWN)
    assert out and all(m.sender == OWN for m in out)


def test_a_percent_sign_is_searched_for_not_matched_as_a_wildcard(desktop_db):
    assert ds.search_messages("%", own_number=OWN) == []


def test_conversations_are_listed_with_their_counts(desktop_db):
    convs = {c["name"]: c for c in ds.list_conversations(own_number=OWN)}
    assert convs["theirhandle"]["message_count"] == 4
    assert convs["theirhandle"]["type"] == "direct"
    assert convs["The Family"]["type"] == "group"


def test_a_group_message_is_not_addressed_to_one_person(desktop_db):
    group = ds.get_conversation("The Family", own_number=OWN)
    assert group == [] or all(m.recipient is None for m in group)


def test_contacts_carry_a_name_and_something_to_read_by(desktop_db):
    contacts = {c["name"]: c for c in ds.list_contacts()}
    assert contacts["theirhandle"]["number"] == THEM
    assert contacts["theirhandle"]["uuid"] == THEIR_UUID
