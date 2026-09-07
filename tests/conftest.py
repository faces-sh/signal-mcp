"""Shared fixtures.

HISTORY IS READ FROM SIGNAL DESKTOP (faced#628), so a test that wants a conversation to exist puts it
in a Signal Desktop shaped database, not in the local store. The local store is still real and still
tested: it is what the daemon writes into and what feeds the unread badge. The two are different
questions now, and a test says which one it means.
"""

import sqlite3

import pytest

from signal_mcp import desktop_store as _desktop_store


class DesktopFixture:
    """A stand-in for Signal Desktop's decrypted database, with its own column names.

    No key, no keychain, no real account: `desktop_store._plain_db` is pointed straight at a plaintext
    file, which is what it would have produced anyway.
    """

    def __init__(self, path):
        self.path = path
        self._next = 0
        conn = sqlite3.connect(path)
        conn.execute("""CREATE TABLE conversations (
            id TEXT PRIMARY KEY, json TEXT, active_at INT, type TEXT, members TEXT, name TEXT,
            profileName TEXT, profileFamilyName TEXT, profileFullName TEXT, e164 TEXT, serviceId TEXT,
            groupId TEXT, profileLastFetchedAt INT, expireTimerVersion INT)""")
        conn.execute("""CREATE TABLE messages (
            rowid INTEGER, id TEXT PRIMARY KEY, json TEXT, readStatus INT, expires_at INT, sent_at INT,
            schemaVersion INT, conversationId TEXT, received_at INT, hasAttachments INT, type TEXT,
            body TEXT, source TEXT, sourceServiceId TEXT, isErased INT)""")
        conn.commit()
        conn.close()

    def contact(self, number, name=None, uuid=None, conv_id=None):
        conv_id = conv_id or f"conv-{number}"
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO conversations (id, type, profileName, e164, serviceId) "
                "VALUES (?, 'private', ?, ?, ?)", (conv_id, name, number, uuid))
        return conv_id

    def group(self, group_id, name, conv_id=None):
        conv_id = conv_id or f"conv-{group_id}"
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT OR REPLACE INTO conversations (id, type, name, groupId) "
                         "VALUES (?, 'group', ?, ?)", (conv_id, name, group_id))
        return conv_id

    def message(self, conv_id, body, outgoing=False, when=None, source=None, read=True):
        """One message in a conversation. `when` is milliseconds; they order by it."""
        self._next += 1
        when = when if when is not None else 1_700_000_000_000 + self._next * 1000
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO messages (id, conversationId, type, body, sent_at, received_at, "
                "source, hasAttachments, readStatus) VALUES (?,?,?,?,?,?,?,0,?)",
                (f"m{self._next}", conv_id, "outgoing" if outgoing else "incoming", body,
                 when, when, source, 0 if read else 1))
        return f"desktop_m{self._next}"


@pytest.fixture(autouse=True)
def _no_real_signal_desktop(monkeypatch):
    """NO TEST EVER READS THE MACHINE'S OWN SIGNAL DESKTOP.

    `desktop_store.available()` is true on any developer's Mac that has Signal installed, so without this
    the suite quietly reads their real history: it turned up as `assert 198 == 2`, 198 being the number of
    people in one person's contact list. A test that touches real data is not a test, and on a laptop it
    is somebody's private messages.
    """
    monkeypatch.setattr(_desktop_store, "available", lambda: False)


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    """Signal Desktop, as far as `desktop_store` is concerned."""
    fixture = DesktopFixture(tmp_path / "signal-desktop.sqlite")
    monkeypatch.setattr(_desktop_store, "_plain_db", lambda: fixture.path)
    monkeypatch.setattr(_desktop_store, "available", lambda: True)
    return fixture
