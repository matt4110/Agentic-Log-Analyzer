"""
SQLite-backed running list of flagged indicators (IPs and domains), plus a
baseline table of previously-seen outbound destinations used to detect
*new* outbound connections.

No scoring by design - the goal is a factual timeline for an LLM (or you)
to interpret without a hidden weighting scheme biasing the read.
"""

import json
import sqlite3
from datetime import datetime, timezone


SCHEMA = """
CREATE TABLE IF NOT EXISTS actors (
    indicator   TEXT NOT NULL,
    type        TEXT NOT NULL CHECK(type IN ('ip', 'domain')),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    categories  TEXT NOT NULL DEFAULT '[]',   -- JSON list of detector categories that have fired
    hit_count   INTEGER NOT NULL DEFAULT 0,
    notes       TEXT DEFAULT '',
    PRIMARY KEY (indicator, type)
);

CREATE TABLE IF NOT EXISTS known_outbound_destinations (
    dst_ip      TEXT PRIMARY KEY,
    first_seen  TEXT NOT NULL
);
"""


class ActorDB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # -- actors -------------------------------------------------------
    def upsert_actor(self, indicator, indicator_type, category, run_date=None):
        """
        Add or update a flagged indicator. `category` is a single detector
        name (e.g. 'port_scan', 'sqli'); it gets appended to the actor's
        category list if not already present.

        Does NOT commit - call commit() once after a batch of upserts.
        Committing per-call forces an fsync to disk every time, which is
        fine for a handful of writes but turns thousands of flags into a
        multi-minute bottleneck for no reason (43.9s for ~18k upserts in
        testing, vs <1s batched).
        """
        now = run_date or datetime.now(timezone.utc).isoformat()
        cur = self.conn.execute(
            "SELECT categories, hit_count FROM actors WHERE indicator=? AND type=?",
            (indicator, indicator_type),
        )
        row = cur.fetchone()
        if row is None:
            cats = [category]
            self.conn.execute(
                "INSERT INTO actors (indicator, type, first_seen, last_seen, categories, hit_count) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (indicator, indicator_type, now, now, json.dumps(cats), 1),
            )
        else:
            cats = json.loads(row[0])
            if category not in cats:
                cats.append(category)
            self.conn.execute(
                "UPDATE actors SET last_seen=?, categories=?, hit_count=hit_count+1 "
                "WHERE indicator=? AND type=?",
                (now, json.dumps(cats), indicator, indicator_type),
            )

    def commit(self):
        self.conn.commit()

    def all_actors(self):
        cur = self.conn.execute("SELECT indicator, type, first_seen, last_seen, categories, hit_count, notes FROM actors")
        return [
            {
                "indicator": r[0], "type": r[1], "first_seen": r[2], "last_seen": r[3],
                "categories": json.loads(r[4]), "hit_count": r[5], "notes": r[6],
            }
            for r in cur.fetchall()
        ]

    def is_known_actor(self, indicator, indicator_type):
        cur = self.conn.execute(
            "SELECT 1 FROM actors WHERE indicator=? AND type=?", (indicator, indicator_type)
        )
        return cur.fetchone() is not None

    # -- outbound destination baseline --------------------------------
    def is_known_outbound(self, dst_ip):
        cur = self.conn.execute(
            "SELECT 1 FROM known_outbound_destinations WHERE dst_ip=?", (dst_ip,)
        )
        return cur.fetchone() is not None

    def record_outbound(self, dst_ip, run_date=None):
        now = run_date or datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT OR IGNORE INTO known_outbound_destinations (dst_ip, first_seen) VALUES (?, ?)",
            (dst_ip, now),
        )
