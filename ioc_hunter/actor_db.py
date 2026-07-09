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
        self._migrate()
        self.conn.commit()

    def _migrate(self):
        """Add columns introduced after initial deployments. Safe to run on
        both fresh and existing databases."""
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(actors)")}
        if "days_seen" not in cols:
            self.conn.execute("ALTER TABLE actors ADD COLUMN days_seen INTEGER NOT NULL DEFAULT 0")

    def close(self):
        self.conn.close()

    # -- actors -------------------------------------------------------
    def get_actor(self, indicator, indicator_type):
        """History lookup for report enrichment. Call BEFORE upserting the
        current run's flags so the returned history reflects prior runs,
        not the run in progress."""
        cur = self.conn.execute(
            "SELECT first_seen, last_seen, categories, hit_count, days_seen "
            "FROM actors WHERE indicator=? AND type=?",
            (indicator, indicator_type),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "first_seen": row[0],
            "last_seen": row[1],
            "historical_categories": json.loads(row[2]),
            "hit_count": row[3],
            "days_seen": row[4],
        }

    def increment_days_seen(self, indicators):
        """Bump days_seen once per run for each unique (indicator, type).
        Call once per daily run, after upserts, with the run's unique set."""
        self.conn.executemany(
            "UPDATE actors SET days_seen = days_seen + 1 WHERE indicator=? AND type=?",
            list(indicators),
        )

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
