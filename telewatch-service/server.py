#!/usr/bin/env python3
import json
import os
import secrets
import sqlite3
import hashlib
import hmac
import datetime as dt
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST = os.getenv('TELEWATCH_HOST', '127.0.0.1')
PORT = int(os.getenv('TELEWATCH_PORT', '9191'))
DB_PATH = Path(os.getenv('TELEWATCH_DB_PATH', '/root/Frenzynet/telewatch-service/data/telewatch.db'))
ROOM_TTL_HOURS = int(os.getenv('TELEWATCH_ROOM_TTL_HOURS', '24'))
EMPTY_ROOM_TTL_MINUTES = max(10, min(1440, int(os.getenv('TELEWATCH_EMPTY_ROOM_TTL_MINUTES', '60'))))
PUBLIC_ROOM_PREFIX = os.getenv('TELEWATCH_PUBLIC_ROOM_PREFIX', 'WATCH').strip().upper()[:6] or 'WATCH'
PUBLIC_ROOM_COUNT = max(1, min(35, int(os.getenv('TELEWATCH_PUBLIC_ROOM_COUNT', '35'))))
MAX_ROOMS = max(1, min(35, int(os.getenv('TELEWATCH_MAX_ROOMS', '35'))))
MAX_PARTICIPANTS_PER_ROOM = max(2, min(50, int(os.getenv('TELEWATCH_MAX_PARTICIPANTS_PER_ROOM', '50'))))
TELEWATCH_ADMIN_KEY = os.getenv('TELEWATCH_ADMIN_KEY', '').strip()
TELEWATCH_ADMIN_CODE = os.getenv('TELEWATCH_ADMIN_CODE', '1978Luke$$').strip()
TELEWATCH_OWNER_USERNAME = os.getenv('TELEWATCH_OWNER_USERNAME', 'Trimbledustn@gmail.com').strip().lower()
TELEWATCH_OWNER_PASSWORD = os.getenv('TELEWATCH_OWNER_PASSWORD', '1978Luke$$').strip()
TELEWATCH_AUTH_SALT = os.getenv('TELEWATCH_AUTH_SALT', 'frenzy-telewatch-salt-v1').strip()
ADMIN_SESSION_TTL_HOURS = max(1, min(168, int(os.getenv('TELEWATCH_ADMIN_SESSION_TTL_HOURS', '24'))))
USER_SESSION_TTL_HOURS = max(1, min(720, int(os.getenv('TELEWATCH_USER_SESSION_TTL_HOURS', '168'))))


def utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def stable_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def clean_name(raw: str, fallback: str = 'Guest') -> str:
    keep = ''.join(ch for ch in str(raw or '').strip() if ch.isalnum() or ch in ' _-.')
    return (keep[:32] or fallback)


def clean_username(raw: str) -> str:
    val = str(raw or '').strip().lower()
    return val[:160]


def clean_theme_key(raw: str, fallback: str = 'clean') -> str:
    keep = ''.join(ch for ch in str(raw or '').strip().lower() if ch.isalnum() or ch in {'_', '-'})
    return (keep[:32] or fallback)


def hash_password(password: str) -> str:
    body = f'{TELEWATCH_AUTH_SALT}:{str(password or "")}'.encode('utf-8', errors='replace')
    return hashlib.sha256(body).hexdigest()


def verify_password(password: str, expected_hash: str) -> bool:
    actual = hash_password(password)
    return hmac.compare_digest(actual, str(expected_hash or '').strip().lower())


def room_code(length: int = 6) -> str:
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def normalize_room_code(raw: str, fallback: str = '') -> str:
    cleaned = ''.join(ch for ch in str(raw or '').strip().upper() if ch.isalnum() or ch in {'-', '_'})
    if len(cleaned) < 3:
        return fallback
    return cleaned[:24]


def public_room_codes() -> list[str]:
    return [f'{PUBLIC_ROOM_PREFIX}{i:02d}' for i in range(1, PUBLIC_ROOM_COUNT + 1)]


def is_public_room(code: str) -> bool:
    return code in set(public_room_codes())


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def ensure_schema() -> None:
    with get_db() as conn:
        conn.executescript(
            '''
            CREATE TABLE IF NOT EXISTS watch_rooms (
              room_code TEXT PRIMARY KEY,
              host_token TEXT NOT NULL UNIQUE,
              title TEXT,
              media_url TEXT,
              theme_key TEXT NOT NULL DEFAULT 'clean',
              allow_webcam INTEGER NOT NULL DEFAULT 1,
              cohost_can_kick INTEGER NOT NULL DEFAULT 1,
              cohost_can_mute INTEGER NOT NULL DEFAULT 1,
              cohost_can_access INTEGER NOT NULL DEFAULT 1,
              cohost_can_pin INTEGER NOT NULL DEFAULT 1,
              access_mode TEXT NOT NULL DEFAULT 'public',
              is_private INTEGER NOT NULL DEFAULT 0,
              delete_on_host_leave INTEGER NOT NULL DEFAULT 1,
              playback_sec REAL NOT NULL DEFAULT 0,
              is_playing INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS watch_participants (
              participant_token TEXT PRIMARY KEY,
              participant_id TEXT UNIQUE,
              room_code TEXT NOT NULL,
              display_name TEXT NOT NULL,
              is_host INTEGER NOT NULL DEFAULT 0,
              is_cohost INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY (room_code) REFERENCES watch_rooms(room_code) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watch_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              room_code TEXT NOT NULL,
              actor_name TEXT NOT NULL,
              event_type TEXT NOT NULL,
              payload_json TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY (room_code) REFERENCES watch_rooms(room_code) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watch_join_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              request_token TEXT NOT NULL UNIQUE,
              room_code TEXT NOT NULL,
              display_name TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              participant_token TEXT,
              participant_id TEXT,
              responded_by TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              responded_at TEXT,
              FOREIGN KEY (room_code) REFERENCES watch_rooms(room_code) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watch_room_invites (
              invite_token TEXT PRIMARY KEY,
              room_code TEXT NOT NULL,
              created_by TEXT NOT NULL,
              max_uses INTEGER NOT NULL DEFAULT 0,
              used_count INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              expires_at TEXT NOT NULL,
              FOREIGN KEY (room_code) REFERENCES watch_rooms(room_code) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watch_room_bans (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              room_code TEXT NOT NULL,
              display_name_norm TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              expires_at TEXT NOT NULL,
              FOREIGN KEY (room_code) REFERENCES watch_rooms(room_code) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watch_admins (
              username TEXT PRIMARY KEY,
              password_hash TEXT NOT NULL,
              is_owner INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS watch_admin_sessions (
              session_token TEXT PRIMARY KEY,
              username TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY (username) REFERENCES watch_admins(username) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watch_settings (
              setting_key TEXT PRIMARY KEY,
              setting_value TEXT NOT NULL,
              updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS watch_users (
              username TEXT PRIMARY KEY,
              password_hash TEXT NOT NULL,
              display_name TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS watch_user_sessions (
              session_token TEXT PRIMARY KEY,
              username TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY (username) REFERENCES watch_users(username) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watch_user_saved_rooms (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL,
              room_code TEXT NOT NULL,
              room_title TEXT NOT NULL DEFAULT '',
              saved_name TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              updated_at TEXT NOT NULL DEFAULT (datetime('now')),
              UNIQUE(username, room_code),
              FOREIGN KEY (username) REFERENCES watch_users(username) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS watch_ip_blocks (
              ip_addr TEXT PRIMARY KEY,
              reason TEXT NOT NULL DEFAULT '',
              created_by TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS watch_user_blocks (
              username TEXT PRIMARY KEY,
              reason TEXT NOT NULL DEFAULT '',
              created_by TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_watch_participants_room ON watch_participants(room_code, last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_watch_events_room ON watch_events(room_code, id);
            CREATE INDEX IF NOT EXISTS idx_watch_join_requests_room_status ON watch_join_requests(room_code, status, created_at);
            CREATE INDEX IF NOT EXISTS idx_watch_room_invites_room_expires ON watch_room_invites(room_code, expires_at);
            CREATE INDEX IF NOT EXISTS idx_watch_room_bans_room_name ON watch_room_bans(room_code, display_name_norm, expires_at);
            CREATE INDEX IF NOT EXISTS idx_watch_admin_sessions_last_seen ON watch_admin_sessions(last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_watch_user_sessions_last_seen ON watch_user_sessions(last_seen_at);
            CREATE INDEX IF NOT EXISTS idx_watch_user_saved_rooms_user ON watch_user_saved_rooms(username, updated_at);
            '''
        )
        try:
            conn.execute("ALTER TABLE watch_participants ADD COLUMN participant_id TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_participants ADD COLUMN is_cohost INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN delete_on_host_leave INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN theme_key TEXT NOT NULL DEFAULT 'clean'")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'public'")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN allow_webcam INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN cohost_can_kick INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN cohost_can_mute INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN cohost_can_access INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE watch_rooms ADD COLUMN cohost_can_pin INTEGER NOT NULL DEFAULT 1")
        except sqlite3.OperationalError:
            pass
        conn.execute(
            '''
            UPDATE watch_rooms
            SET theme_key='clean'
            WHERE theme_key IS NULL OR trim(theme_key)=''
            '''
        )
        conn.execute(
            '''
            UPDATE watch_rooms
            SET access_mode=CASE WHEN is_private=1 THEN 'invite' ELSE 'public' END
            WHERE access_mode IS NULL OR trim(access_mode)=''
            '''
        )
        conn.execute(
            '''
            UPDATE watch_participants
            SET participant_id = lower(hex(randomblob(6)))
            WHERE participant_id IS NULL OR trim(participant_id)=''
            '''
        )
        owner_username = clean_username(TELEWATCH_OWNER_USERNAME)
        owner_hash = hash_password(TELEWATCH_OWNER_PASSWORD)
        if owner_username and owner_hash:
            conn.execute(
                '''
                INSERT INTO watch_admins(username, password_hash, is_owner, created_at, updated_at)
                VALUES(?,?,1,datetime('now'),datetime('now'))
                ON CONFLICT(username) DO UPDATE SET
                  password_hash=excluded.password_hash,
                  is_owner=1,
                  updated_at=datetime('now')
                ''',
                (owner_username, owner_hash),
            )
        conn.execute(
            "DELETE FROM watch_admin_sessions WHERE last_seen_at < datetime('now', ?)",
            (f'-{ADMIN_SESSION_TTL_HOURS} hours',),
        )
        conn.execute(
            "DELETE FROM watch_user_sessions WHERE last_seen_at < datetime('now', ?)",
            (f'-{USER_SESSION_TTL_HOURS} hours',),
        )
        conn.execute(
            '''
            INSERT INTO watch_settings(setting_key, setting_value, updated_at)
            VALUES('empty_room_ttl_minutes', ?, datetime('now'))
            ON CONFLICT(setting_key) DO NOTHING
            ''',
            (str(EMPTY_ROOM_TTL_MINUTES),),
        )
        conn.execute("DELETE FROM watch_room_bans WHERE expires_at <= datetime('now')")
        conn.execute("DELETE FROM watch_room_invites WHERE expires_at <= datetime('now') OR (max_uses > 0 AND used_count >= max_uses)")
        ensure_public_rooms(conn)
        conn.commit()


def get_empty_room_ttl_minutes(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT setting_value FROM watch_settings WHERE setting_key='empty_room_ttl_minutes' LIMIT 1"
    ).fetchone()
    raw = str(row['setting_value']).strip() if row is not None else str(EMPTY_ROOM_TTL_MINUTES)
    try:
        val = int(raw)
    except Exception:
        val = EMPTY_ROOM_TTL_MINUTES
    return max(10, min(1440, val))


def cleanup_rooms(conn: sqlite3.Connection) -> None:
    placeholders = ','.join(['?'] * len(public_room_codes()))
    ttl_window = f'-{get_empty_room_ttl_minutes(conn)} minutes'
    conn.execute(
        f"""
        DELETE FROM watch_rooms
        WHERE room_code NOT IN ({placeholders})
          AND updated_at < datetime('now', ?)
          AND NOT EXISTS (
            SELECT 1
            FROM watch_participants p
            WHERE p.room_code=watch_rooms.room_code
              AND p.last_seen_at >= datetime('now', ?)
          )
        """,
        tuple(public_room_codes()) + (ttl_window, ttl_window),
    )
    conn.execute("DELETE FROM watch_room_bans WHERE expires_at <= datetime('now')")
    conn.execute("DELETE FROM watch_room_invites WHERE expires_at <= datetime('now') OR (max_uses > 0 AND used_count >= max_uses)")


def room_payload(room_row: sqlite3.Row) -> dict:
    access_mode = str(room_row['access_mode'] if 'access_mode' in room_row.keys() else '').strip().lower()
    if access_mode not in {'public', 'invite', 'closed'}:
        access_mode = 'invite' if bool(room_row['is_private']) else 'public'
    return {
        'roomCode': room_row['room_code'],
        'title': room_row['title'] or '',
        'mediaUrl': room_row['media_url'] or '',
        'themeKey': clean_theme_key(room_row['theme_key'] if 'theme_key' in room_row.keys() else 'clean'),
        'allowWebcam': bool(room_row['allow_webcam']) if 'allow_webcam' in room_row.keys() else True,
        'cohostPerms': {
            'kick': bool(room_row['cohost_can_kick']) if 'cohost_can_kick' in room_row.keys() else True,
            'mute': bool(room_row['cohost_can_mute']) if 'cohost_can_mute' in room_row.keys() else True,
            'access': bool(room_row['cohost_can_access']) if 'cohost_can_access' in room_row.keys() else True,
            'pin': bool(room_row['cohost_can_pin']) if 'cohost_can_pin' in room_row.keys() else True,
        },
        'accessMode': access_mode,
        'isPrivate': bool(room_row['is_private']),
        'deleteOnHostLeave': bool(room_row['delete_on_host_leave']),
        'playbackSec': float(room_row['playback_sec'] or 0.0),
        'isPlaying': bool(room_row['is_playing']),
        'updatedAt': room_row['updated_at'],
    }


def ensure_public_rooms(conn: sqlite3.Connection) -> None:
    for code in public_room_codes():
        exists = conn.execute('SELECT 1 FROM watch_rooms WHERE room_code=?', (code,)).fetchone()
        if exists is not None:
            continue
        conn.execute(
            '''
            INSERT INTO watch_rooms(room_code, host_token, title, media_url, theme_key, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, created_at, updated_at)
            VALUES(?,?,?,?,?,'public',0,1,0,0,datetime('now'),datetime('now'))
            ''',
            (code, secrets.token_urlsafe(32), f'Public Room {code[-2:]}', '', 'clean'),
        )
        conn.execute(
            '''
            INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at)
            VALUES(?,?,?,?,datetime('now'))
            ''',
            (code, 'FrenzyHost', 'room_seeded', stable_json({'public': True})),
        )


def create_admin_session(conn: sqlite3.Connection, username: str) -> str:
    session_token = secrets.token_urlsafe(40)
    conn.execute(
        '''
        INSERT INTO watch_admin_sessions(session_token, username, created_at, last_seen_at)
        VALUES(?,?,datetime('now'),datetime('now'))
        ''',
        (session_token, clean_username(username)),
    )
    return session_token


def create_user_session(conn: sqlite3.Connection, username: str) -> str:
    session_token = secrets.token_urlsafe(40)
    conn.execute(
        '''
        INSERT INTO watch_user_sessions(session_token, username, created_at, last_seen_at)
        VALUES(?,?,datetime('now'),datetime('now'))
        ''',
        (session_token, clean_username(username)),
    )
    return session_token


def validate_admin_session(conn: sqlite3.Connection, session_token: str) -> sqlite3.Row | None:
    token = str(session_token or '').strip()
    if not token:
        return None
    row = conn.execute(
        '''
        SELECT s.session_token, s.username, a.is_owner
        FROM watch_admin_sessions s
        JOIN watch_admins a ON a.username=s.username
        WHERE s.session_token=? AND s.last_seen_at >= datetime('now', ?)
        LIMIT 1
        ''',
        (token, f'-{ADMIN_SESSION_TTL_HOURS} hours'),
    ).fetchone()
    if row is None:
        return None
    conn.execute("UPDATE watch_admin_sessions SET last_seen_at=datetime('now') WHERE session_token=?", (token,))
    return row


def validate_user_session(conn: sqlite3.Connection, session_token: str) -> sqlite3.Row | None:
    token = str(session_token or '').strip()
    if not token:
        return None
    row = conn.execute(
        '''
        SELECT s.session_token, s.username, u.display_name
        FROM watch_user_sessions s
        JOIN watch_users u ON u.username=s.username
        WHERE s.session_token=? AND s.last_seen_at >= datetime('now', ?)
        LIMIT 1
        ''',
        (token, f'-{USER_SESSION_TTL_HOURS} hours'),
    ).fetchone()
    if row is None:
        return None
    conn.execute("UPDATE watch_user_sessions SET last_seen_at=datetime('now') WHERE session_token=?", (token,))
    return row


class TelewatchHandler(BaseHTTPRequestHandler):
    server_version = 'Telewatch/1.0'

    def log_message(self, fmt, *args):
        return

    def _json(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=True).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            n = int(self.headers.get('Content-Length', '0'))
        except Exception:
            return None, 'invalid_content_length'
        if n > 65536:
            return None, 'body_too_large'
        try:
            raw = self.rfile.read(max(0, n)) if n > 0 else b'{}'
            return json.loads(raw.decode('utf-8', errors='replace') or '{}'), None
        except Exception:
            return None, 'invalid_json'

    def _client_ip(self) -> str:
        forwarded = str(self.headers.get('X-Forwarded-For', '')).strip()
        if forwarded:
            # Use the first IP from standard X-Forwarded-For chain.
            return forwarded.split(',')[0].strip()[:64]
        if self.client_address and self.client_address[0]:
            return str(self.client_address[0]).strip()[:64]
        return ''

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        q = parse_qs(parsed.query)

        public_rooms_paths = {
            '/public-rooms',
            '/api/public-rooms',
            '/api/telewatch/public-rooms',
            '/api/telewatch/api/public-rooms',
        }
        state_paths = {'/watch/state', '/api/watch/state', '/api/telewatch/watch/state', '/api/telewatch/api/watch/state'}
        if path in public_rooms_paths:
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                rooms = []
                for code in public_room_codes():
                    room = conn.execute(
                        'SELECT room_code, title, media_url, theme_key, allow_webcam, cohost_can_kick, cohost_can_mute, cohost_can_access, cohost_can_pin, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, updated_at FROM watch_rooms WHERE room_code=?',
                        (code,),
                    ).fetchone()
                    if room is None:
                        continue
                    active_count = conn.execute(
                        '''
                        SELECT COUNT(*)
                        FROM watch_participants
                        WHERE room_code=? AND last_seen_at >= datetime('now', '-20 minutes')
                        ''',
                        (code,),
                    ).fetchone()[0]
                    rooms.append(
                        {
                            'roomCode': code,
                            'title': room['title'] or f'Public Room {code[-2:]}',
                            'themeKey': clean_theme_key(room['theme_key']),
                            'accessMode': 'public',
                            'activeCount': int(active_count),
                            'isLive': bool(active_count > 0),
                            'joinUrl': f'/telewatch/?room={code}',
                        }
                    )
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'rooms': rooms, 'serverNow': utc_iso()})
            return

        if path not in state_paths:
            self._json(HTTPStatus.NOT_FOUND, {'error': 'not_found'})
            return

        room_code_val = normalize_room_code((q.get('roomCode') or [''])[0], '')
        participant_token = str((q.get('participantToken') or [''])[0]).strip()[:128]
        try:
            since_event_id = int(str((q.get('sinceEventId') or ['0'])[0]).strip() or '0')
        except Exception:
            since_event_id = 0
        try:
            wait_ms = int(str((q.get('waitMs') or ['0'])[0]).strip() or '0')
        except Exception:
            wait_ms = 0
        wait_ms = max(0, min(25000, wait_ms))

        if not room_code_val or not participant_token:
            self._json(HTTPStatus.BAD_REQUEST, {'error': 'roomCode_and_participantToken_required'})
            return

        with get_db() as conn:
            ensure_public_rooms(conn)
            cleanup_rooms(conn)
            part = conn.execute(
                'SELECT participant_id, display_name, is_host, is_cohost FROM watch_participants WHERE participant_token=? AND room_code=?',
                (participant_token, room_code_val),
            ).fetchone()
            if part is None:
                self._json(HTTPStatus.UNAUTHORIZED, {'error': 'invalid_participant'})
                return

            conn.execute("UPDATE watch_participants SET last_seen_at=datetime('now') WHERE participant_token=?", (participant_token,))

            room = conn.execute(
                'SELECT room_code, title, media_url, theme_key, allow_webcam, cohost_can_kick, cohost_can_mute, cohost_can_access, cohost_can_pin, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, updated_at FROM watch_rooms WHERE room_code=?',
                (room_code_val,),
            ).fetchone()
            if room is None:
                self._json(HTTPStatus.NOT_FOUND, {'error': 'room_not_found'})
                return

            participants_rows = conn.execute(
                '''
                SELECT participant_id, display_name, is_host, is_cohost, created_at
                FROM watch_participants
                WHERE room_code=? AND last_seen_at >= datetime('now', '-30 minutes')
                ORDER BY is_host DESC, created_at ASC
                ''',
                (room_code_val,),
            ).fetchall()
            if participants_rows and not any(bool(r['is_host']) for r in participants_rows):
                cohost_candidates = [r for r in participants_rows if bool(r['is_cohost'])]
                promote = cohost_candidates[0] if cohost_candidates else participants_rows[0]
                conn.execute('UPDATE watch_participants SET is_host=0 WHERE room_code=?', (room_code_val,))
                conn.execute(
                    'UPDATE watch_participants SET is_host=1 WHERE room_code=? AND participant_id=?',
                    (room_code_val, promote['participant_id']),
                )
                conn.execute(
                    '''
                    INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at)
                    VALUES(?,?,?,?,datetime('now'))
                    ''',
                    (
                        room_code_val,
                        str(promote['display_name'] or 'Host'),
                        'host_handoff',
                        stable_json(
                            {
                                'toParticipantId': str(promote['participant_id'] or ''),
                                'toDisplayName': str(promote['display_name'] or ''),
                                'reason': 'previous_host_inactive',
                            }
                        ),
                    ),
                )
                participants_rows = conn.execute(
                    '''
                    SELECT participant_id, display_name, is_host, is_cohost, created_at
                    FROM watch_participants
                    WHERE room_code=? AND last_seen_at >= datetime('now', '-30 minutes')
                    ORDER BY is_host DESC, created_at ASC
                    ''',
                    (room_code_val,),
                ).fetchall()

            active_count = int(
                conn.execute(
                    '''
                    SELECT COUNT(*)
                    FROM watch_participants
                    WHERE room_code=? AND last_seen_at >= datetime('now', '-20 minutes')
                    ''',
                    (room_code_val,),
                ).fetchone()[0]
            )
            baseline_active_count = int(active_count)
            baseline_room_updated = str(room['updated_at'] or '')
            pending_join_requests = []
            can_manage_joins = bool(part['is_host']) or bool(part['is_cohost'])
            baseline_pending_count = 0
            if can_manage_joins:
                req_rows = conn.execute(
                    '''
                    SELECT request_token, display_name, created_at
                    FROM watch_join_requests
                    WHERE room_code=? AND status='pending'
                    ORDER BY created_at ASC
                    LIMIT 60
                    ''',
                    (room_code_val,),
                ).fetchall()
                pending_join_requests = [
                    {
                        'requestToken': r['request_token'],
                        'displayName': r['display_name'],
                        'createdAt': r['created_at'],
                    }
                    for r in req_rows
                ]
                baseline_pending_count = len(pending_join_requests)

            rows = conn.execute(
                '''
                SELECT id, actor_name, event_type, payload_json, created_at
                FROM watch_events
                WHERE room_code=? AND id>?
                ORDER BY id ASC
                LIMIT 120
                ''',
                (room_code_val, max(0, since_event_id)),
            ).fetchall()

            deadline = time.monotonic() + (wait_ms / 1000.0)
            while wait_ms > 0 and not rows and time.monotonic() < deadline:
                room_tick = conn.execute(
                    'SELECT updated_at FROM watch_rooms WHERE room_code=?',
                    (room_code_val,),
                ).fetchone()
                if room_tick is None:
                    self._json(HTTPStatus.NOT_FOUND, {'error': 'room_not_found'})
                    return
                if str(room_tick['updated_at'] or '') != baseline_room_updated:
                    room = conn.execute(
                        'SELECT room_code, title, media_url, theme_key, allow_webcam, cohost_can_kick, cohost_can_mute, cohost_can_access, cohost_can_pin, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, updated_at FROM watch_rooms WHERE room_code=?',
                        (room_code_val,),
                    ).fetchone()
                    break
                active_tick = int(
                    conn.execute(
                        '''
                        SELECT COUNT(*)
                        FROM watch_participants
                        WHERE room_code=? AND last_seen_at >= datetime('now', '-20 minutes')
                        ''',
                        (room_code_val,),
                    ).fetchone()[0]
                )
                if active_tick != baseline_active_count:
                    active_count = active_tick
                    break
                if can_manage_joins:
                    pending_tick = int(
                        conn.execute(
                            '''
                            SELECT COUNT(*)
                            FROM watch_join_requests
                            WHERE room_code=? AND status='pending'
                            ''',
                            (room_code_val,),
                        ).fetchone()[0]
                    )
                    if pending_tick != baseline_pending_count:
                        break
                time.sleep(0.45)
                rows = conn.execute(
                    '''
                    SELECT id, actor_name, event_type, payload_json, created_at
                    FROM watch_events
                    WHERE room_code=? AND id>?
                    ORDER BY id ASC
                    LIMIT 120
                    ''',
                    (room_code_val, max(0, since_event_id)),
                ).fetchall()

            events = []
            for row in rows:
                payload = {}
                try:
                    payload = json.loads(row['payload_json'] or '{}')
                except Exception:
                    payload = {}
                events.append(
                    {
                        'id': int(row['id']),
                        'actor': row['actor_name'],
                        'type': row['event_type'],
                        'payload': payload,
                        'createdAt': row['created_at'],
                    }
                )

            participants_rows = conn.execute(
                '''
                SELECT participant_id, display_name, is_host, is_cohost, created_at
                FROM watch_participants
                WHERE room_code=? AND last_seen_at >= datetime('now', '-30 minutes')
                ORDER BY is_host DESC, created_at ASC
                ''',
                (room_code_val,),
            ).fetchall()
            active_count = int(
                conn.execute(
                    '''
                    SELECT COUNT(*)
                    FROM watch_participants
                    WHERE room_code=? AND last_seen_at >= datetime('now', '-20 minutes')
                    ''',
                    (room_code_val,),
                ).fetchone()[0]
            )
            room = conn.execute(
                'SELECT room_code, title, media_url, theme_key, allow_webcam, cohost_can_kick, cohost_can_mute, cohost_can_access, cohost_can_pin, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, updated_at FROM watch_rooms WHERE room_code=?',
                (room_code_val,),
            ).fetchone()
            if room is None:
                self._json(HTTPStatus.NOT_FOUND, {'error': 'room_not_found'})
                return
            if can_manage_joins:
                req_rows = conn.execute(
                    '''
                    SELECT request_token, display_name, created_at
                    FROM watch_join_requests
                    WHERE room_code=? AND status='pending'
                    ORDER BY created_at ASC
                    LIMIT 60
                    ''',
                    (room_code_val,),
                ).fetchall()
                pending_join_requests = [
                    {
                        'requestToken': r['request_token'],
                        'displayName': r['display_name'],
                        'createdAt': r['created_at'],
                    }
                    for r in req_rows
                ]
            conn.commit()

        self._json(
            HTTPStatus.OK,
            {
                'ok': True,
                'room': room_payload(room),
                'participant': {'displayName': part['display_name'], 'isHost': bool(part['is_host']), 'isCohost': bool(part['is_cohost'])},
                'selfParticipantId': part['participant_id'],
                'participants': [
                    {
                        'participantId': r['participant_id'],
                        'displayName': r['display_name'],
                        'isHost': bool(r['is_host']),
                        'isCohost': bool(r['is_cohost']),
                        'isSelf': bool(r['participant_id'] == part['participant_id']),
                    }
                    for r in participants_rows
                ],
                'activeCount': int(active_count),
                'events': events,
                'pendingJoinRequests': pending_join_requests,
                'serverNow': utc_iso(),
            },
        )

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        payload, err = self._read_json()
        if err:
            self._json(HTTPStatus.BAD_REQUEST, {'error': err})
            return

        create_paths = {'/watch/create', '/api/watch/create', '/api/telewatch/watch/create', '/api/telewatch/api/watch/create'}
        join_paths = {'/watch/join', '/api/watch/join', '/api/telewatch/watch/join', '/api/telewatch/api/watch/join'}
        admin_login_paths = {
            '/watch/admin/login',
            '/api/watch/admin/login',
            '/api/telewatch/watch/admin/login',
            '/api/telewatch/api/watch/admin/login',
        }
        admin_add_paths = {
            '/watch/admin/add',
            '/api/watch/admin/add',
            '/api/telewatch/watch/admin/add',
            '/api/telewatch/api/watch/admin/add',
        }
        admin_list_paths = {
            '/watch/admin/list',
            '/api/watch/admin/list',
            '/api/telewatch/watch/admin/list',
            '/api/telewatch/api/watch/admin/list',
        }
        admin_remove_paths = {
            '/watch/admin/remove',
            '/api/watch/admin/remove',
            '/api/telewatch/watch/admin/remove',
            '/api/telewatch/api/watch/admin/remove',
        }
        admin_logout_paths = {
            '/watch/admin/logout',
            '/api/watch/admin/logout',
            '/api/telewatch/watch/admin/logout',
            '/api/telewatch/api/watch/admin/logout',
        }
        admin_rooms_paths = {
            '/watch/admin/rooms',
            '/api/watch/admin/rooms',
            '/api/telewatch/watch/admin/rooms',
            '/api/telewatch/api/watch/admin/rooms',
        }
        admin_settings_paths = {
            '/watch/admin/settings',
            '/api/watch/admin/settings',
            '/api/telewatch/watch/admin/settings',
            '/api/telewatch/api/watch/admin/settings',
        }
        user_register_paths = {
            '/watch/user/register',
            '/api/watch/user/register',
            '/api/telewatch/watch/user/register',
            '/api/telewatch/api/watch/user/register',
        }
        user_login_paths = {
            '/watch/user/login',
            '/api/watch/user/login',
            '/api/telewatch/watch/user/login',
            '/api/telewatch/api/watch/user/login',
        }
        user_me_paths = {
            '/watch/user/me',
            '/api/watch/user/me',
            '/api/telewatch/watch/user/me',
            '/api/telewatch/api/watch/user/me',
        }
        user_saved_rooms_paths = {
            '/watch/user/saved-rooms',
            '/api/watch/user/saved-rooms',
            '/api/telewatch/watch/user/saved-rooms',
            '/api/telewatch/api/watch/user/saved-rooms',
        }
        user_save_room_paths = {
            '/watch/user/save-room',
            '/api/watch/user/save-room',
            '/api/telewatch/watch/user/save-room',
            '/api/telewatch/api/watch/user/save-room',
        }
        user_delete_saved_room_paths = {
            '/watch/user/delete-saved-room',
            '/api/watch/user/delete-saved-room',
            '/api/telewatch/watch/user/delete-saved-room',
            '/api/telewatch/api/watch/user/delete-saved-room',
        }
        user_logout_paths = {
            '/watch/user/logout',
            '/api/watch/user/logout',
            '/api/telewatch/watch/user/logout',
            '/api/telewatch/api/watch/user/logout',
        }
        admin_ip_block_add_paths = {
            '/watch/admin/ip-block/add',
            '/api/watch/admin/ip-block/add',
            '/api/telewatch/watch/admin/ip-block/add',
            '/api/telewatch/api/watch/admin/ip-block/add',
        }
        admin_ip_block_remove_paths = {
            '/watch/admin/ip-block/remove',
            '/api/watch/admin/ip-block/remove',
            '/api/telewatch/watch/admin/ip-block/remove',
            '/api/telewatch/api/watch/admin/ip-block/remove',
        }
        admin_ip_block_list_paths = {
            '/watch/admin/ip-block/list',
            '/api/watch/admin/ip-block/list',
            '/api/telewatch/watch/admin/ip-block/list',
            '/api/telewatch/api/watch/admin/ip-block/list',
        }
        admin_user_block_add_paths = {
            '/watch/admin/user-block/add',
            '/api/watch/admin/user-block/add',
            '/api/telewatch/watch/admin/user-block/add',
            '/api/telewatch/api/watch/admin/user-block/add',
        }
        admin_user_block_remove_paths = {
            '/watch/admin/user-block/remove',
            '/api/watch/admin/user-block/remove',
            '/api/telewatch/watch/admin/user-block/remove',
            '/api/telewatch/api/watch/admin/user-block/remove',
        }
        admin_user_block_list_paths = {
            '/watch/admin/user-block/list',
            '/api/watch/admin/user-block/list',
            '/api/telewatch/watch/admin/user-block/list',
            '/api/telewatch/api/watch/admin/user-block/list',
        }
        delete_paths = {'/watch/delete', '/api/watch/delete', '/api/telewatch/watch/delete', '/api/telewatch/api/watch/delete'}
        control_paths = {'/watch/control', '/api/watch/control', '/api/telewatch/watch/control', '/api/telewatch/api/watch/control'}
        client_ip = self._client_ip()

        def is_ip_blocked(conn: sqlite3.Connection, ip_addr: str) -> bool:
            if not ip_addr:
                return False
            row = conn.execute(
                'SELECT 1 FROM watch_ip_blocks WHERE ip_addr=? LIMIT 1',
                (str(ip_addr).strip()[:64],),
            ).fetchone()
            return row is not None

        def is_user_blocked(conn: sqlite3.Connection, username: str) -> bool:
            clean = clean_username(username)
            if not clean:
                return False
            row = conn.execute(
                'SELECT 1 FROM watch_user_blocks WHERE username=? LIMIT 1',
                (clean,),
            ).fetchone()
            return row is not None

        if path in user_register_paths:
            username = clean_username(payload.get('username', ''))
            password = str(payload.get('password', '')).strip()
            display_name = clean_name(payload.get('displayName', ''), 'Viewer')
            if len(username) < 3 or '@' not in username:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'username_invalid'})
                return
            if len(password) < 8:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'password_too_short'})
                return
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                if is_ip_blocked(conn, client_ip):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'ip_blocked'})
                    return
                if is_user_blocked(conn, username):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'user_blocked'})
                    return
                exists = conn.execute('SELECT 1 FROM watch_users WHERE username=? LIMIT 1', (username,)).fetchone()
                if exists is not None:
                    self._json(HTTPStatus.CONFLICT, {'error': 'user_exists'})
                    return
                conn.execute(
                    '''
                    INSERT INTO watch_users(username, password_hash, display_name, created_at, updated_at)
                    VALUES(?,?,?,datetime('now'),datetime('now'))
                    ''',
                    (username, hash_password(password), display_name),
                )
                token = create_user_session(conn, username)
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'userToken': token, 'username': username, 'displayName': display_name})
            return

        if path in user_login_paths:
            username = clean_username(payload.get('username', ''))
            password = str(payload.get('password', '')).strip()
            if not username or not password:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'username_password_required'})
                return
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                if is_ip_blocked(conn, client_ip):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'ip_blocked'})
                    return
                if is_user_blocked(conn, username):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'user_blocked'})
                    return
                row = conn.execute(
                    'SELECT username, password_hash, display_name FROM watch_users WHERE username=? LIMIT 1',
                    (username,),
                ).fetchone()
                if row is None or not verify_password(password, row['password_hash']):
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'user_login_invalid'})
                    return
                token = create_user_session(conn, username)
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {'ok': True, 'userToken': token, 'username': username, 'displayName': str(row['display_name'] or username)},
            )
            return

        if path in user_me_paths:
            user_token = str(payload.get('userToken', '')).strip()
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                row = validate_user_session(conn, user_token)
                if row is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'user_auth_invalid'})
                    return
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {'ok': True, 'username': str(row['username'] or ''), 'displayName': str(row['display_name'] or '')},
            )
            return

        if path in user_saved_rooms_paths:
            user_token = str(payload.get('userToken', '')).strip()
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                user = validate_user_session(conn, user_token)
                if user is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'user_auth_invalid'})
                    return
                rows = conn.execute(
                    '''
                    SELECT room_code, room_title, saved_name, updated_at
                    FROM watch_user_saved_rooms
                    WHERE username=?
                    ORDER BY updated_at DESC
                    LIMIT 80
                    ''',
                    (str(user['username']),),
                ).fetchall()
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {
                    'ok': True,
                    'rooms': [
                        {
                            'roomCode': str(r['room_code'] or ''),
                            'roomTitle': str(r['room_title'] or ''),
                            'savedName': str(r['saved_name'] or ''),
                            'updatedAt': str(r['updated_at'] or ''),
                        }
                        for r in rows
                    ],
                },
            )
            return

        if path in user_save_room_paths:
            user_token = str(payload.get('userToken', '')).strip()
            room_code_val = normalize_room_code(payload.get('roomCode', ''), '')
            room_title = str(payload.get('roomTitle', '')).strip()[:160]
            saved_name = str(payload.get('savedName', '')).strip()[:120]
            if not room_code_val:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'roomCode_required'})
                return
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                user = validate_user_session(conn, user_token)
                if user is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'user_auth_invalid'})
                    return
                conn.execute(
                    '''
                    INSERT INTO watch_user_saved_rooms(username, room_code, room_title, saved_name, created_at, updated_at)
                    VALUES(?,?,?,?,datetime('now'),datetime('now'))
                    ON CONFLICT(username, room_code) DO UPDATE SET
                      room_title=excluded.room_title,
                      saved_name=excluded.saved_name,
                      updated_at=datetime('now')
                    ''',
                    (str(user['username']), room_code_val, room_title, saved_name),
                )
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'saved': True, 'roomCode': room_code_val})
            return

        if path in user_delete_saved_room_paths:
            user_token = str(payload.get('userToken', '')).strip()
            room_code_val = normalize_room_code(payload.get('roomCode', ''), '')
            if not room_code_val:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'roomCode_required'})
                return
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                user = validate_user_session(conn, user_token)
                if user is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'user_auth_invalid'})
                    return
                conn.execute(
                    'DELETE FROM watch_user_saved_rooms WHERE username=? AND room_code=?',
                    (str(user['username']), room_code_val),
                )
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'deleted': True, 'roomCode': room_code_val})
            return

        if path in user_logout_paths:
            user_token = str(payload.get('userToken', '')).strip()
            if not user_token:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'userToken_required'})
                return
            with get_db() as conn:
                conn.execute('DELETE FROM watch_user_sessions WHERE session_token=?', (user_token,))
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'loggedOut': True})
            return

        if path in admin_ip_block_add_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            admin_code = str(payload.get('adminCode', '')).strip()
            ip_addr = str(payload.get('ipAddress', '')).strip()[:64]
            reason = str(payload.get('reason', '')).strip()[:180]
            if not admin_token:
                self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_required'})
                return
            if not ip_addr:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'ipAddress_required'})
                return
            if TELEWATCH_ADMIN_CODE and admin_code != TELEWATCH_ADMIN_CODE:
                self._json(HTTPStatus.FORBIDDEN, {'error': 'admin_code_invalid'})
                return
            with get_db() as conn:
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                conn.execute(
                    '''
                    INSERT INTO watch_ip_blocks(ip_addr, reason, created_by, created_at)
                    VALUES(?,?,?,datetime('now'))
                    ON CONFLICT(ip_addr) DO UPDATE SET
                      reason=excluded.reason,
                      created_by=excluded.created_by,
                      created_at=datetime('now')
                    ''',
                    (ip_addr, reason, str(actor['username'] or 'admin')),
                )
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'blocked': True, 'ipAddress': ip_addr})
            return

        if path in admin_ip_block_remove_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            admin_code = str(payload.get('adminCode', '')).strip()
            ip_addr = str(payload.get('ipAddress', '')).strip()[:64]
            if not admin_token:
                self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_required'})
                return
            if not ip_addr:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'ipAddress_required'})
                return
            if TELEWATCH_ADMIN_CODE and admin_code != TELEWATCH_ADMIN_CODE:
                self._json(HTTPStatus.FORBIDDEN, {'error': 'admin_code_invalid'})
                return
            with get_db() as conn:
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                conn.execute('DELETE FROM watch_ip_blocks WHERE ip_addr=?', (ip_addr,))
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'removed': True, 'ipAddress': ip_addr})
            return

        if path in admin_ip_block_list_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            with get_db() as conn:
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                rows = conn.execute(
                    '''
                    SELECT ip_addr, reason, created_by, created_at
                    FROM watch_ip_blocks
                    ORDER BY created_at DESC
                    LIMIT 300
                    '''
                ).fetchall()
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {
                    'ok': True,
                    'blocks': [
                        {
                            'ipAddress': str(r['ip_addr'] or ''),
                            'reason': str(r['reason'] or ''),
                            'createdBy': str(r['created_by'] or ''),
                            'createdAt': str(r['created_at'] or ''),
                        }
                        for r in rows
                    ],
                },
            )
            return

        if path in admin_user_block_add_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            admin_code = str(payload.get('adminCode', '')).strip()
            username = clean_username(payload.get('username', ''))
            reason = str(payload.get('reason', '')).strip()[:180]
            if not admin_token:
                self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_required'})
                return
            if not username:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'username_required'})
                return
            if TELEWATCH_ADMIN_CODE and admin_code != TELEWATCH_ADMIN_CODE:
                self._json(HTTPStatus.FORBIDDEN, {'error': 'admin_code_invalid'})
                return
            with get_db() as conn:
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                conn.execute(
                    '''
                    INSERT INTO watch_user_blocks(username, reason, created_by, created_at)
                    VALUES(?,?,?,datetime('now'))
                    ON CONFLICT(username) DO UPDATE SET
                      reason=excluded.reason,
                      created_by=excluded.created_by,
                      created_at=datetime('now')
                    ''',
                    (username, reason, str(actor['username'] or 'admin')),
                )
                conn.execute('DELETE FROM watch_user_sessions WHERE username=?', (username,))
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'blocked': True, 'username': username})
            return

        if path in admin_user_block_remove_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            admin_code = str(payload.get('adminCode', '')).strip()
            username = clean_username(payload.get('username', ''))
            if not admin_token:
                self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_required'})
                return
            if not username:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'username_required'})
                return
            if TELEWATCH_ADMIN_CODE and admin_code != TELEWATCH_ADMIN_CODE:
                self._json(HTTPStatus.FORBIDDEN, {'error': 'admin_code_invalid'})
                return
            with get_db() as conn:
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                conn.execute('DELETE FROM watch_user_blocks WHERE username=?', (username,))
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'removed': True, 'username': username})
            return

        if path in admin_user_block_list_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            with get_db() as conn:
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                rows = conn.execute(
                    '''
                    SELECT username, reason, created_by, created_at
                    FROM watch_user_blocks
                    ORDER BY created_at DESC
                    LIMIT 300
                    '''
                ).fetchall()
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {
                    'ok': True,
                    'blocks': [
                        {
                            'username': str(r['username'] or ''),
                            'reason': str(r['reason'] or ''),
                            'createdBy': str(r['created_by'] or ''),
                            'createdAt': str(r['created_at'] or ''),
                        }
                        for r in rows
                    ],
                },
            )
            return

        if path in admin_login_paths:
            username = clean_username(payload.get('username', ''))
            password = str(payload.get('password', '')).strip()
            if not username or not password:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'username_password_required'})
                return
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                row = conn.execute(
                    'SELECT username, password_hash, is_owner FROM watch_admins WHERE username=? LIMIT 1',
                    (username,),
                ).fetchone()
                if row is None or not verify_password(password, row['password_hash']):
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_login_invalid'})
                    return
                token = create_admin_session(conn, username)
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {'ok': True, 'adminToken': token, 'username': username, 'isOwner': bool(row['is_owner'])},
            )
            return

        if path in admin_add_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            admin_code = str(payload.get('adminCode', '')).strip()
            new_username = clean_username(payload.get('newUsername', ''))
            new_password = str(payload.get('newPassword', '')).strip()
            if not admin_token:
                self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_required'})
                return
            if TELEWATCH_ADMIN_CODE and admin_code != TELEWATCH_ADMIN_CODE:
                self._json(HTTPStatus.FORBIDDEN, {'error': 'admin_code_invalid'})
                return
            if len(new_username) < 3 or '@' not in new_username:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'new_username_invalid'})
                return
            if len(new_password) < 8:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'new_password_too_short'})
                return
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                conn.execute(
                    '''
                    INSERT INTO watch_admins(username, password_hash, is_owner, created_at, updated_at)
                    VALUES(?,?,0,datetime('now'),datetime('now'))
                    ON CONFLICT(username) DO UPDATE SET
                      password_hash=excluded.password_hash,
                      updated_at=datetime('now')
                    ''',
                    (new_username, hash_password(new_password)),
                )
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'added': True, 'username': new_username})
            return

        if path in admin_list_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                rows = conn.execute(
                    '''
                    SELECT username, is_owner, created_at, updated_at
                    FROM watch_admins
                    ORDER BY is_owner DESC, username ASC
                    '''
                ).fetchall()
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {
                    'ok': True,
                    'admins': [
                        {
                            'username': r['username'],
                            'isOwner': bool(r['is_owner']),
                            'createdAt': r['created_at'],
                            'updatedAt': r['updated_at'],
                        }
                        for r in rows
                    ],
                },
            )
            return

        if path in admin_remove_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            admin_code = str(payload.get('adminCode', '')).strip()
            remove_username = clean_username(payload.get('username', ''))
            if not remove_username:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'username_required'})
                return
            if TELEWATCH_ADMIN_CODE and admin_code != TELEWATCH_ADMIN_CODE:
                self._json(HTTPStatus.FORBIDDEN, {'error': 'admin_code_invalid'})
                return
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                if not bool(actor['is_owner']):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'owner_required'})
                    return
                row = conn.execute(
                    'SELECT username, is_owner FROM watch_admins WHERE username=? LIMIT 1',
                    (remove_username,),
                ).fetchone()
                if row is None:
                    self._json(HTTPStatus.NOT_FOUND, {'error': 'admin_not_found'})
                    return
                if bool(row['is_owner']):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'cannot_remove_owner'})
                    return
                conn.execute('DELETE FROM watch_admins WHERE username=?', (remove_username,))
                conn.execute('DELETE FROM watch_admin_sessions WHERE username=?', (remove_username,))
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'removed': True, 'username': remove_username})
            return

        if path in admin_logout_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            if not admin_token:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'adminToken_required'})
                return
            with get_db() as conn:
                conn.execute('DELETE FROM watch_admin_sessions WHERE session_token=?', (admin_token,))
                conn.commit()
            self._json(HTTPStatus.OK, {'ok': True, 'loggedOut': True})
            return

        if path in admin_rooms_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                rows = conn.execute(
                    '''
                    SELECT
                      r.room_code,
                      r.title,
                      r.access_mode,
                      r.updated_at,
                      (
                        SELECT COUNT(*)
                        FROM watch_participants p
                        WHERE p.room_code=r.room_code AND p.last_seen_at >= datetime('now', '-20 minutes')
                      ) AS active_count,
                      (
                        SELECT p.display_name
                        FROM watch_participants p
                        WHERE p.room_code=r.room_code
                          AND p.is_host=1
                          AND p.last_seen_at >= datetime('now', '-30 minutes')
                        ORDER BY p.created_at ASC
                        LIMIT 1
                      ) AS host_name
                    FROM watch_rooms r
                    ORDER BY active_count DESC, r.updated_at DESC
                    LIMIT 120
                    '''
                ).fetchall()
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {
                    'ok': True,
                    'rooms': [
                        {
                            'roomCode': r['room_code'],
                            'title': r['title'] or '',
                            'accessMode': str(r['access_mode'] or 'public').strip().lower(),
                            'updatedAt': r['updated_at'],
                            'activeCount': int(r['active_count'] or 0),
                            'hostName': str(r['host_name'] or '').strip(),
                            'isActive': bool(int(r['active_count'] or 0) > 0),
                        }
                        for r in rows
                    ],
                },
            )
            return

        if path in admin_settings_paths:
            admin_token = str(payload.get('adminToken', '')).strip()
            action = str(payload.get('action', 'get')).strip().lower()
            admin_code = str(payload.get('adminCode', '')).strip()
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                actor = validate_admin_session(conn, admin_token)
                if actor is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_invalid'})
                    return
                if action == 'set':
                    if not bool(actor['is_owner']):
                        self._json(HTTPStatus.FORBIDDEN, {'error': 'owner_required'})
                        return
                    if TELEWATCH_ADMIN_CODE and admin_code != TELEWATCH_ADMIN_CODE:
                        self._json(HTTPStatus.FORBIDDEN, {'error': 'admin_code_invalid'})
                        return
                    raw_minutes = payload.get('emptyRoomTtlMinutes')
                    try:
                        minutes = int(str(raw_minutes).strip())
                    except Exception:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'emptyRoomTtlMinutes_invalid'})
                        return
                    minutes = max(10, min(1440, minutes))
                    conn.execute(
                        '''
                        INSERT INTO watch_settings(setting_key, setting_value, updated_at)
                        VALUES('empty_room_ttl_minutes', ?, datetime('now'))
                        ON CONFLICT(setting_key) DO UPDATE SET
                          setting_value=excluded.setting_value,
                          updated_at=datetime('now')
                        ''',
                        (str(minutes),),
                    )
                    conn.commit()
                ttl_minutes = get_empty_room_ttl_minutes(conn)
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {
                    'ok': True,
                    'settings': {
                        'emptyRoomTtlMinutes': int(ttl_minutes),
                    },
                },
            )
            return

        if path in delete_paths:
            room_code_val = normalize_room_code(payload.get('roomCode', ''), '')
            provided_admin_key = str(payload.get('adminKey', '')).strip()
            provided_admin_code = str(payload.get('adminCode', provided_admin_key)).strip()
            provided_admin_token = str(payload.get('adminToken', '')).strip()
            if not room_code_val:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'roomCode_required'})
                return
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                admin_user = validate_admin_session(conn, provided_admin_token)
                legacy_ok = bool(TELEWATCH_ADMIN_KEY and provided_admin_key and provided_admin_key == TELEWATCH_ADMIN_KEY)
                if admin_user is None and not legacy_ok:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_auth_required'})
                    return
                if TELEWATCH_ADMIN_CODE:
                    if not provided_admin_code:
                        self._json(HTTPStatus.UNAUTHORIZED, {'error': 'admin_code_required'})
                        return
                    if provided_admin_code != TELEWATCH_ADMIN_CODE:
                        self._json(HTTPStatus.FORBIDDEN, {'error': 'admin_code_invalid'})
                        return
                room = conn.execute(
                    'SELECT room_code FROM watch_rooms WHERE room_code=?',
                    (room_code_val,),
                ).fetchone()
                if room is None:
                    self._json(HTTPStatus.NOT_FOUND, {'error': 'room_not_found'})
                    return
                if is_public_room(room_code_val):
                    conn.execute(
                        '''
                        UPDATE watch_rooms
                        SET title=?, media_url='', theme_key='clean', allow_webcam=1, cohost_can_kick=1, cohost_can_mute=1, cohost_can_access=1, cohost_can_pin=1, access_mode='public', is_private=0, delete_on_host_leave=1, playback_sec=0, is_playing=0, updated_at=datetime('now')
                        WHERE room_code=?
                        ''',
                        (f'Public Room {room_code_val[-2:]}', room_code_val),
                    )
                    conn.execute('DELETE FROM watch_participants WHERE room_code=?', (room_code_val,))
                    conn.execute('DELETE FROM watch_events WHERE room_code=?', (room_code_val,))
                    conn.execute('DELETE FROM watch_join_requests WHERE room_code=?', (room_code_val,))
                    conn.execute('DELETE FROM watch_room_invites WHERE room_code=?', (room_code_val,))
                    conn.execute('DELETE FROM watch_room_bans WHERE room_code=?', (room_code_val,))
                    conn.execute(
                        '''
                        INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at)
                        VALUES(?,?,?,?,datetime('now'))
                        ''',
                        (room_code_val, 'Admin', 'room_reset', stable_json({'publicRoom': True})),
                    )
                    conn.commit()
                    self._json(HTTPStatus.OK, {'ok': True, 'deleted': True, 'publicReset': True, 'roomCode': room_code_val})
                    return
                conn.execute('DELETE FROM watch_rooms WHERE room_code=?', (room_code_val,))
                conn.commit()
                self._json(HTTPStatus.OK, {'ok': True, 'deleted': True, 'roomCode': room_code_val})
                return

        if path in create_paths:
            display_name = clean_name(payload.get('displayName', ''), 'Host')
            title = str(payload.get('title', '')).strip()[:160]
            media_url = str(payload.get('mediaUrl', '')).strip()[:600]
            theme_key = clean_theme_key(payload.get('themeKey', 'clean'), 'clean')
            requested_access_mode = str(payload.get('accessMode', 'public')).strip().lower()
            access_mode = requested_access_mode if requested_access_mode in {'public', 'invite', 'closed'} else 'public'
            requested_code = normalize_room_code(payload.get('roomCode', ''), '')
            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                if is_ip_blocked(conn, client_ip):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'ip_blocked'})
                    return
                custom_room_count = conn.execute(
                    f"SELECT COUNT(*) FROM watch_rooms WHERE room_code NOT IN ({','.join(['?'] * len(public_room_codes()))})",
                    tuple(public_room_codes()),
                ).fetchone()[0]
                if int(custom_room_count or 0) >= MAX_ROOMS:
                    self._json(HTTPStatus.CONFLICT, {'error': 'room_capacity_reached', 'maxRooms': MAX_ROOMS})
                    return
                code = ''
                if requested_code:
                    exists = conn.execute('SELECT 1 FROM watch_rooms WHERE room_code=?', (requested_code,)).fetchone()
                    if exists is not None:
                        self._json(HTTPStatus.CONFLICT, {'error': 'room_code_taken'})
                        return
                    code = requested_code
                else:
                    for _ in range(12):
                        candidate = room_code()
                        exists = conn.execute('SELECT 1 FROM watch_rooms WHERE room_code=?', (candidate,)).fetchone()
                        if exists is None:
                            code = candidate
                            break
                if not code:
                    self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {'error': 'room_create_failed'})
                    return
                host_token = secrets.token_urlsafe(32)
                participant_id = secrets.token_hex(6)
                conn.execute(
                    '''
                    INSERT INTO watch_rooms(room_code, host_token, title, media_url, theme_key, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, created_at, updated_at)
                    VALUES(?,?,?,?,?,?,?,1,0,0,datetime('now'),datetime('now'))
                    ''',
                    (code, host_token, title, media_url, theme_key, access_mode, 1 if access_mode == 'invite' else 0),
                )
                conn.execute(
                    '''
                    INSERT INTO watch_participants(participant_token, participant_id, room_code, display_name, is_host, created_at, last_seen_at)
                    VALUES(?,?,?,?,1,datetime('now'),datetime('now'))
                    ''',
                    (host_token, participant_id, code, display_name),
                )
                conn.execute(
                    '''
                    INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at)
                    VALUES(?,?,?,?,datetime('now'))
                    ''',
                    (code, display_name, 'room_created', stable_json({'title': title, 'mediaUrl': media_url, 'themeKey': theme_key, 'accessMode': access_mode})),
                )
                conn.commit()
            self._json(
                HTTPStatus.OK,
                {
                    'ok': True,
                    'roomCode': code,
                    'participantToken': host_token,
                    'participantId': participant_id,
                    'isHost': True,
                    'joinUrl': f'/telewatch/?room={code}',
                },
            )
            return

        if path in join_paths:
            room_code_val = normalize_room_code(payload.get('roomCode', ''), '')
            display_name = clean_name(payload.get('displayName', ''), f"Guest-{secrets.randbelow(900) + 100}")
            request_token_in = str(payload.get('requestToken', '')).strip()[:96]
            invite_token_in = str(payload.get('inviteToken', '')).strip()[:96]
            if not room_code_val:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'roomCode_required'})
                return

            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                if is_ip_blocked(conn, client_ip):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'ip_blocked'})
                    return
                room = conn.execute(
                    'SELECT room_code, title, media_url, theme_key, allow_webcam, cohost_can_kick, cohost_can_mute, cohost_can_access, cohost_can_pin, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, updated_at FROM watch_rooms WHERE room_code=?',
                    (room_code_val,),
                ).fetchone()
                if room is None:
                    self._json(HTTPStatus.NOT_FOUND, {'error': 'room_not_found'})
                    return
                access_mode = str(room['access_mode'] or '').strip().lower()
                if access_mode not in {'public', 'invite', 'closed'}:
                    access_mode = 'invite' if bool(room['is_private']) else 'public'
                participant_count = conn.execute(
                    '''
                    SELECT COUNT(*)
                    FROM watch_participants
                    WHERE room_code=? AND last_seen_at >= datetime('now', '-30 minutes')
                    ''',
                    (room_code_val,),
                ).fetchone()[0]
                if int(participant_count or 0) >= MAX_PARTICIPANTS_PER_ROOM:
                    self._json(
                        HTTPStatus.CONFLICT,
                        {'error': 'room_full', 'maxParticipants': MAX_PARTICIPANTS_PER_ROOM},
                    )
                    return

                host_exists = conn.execute(
                    '''
                    SELECT 1
                    FROM watch_participants
                    WHERE room_code=? AND is_host=1 AND last_seen_at >= datetime('now', '-30 minutes')
                    LIMIT 1
                    ''',
                    (room_code_val,),
                ).fetchone()
                join_is_host = bool(is_public_room(room_code_val) and host_exists is None)
                invite_row = None
                if invite_token_in:
                    invite_row = conn.execute(
                        '''
                        SELECT invite_token, max_uses, used_count
                        FROM watch_room_invites
                        WHERE room_code=? AND invite_token=? AND expires_at > datetime('now')
                        LIMIT 1
                        ''',
                        (room_code_val, invite_token_in),
                    ).fetchone()
                    if invite_row is not None:
                        max_uses = int(invite_row['max_uses'] or 0)
                        used_count = int(invite_row['used_count'] or 0)
                        if max_uses > 0 and used_count >= max_uses:
                            invite_row = None
                    if invite_row is None:
                        self._json(HTTPStatus.FORBIDDEN, {'error': 'invite_invalid'})
                        return

                if request_token_in:
                    req = conn.execute(
                        '''
                        SELECT request_token, status, participant_token, participant_id
                        FROM watch_join_requests
                        WHERE room_code=? AND request_token=?
                        LIMIT 1
                        ''',
                        (room_code_val, request_token_in),
                    ).fetchone()
                    if req is not None:
                        status = str(req['status'] or '').strip().lower()
                        if status == 'approved' and req['participant_token'] and req['participant_id']:
                            conn.execute(
                                '''
                                UPDATE watch_participants
                                SET last_seen_at=datetime('now')
                                WHERE participant_token=? AND room_code=?
                                ''',
                                (req['participant_token'], room_code_val),
                            )
                            conn.commit()
                            self._json(
                                HTTPStatus.OK,
                                {
                                    'ok': True,
                                    'participantToken': req['participant_token'],
                                    'participantId': req['participant_id'],
                                    'isHost': False,
                                    'room': room_payload(room),
                                },
                            )
                            return
                        if status == 'denied':
                            self._json(HTTPStatus.FORBIDDEN, {'error': 'join_request_denied'})
                            return
                        self._json(HTTPStatus.OK, {'ok': True, 'pendingApproval': True, 'requestToken': request_token_in})
                        return

                if not join_is_host and access_mode == 'closed' and invite_row is None:
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'room_closed'})
                    return
                if not join_is_host and access_mode == 'invite' and invite_row is None:
                    existing_req = conn.execute(
                        '''
                        SELECT request_token, status
                        FROM watch_join_requests
                        WHERE room_code=? AND lower(display_name)=lower(?) AND status='pending'
                        ORDER BY id DESC
                        LIMIT 1
                        ''',
                        (room_code_val, display_name),
                    ).fetchone()
                    request_token = str(existing_req['request_token']) if existing_req is not None else secrets.token_urlsafe(24)
                    if existing_req is None:
                        conn.execute(
                            '''
                            INSERT INTO watch_join_requests(request_token, room_code, display_name, status, created_at)
                            VALUES(?,?,?,'pending',datetime('now'))
                            ''',
                            (request_token, room_code_val, display_name),
                        )
                        conn.execute(
                            '''
                            INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at)
                            VALUES(?,?,?,?,datetime('now'))
                            ''',
                            (room_code_val, display_name, 'join_requested', stable_json({'displayName': display_name})),
                        )
                    conn.commit()
                    self._json(HTTPStatus.OK, {'ok': True, 'pendingApproval': True, 'requestToken': request_token})
                    return

                participant_token = secrets.token_urlsafe(32)
                participant_id = secrets.token_hex(6)
                conn.execute(
                    '''
                    INSERT INTO watch_participants(participant_token, participant_id, room_code, display_name, is_host, created_at, last_seen_at)
                    VALUES(?,?,?,?,0,datetime('now'),datetime('now'))
                    ''',
                    (participant_token, participant_id, room_code_val, display_name),
                )
                if invite_row is not None:
                    conn.execute(
                        '''
                        UPDATE watch_room_invites
                        SET used_count=used_count+1
                        WHERE invite_token=?
                        ''',
                        (invite_token_in,),
                    )
                if join_is_host:
                    conn.execute(
                        'UPDATE watch_participants SET is_host=1 WHERE participant_token=?',
                        (participant_token,),
                    )
                conn.execute(
                    '''
                    INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at)
                    VALUES(?,?,?,?,datetime('now'))
                    ''',
                    (room_code_val, display_name, 'join', stable_json({'displayName': display_name})),
                )
                if join_is_host:
                    conn.execute(
                        '''
                        INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at)
                        VALUES(?,?,?,?,datetime('now'))
                        ''',
                        (room_code_val, display_name, 'host_claimed', stable_json({'publicRoom': True})),
                    )
                conn.commit()

            self._json(
                HTTPStatus.OK,
                {
                    'ok': True,
                    'participantToken': participant_token,
                    'participantId': participant_id,
                    'isHost': bool(join_is_host),
                    'room': room_payload(room),
                },
            )
            return

        if path in control_paths:
            room_code_val = normalize_room_code(payload.get('roomCode', ''), '')
            participant_token = str(payload.get('participantToken', '')).strip()[:128]
            action = str(payload.get('action', '')).strip().lower()[:32]
            if not room_code_val or not participant_token or not action:
                self._json(HTTPStatus.BAD_REQUEST, {'error': 'roomCode_participantToken_action_required'})
                return

            with get_db() as conn:
                ensure_public_rooms(conn)
                cleanup_rooms(conn)
                part = conn.execute(
                    'SELECT participant_id, display_name, is_host, is_cohost FROM watch_participants WHERE participant_token=? AND room_code=?',
                    (participant_token, room_code_val),
                ).fetchone()
                if part is None:
                    self._json(HTTPStatus.UNAUTHORIZED, {'error': 'invalid_participant'})
                    return

                conn.execute("UPDATE watch_participants SET last_seen_at=datetime('now') WHERE participant_token=?", (participant_token,))
                room = conn.execute(
                    'SELECT room_code, title, media_url, theme_key, allow_webcam, cohost_can_kick, cohost_can_mute, cohost_can_access, cohost_can_pin, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, updated_at FROM watch_rooms WHERE room_code=?',
                    (room_code_val,),
                ).fetchone()
                if room is None:
                    self._json(HTTPStatus.NOT_FOUND, {'error': 'room_not_found'})
                    return

                is_host = bool(part['is_host'])
                is_cohost = bool(part['is_cohost'])
                cohost_can_kick = bool(room['cohost_can_kick']) if 'cohost_can_kick' in room.keys() else True
                cohost_can_mute = bool(room['cohost_can_mute']) if 'cohost_can_mute' in room.keys() else True
                cohost_can_access = bool(room['cohost_can_access']) if 'cohost_can_access' in room.keys() else True
                cohost_can_pin = bool(room['cohost_can_pin']) if 'cohost_can_pin' in room.keys() else True
                if action in {'play', 'pause', 'seek', 'set_media', 'set_title', 'set_theme', 'set_webcam_policy', 'delete_room', 'reset_room', 'resolve_request', 'create_invite', 'set_cohost', 'set_cohost_perms'} and not is_host:
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'host_required'})
                    return
                if action == 'set_access_mode' and not (is_host or (is_cohost and cohost_can_access)):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'moderator_required'})
                    return
                if action == 'kick_user' and not (is_host or (is_cohost and cohost_can_kick)):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'moderator_required'})
                    return
                if action == 'mute_user' and not (is_host or (is_cohost and cohost_can_mute)):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'moderator_required'})
                    return
                if action in {'resolve_join_request', 'list_invites', 'revoke_invite'} and not (is_host or (is_cohost and cohost_can_access)):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'moderator_required'})
                    return
                if action == 'pin_chat' and not (is_host or (is_cohost and cohost_can_pin)):
                    self._json(HTTPStatus.FORBIDDEN, {'error': 'moderator_required'})
                    return

                event_payload = {}
                playback_raw = payload.get('playbackSec')
                try:
                    playback_sec = float(playback_raw) if playback_raw is not None else None
                except Exception:
                    playback_sec = None
                if playback_sec is not None:
                    playback_sec = max(0.0, min(172800.0, playback_sec))

                if action == 'play':
                    if playback_sec is not None:
                        conn.execute(
                            'UPDATE watch_rooms SET playback_sec=?, is_playing=1, updated_at=datetime(\'now\') WHERE room_code=?',
                            (playback_sec, room_code_val),
                        )
                        event_payload['playbackSec'] = playback_sec
                    else:
                        conn.execute('UPDATE watch_rooms SET is_playing=1, updated_at=datetime(\'now\') WHERE room_code=?', (room_code_val,))
                elif action == 'pause':
                    if playback_sec is not None:
                        conn.execute(
                            'UPDATE watch_rooms SET playback_sec=?, is_playing=0, updated_at=datetime(\'now\') WHERE room_code=?',
                            (playback_sec, room_code_val),
                        )
                        event_payload['playbackSec'] = playback_sec
                    else:
                        conn.execute('UPDATE watch_rooms SET is_playing=0, updated_at=datetime(\'now\') WHERE room_code=?', (room_code_val,))
                elif action == 'seek':
                    if playback_sec is None:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'playbackSec_required'})
                        return
                    conn.execute('UPDATE watch_rooms SET playback_sec=?, updated_at=datetime(\'now\') WHERE room_code=?', (playback_sec, room_code_val))
                    event_payload['playbackSec'] = playback_sec
                elif action == 'set_media':
                    media_url = str(payload.get('mediaUrl', '')).strip()[:600]
                    title = str(payload.get('title', '')).strip()[:160]
                    conn.execute(
                        'UPDATE watch_rooms SET media_url=?, title=?, playback_sec=0, is_playing=0, updated_at=datetime(\'now\') WHERE room_code=?',
                        (media_url, title, room_code_val),
                    )
                    event_payload['mediaUrl'] = media_url
                    event_payload['title'] = title
                elif action == 'set_title':
                    title = str(payload.get('title', '')).strip()[:160]
                    conn.execute('UPDATE watch_rooms SET title=?, updated_at=datetime(\'now\') WHERE room_code=?', (title, room_code_val))
                    event_payload['title'] = title
                elif action == 'set_theme':
                    theme_key = clean_theme_key(payload.get('themeKey', ''), 'clean')
                    conn.execute(
                        'UPDATE watch_rooms SET theme_key=?, updated_at=datetime(\'now\') WHERE room_code=?',
                        (theme_key, room_code_val),
                    )
                    event_payload['themeKey'] = theme_key
                elif action == 'set_webcam_policy':
                    allow_webcam = bool(payload.get('allowWebcam', True))
                    conn.execute(
                        'UPDATE watch_rooms SET allow_webcam=?, updated_at=datetime(\'now\') WHERE room_code=?',
                        (1 if allow_webcam else 0, room_code_val),
                    )
                    event_payload['allowWebcam'] = allow_webcam
                elif action == 'set_cohost_perms':
                    can_kick = bool(payload.get('canKick', True))
                    can_mute = bool(payload.get('canMute', True))
                    can_access = bool(payload.get('canAccess', True))
                    can_pin = bool(payload.get('canPin', True))
                    conn.execute(
                        '''
                        UPDATE watch_rooms
                        SET cohost_can_kick=?, cohost_can_mute=?, cohost_can_access=?, cohost_can_pin=?, updated_at=datetime('now')
                        WHERE room_code=?
                        ''',
                        (1 if can_kick else 0, 1 if can_mute else 0, 1 if can_access else 0, 1 if can_pin else 0, room_code_val),
                    )
                    event_payload['cohostPerms'] = {
                        'kick': bool(can_kick),
                        'mute': bool(can_mute),
                        'access': bool(can_access),
                        'pin': bool(can_pin),
                    }
                elif action == 'create_invite':
                    ttl_minutes_raw = payload.get('ttlMinutes')
                    max_uses_raw = payload.get('maxUses')
                    try:
                        ttl_minutes = int(str(ttl_minutes_raw).strip()) if ttl_minutes_raw is not None else 720
                    except Exception:
                        ttl_minutes = 720
                    try:
                        max_uses = int(str(max_uses_raw).strip()) if max_uses_raw is not None else 0
                    except Exception:
                        max_uses = 0
                    ttl_minutes = max(5, min(10080, ttl_minutes))
                    max_uses = max(0, min(500, max_uses))
                    invite_token = secrets.token_urlsafe(24)
                    conn.execute(
                        '''
                        INSERT INTO watch_room_invites(invite_token, room_code, created_by, max_uses, used_count, created_at, expires_at)
                        VALUES(?,?,?,?,0,datetime('now'),datetime('now', ?))
                        ''',
                        (invite_token, room_code_val, str(part['display_name'] or 'Host'), max_uses, f'+{ttl_minutes} minutes'),
                    )
                    event_payload['inviteToken'] = invite_token
                    event_payload['ttlMinutes'] = ttl_minutes
                    event_payload['maxUses'] = max_uses
                elif action == 'set_access_mode':
                    access_mode = str(payload.get('accessMode', '')).strip().lower()
                    if access_mode not in {'public', 'invite', 'closed'}:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'invalid_access_mode'})
                        return
                    conn.execute(
                        '''
                        UPDATE watch_rooms
                        SET access_mode=?, is_private=?, updated_at=datetime('now')
                        WHERE room_code=?
                        ''',
                        (access_mode, 1 if access_mode == 'invite' else 0, room_code_val),
                    )
                    event_payload['accessMode'] = access_mode
                elif action == 'reset_room':
                    title = str(payload.get('title', '')).strip()[:160]
                    if not title:
                        title = room['title'] or ''
                    conn.execute(
                        '''
                        UPDATE watch_rooms
                        SET media_url='', playback_sec=0, is_playing=0, title=?, updated_at=datetime('now')
                        WHERE room_code=?
                        ''',
                        (title, room_code_val),
                    )
                    event_payload['title'] = title
                elif action == 'mute_user':
                    to_participant_id = str(payload.get('toParticipantId', '')).strip().lower()[:24]
                    muted = bool(payload.get('muted', True))
                    if not to_participant_id:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'toParticipantId_required'})
                        return
                    target = conn.execute(
                        'SELECT participant_id FROM watch_participants WHERE room_code=? AND participant_id=? LIMIT 1',
                        (room_code_val, to_participant_id),
                    ).fetchone()
                    if target is None:
                        self._json(HTTPStatus.NOT_FOUND, {'error': 'target_participant_not_found'})
                        return
                    event_payload['toParticipantId'] = to_participant_id
                    event_payload['muted'] = bool(muted)
                elif action == 'set_cohost':
                    to_participant_id = str(payload.get('toParticipantId', '')).strip().lower()[:24]
                    enabled = bool(payload.get('enabled', True))
                    if not to_participant_id:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'toParticipantId_required'})
                        return
                    target = conn.execute(
                        'SELECT participant_id, is_host FROM watch_participants WHERE room_code=? AND participant_id=? LIMIT 1',
                        (room_code_val, to_participant_id),
                    ).fetchone()
                    if target is None:
                        self._json(HTTPStatus.NOT_FOUND, {'error': 'target_participant_not_found'})
                        return
                    if bool(target['is_host']):
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'cannot_change_host_cohost'})
                        return
                    conn.execute(
                        'UPDATE watch_participants SET is_cohost=? WHERE room_code=? AND participant_id=?',
                        (1 if enabled else 0, room_code_val, to_participant_id),
                    )
                    event_payload['toParticipantId'] = to_participant_id
                    event_payload['enabled'] = bool(enabled)
                elif action == 'kick_user':
                    to_participant_id = str(payload.get('toParticipantId', '')).strip().lower()[:24]
                    if not to_participant_id:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'toParticipantId_required'})
                        return
                    if to_participant_id == str(part['participant_id'] or '').lower():
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'cannot_kick_self'})
                        return
                    target = conn.execute(
                        'SELECT participant_id, is_host FROM watch_participants WHERE room_code=? AND participant_id=? LIMIT 1',
                        (room_code_val, to_participant_id),
                    ).fetchone()
                    if target is None:
                        self._json(HTTPStatus.NOT_FOUND, {'error': 'target_participant_not_found'})
                        return
                    if bool(target['is_host']):
                        self._json(HTTPStatus.FORBIDDEN, {'error': 'cannot_kick_host'})
                        return
                    conn.execute(
                        'DELETE FROM watch_participants WHERE room_code=? AND participant_id=?',
                        (room_code_val, to_participant_id),
                    )
                    event_payload['toParticipantId'] = to_participant_id
                elif action == 'resolve_join_request':
                    request_token = str(payload.get('requestToken', '')).strip()[:96]
                    status = str(payload.get('status', '')).strip().lower()[:16]
                    if not request_token:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'requestToken_required'})
                        return
                    if status not in {'approved', 'denied'}:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'invalid_status'})
                        return
                    req = conn.execute(
                        '''
                        SELECT request_token, display_name, status
                        FROM watch_join_requests
                        WHERE room_code=? AND request_token=?
                        LIMIT 1
                        ''',
                        (room_code_val, request_token),
                    ).fetchone()
                    if req is None:
                        self._json(HTTPStatus.NOT_FOUND, {'error': 'join_request_not_found'})
                        return
                    participant_token_new = None
                    participant_id_new = None
                    if status == 'approved':
                        participant_token_new = secrets.token_urlsafe(32)
                        participant_id_new = secrets.token_hex(6)
                        conn.execute(
                            '''
                            INSERT INTO watch_participants(participant_token, participant_id, room_code, display_name, is_host, created_at, last_seen_at)
                            VALUES(?,?,?,?,0,datetime('now'),datetime('now'))
                            ''',
                            (participant_token_new, participant_id_new, room_code_val, clean_name(req['display_name'], 'Guest')),
                        )
                    conn.execute(
                        '''
                        UPDATE watch_join_requests
                        SET status=?, participant_token=?, participant_id=?, responded_by=?, responded_at=datetime('now')
                        WHERE room_code=? AND request_token=?
                        ''',
                        (status, participant_token_new, participant_id_new, part['display_name'], room_code_val, request_token),
                    )
                    event_payload['requestToken'] = request_token
                    event_payload['status'] = status
                elif action == 'request_item':
                    request_type = str(payload.get('requestType', '')).strip().lower()[:32]
                    request_text = str(payload.get('requestText', '')).strip()[:300]
                    if request_type not in {'media', 'skip_intro', 'next_episode', 'cohost', 'general'}:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'invalid_request_type'})
                        return
                    if not request_text:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'requestText_required'})
                        return
                    event_payload['requestType'] = request_type
                    event_payload['requestText'] = request_text
                elif action == 'resolve_request':
                    request_id = int(payload.get('requestId', 0) or 0)
                    status = str(payload.get('status', '')).strip().lower()[:16]
                    note = str(payload.get('note', '')).strip()[:200]
                    if request_id <= 0:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'requestId_required'})
                        return
                    if status not in {'approved', 'denied'}:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'invalid_status'})
                        return
                    event_payload['requestId'] = request_id
                    event_payload['status'] = status
                    if note:
                        event_payload['note'] = note
                elif action == 'reaction':
                    emoji = str(payload.get('emoji', '')).strip()[:8]
                    if not emoji:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'emoji_required'})
                        return
                    event_payload['emoji'] = emoji
                elif action == 'chat':
                    msg = str(payload.get('message', '')).strip()
                    if not msg:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'message_required'})
                        return
                    event_payload['message'] = msg[:280]
                elif action == 'react_chat':
                    message_id = int(payload.get('messageId', 0) or 0)
                    emoji = str(payload.get('emoji', '')).strip()[:8]
                    if message_id <= 0:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'messageId_required'})
                        return
                    if not emoji:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'emoji_required'})
                        return
                    event_payload['messageId'] = message_id
                    event_payload['emoji'] = emoji
                elif action == 'pin_chat':
                    message_id = int(payload.get('messageId', 0) or 0)
                    pinned = bool(payload.get('pinned', True))
                    if message_id <= 0:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'messageId_required'})
                        return
                    event_payload['messageId'] = message_id
                    event_payload['pinned'] = pinned
                elif action == 'signal':
                    to_participant_id = str(payload.get('toParticipantId', '')).strip().lower()[:24]
                    signal_type = str(payload.get('signalType', '')).strip().lower()[:16]
                    if not to_participant_id or signal_type not in {'offer', 'answer', 'ice'}:
                        self._json(HTTPStatus.BAD_REQUEST, {'error': 'invalid_signal_payload'})
                        return
                    target = conn.execute(
                        'SELECT participant_id FROM watch_participants WHERE room_code=? AND participant_id=? LIMIT 1',
                        (room_code_val, to_participant_id),
                    ).fetchone()
                    if target is None:
                        self._json(HTTPStatus.NOT_FOUND, {'error': 'target_participant_not_found'})
                        return
                    event_payload['fromParticipantId'] = str(part['participant_id'] or '')
                    event_payload['toParticipantId'] = to_participant_id
                    event_payload['signalType'] = signal_type
                    if signal_type in {'offer', 'answer'}:
                        event_payload['sdp'] = str(payload.get('sdp', ''))[:20000]
                    if signal_type == 'ice':
                        event_payload['candidate'] = str(payload.get('candidate', ''))[:4000]
                elif action == 'delete_room':
                    if is_public_room(room_code_val):
                        conn.execute(
                            '''
                            UPDATE watch_rooms
                            SET title=?, media_url='', theme_key='clean', allow_webcam=1, cohost_can_kick=1, cohost_can_mute=1, cohost_can_access=1, cohost_can_pin=1, access_mode='public', is_private=0, delete_on_host_leave=1, playback_sec=0, is_playing=0, updated_at=datetime('now')
                            WHERE room_code=?
                            ''',
                            (f'Public Room {room_code_val[-2:]}', room_code_val),
                        )
                        conn.execute('DELETE FROM watch_participants WHERE room_code=?', (room_code_val,))
                        conn.execute('DELETE FROM watch_events WHERE room_code=?', (room_code_val,))
                        conn.execute('DELETE FROM watch_join_requests WHERE room_code=?', (room_code_val,))
                        conn.execute('DELETE FROM watch_room_invites WHERE room_code=?', (room_code_val,))
                        conn.execute('DELETE FROM watch_room_bans WHERE room_code=?', (room_code_val,))
                        conn.execute(
                            '''
                            INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at)
                            VALUES(?,?,?,?,datetime('now'))
                            ''',
                            (room_code_val, part['display_name'], 'room_reset', stable_json({'publicRoom': True})),
                        )
                        conn.commit()
                        self._json(HTTPStatus.OK, {'ok': True, 'deleted': True, 'publicReset': True, 'roomCode': room_code_val})
                        return
                    conn.execute('DELETE FROM watch_rooms WHERE room_code=?', (room_code_val,))
                    conn.commit()
                    self._json(HTTPStatus.OK, {'ok': True, 'deleted': True, 'roomCode': room_code_val})
                    return
                elif action == 'ping':
                    event_payload = {}
                else:
                    self._json(HTTPStatus.BAD_REQUEST, {'error': 'invalid_action'})
                    return

                event_id = None
                if action != 'ping':
                    cur = conn.execute(
                        'INSERT INTO watch_events(room_code, actor_name, event_type, payload_json, created_at) VALUES(?,?,?,?,datetime(\'now\'))',
                        (room_code_val, part['display_name'], action, stable_json(event_payload)),
                    )
                    event_id = int(cur.lastrowid or 0)

                room_after = conn.execute(
                    'SELECT room_code, title, media_url, theme_key, allow_webcam, cohost_can_kick, cohost_can_mute, cohost_can_access, cohost_can_pin, access_mode, is_private, delete_on_host_leave, playback_sec, is_playing, updated_at FROM watch_rooms WHERE room_code=?',
                    (room_code_val,),
                ).fetchone()
                conn.commit()

            self._json(HTTPStatus.OK, {'ok': True, 'eventId': event_id, 'room': room_payload(room_after), 'actionPayload': event_payload})
            return

        self._json(HTTPStatus.NOT_FOUND, {'error': 'not_found'})


def main() -> None:
    ensure_schema()
    server = ThreadingHTTPServer((HOST, PORT), TelewatchHandler)
    print(f'Telewatch service listening on {HOST}:{PORT} db={DB_PATH}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
