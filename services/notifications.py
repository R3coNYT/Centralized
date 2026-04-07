"""
Notification firing helper.

Call `fire_notification(scope, entity_id, event, title, body, url)` from any
route to queue a desktop notification for every user who subscribed to *event*
on the given scope/entity.

The records are added to the current SQLAlchemy session but NOT committed here;
the caller's `db.session.commit()` will persist them.

For real-time delivery, each active SSE connection registers a `queue.Queue`
via `get_user_queue()`.  `fire_notification()` also pushes directly onto that
queue so the SSE stream receives the event instantly.
"""

import queue
import threading
import json as _json
from models import NotificationPref, PendingNotification
from extensions import db

# Thread-safe registry of per-user in-memory queues (one per SSE connection).
# Keys are user_id (int); values are sets of Queue objects so multiple tabs
# / connections for the same user all receive the notification.
_user_queues: dict[int, set] = {}
_queues_lock = threading.Lock()


def register_queue(user_id: int) -> queue.Queue:
    """Create and register a new Queue for an SSE connection."""
    q: queue.Queue = queue.Queue(maxsize=100)
    with _queues_lock:
        if user_id not in _user_queues:
            _user_queues[user_id] = set()
        _user_queues[user_id].add(q)
    return q


def unregister_queue(user_id: int, q: queue.Queue) -> None:
    """Remove a Queue when the SSE connection closes."""
    with _queues_lock:
        if user_id in _user_queues:
            _user_queues[user_id].discard(q)
            if not _user_queues[user_id]:
                del _user_queues[user_id]


def _push_to_queues(user_id: int, payload: dict) -> None:
    with _queues_lock:
        queues = list(_user_queues.get(user_id, []))
    for q in queues:
        try:
            q.put_nowait(payload)
        except queue.Full:
            pass


def broadcast_live_event(event_type: str, payload: dict) -> None:
    """Push a live-update event to ALL connected SSE clients (all users).

    The payload is broadcast to every registered queue so every open tab/client
    receives it instantly.  Pages use this to react to data changes made by
    other users (e.g. audit status change, new host, new vuln).

    payload should be a plain dict of serialisable values.
    The key ``_event_type`` is reserved and will be set to ``live_update``.
    """
    message = {"_event_type": "live_update", "type": event_type, **payload}
    with _queues_lock:
        all_queues = [q for qs in _user_queues.values() for q in qs]
    for q in all_queues:
        try:
            q.put_nowait(message)
        except queue.Full:
            pass


def fire_notification(
    scope: str,
    entity_id: int,
    event: str,
    title: str,
    body: str = "",
    url: str = "",
) -> None:
    """Queue a PendingNotification for every subscriber of *event* on scope/entity_id."""
    prefs = NotificationPref.query.filter_by(scope=scope, entity_id=entity_id).all()
    for pref in prefs:
        events = _json.loads(pref.events) if pref.events else []
        if event in events:
            db.session.add(PendingNotification(
                user_id=pref.user_id,
                title=title,
                body=body,
                url=url,
            ))
            # Also push in real-time to any open SSE connection
            _push_to_queues(pref.user_id, {"title": title, "body": body, "url": url})
