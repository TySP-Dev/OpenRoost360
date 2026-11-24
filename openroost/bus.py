"""In-process publish/subscribe for live updates (server-sent events to the web app and mobile app)."""
import itertools, json, queue, threading, time


class Bus:
    def __init__(self):
        self.subs, self.lock, self.seq = set(), threading.Lock(), itertools.count(1)

    def subscribe(self, filt=None):
        q = queue.Queue(maxsize=500); q.filt = filt
        with self.lock: self.subs.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock: self.subs.discard(q)

    def publish(self, kind, data):
        msg = {'id': next(self.seq), 'type': kind, 't': time.time(), 'data': data}
        with self.lock: subs = list(self.subs)
        for q in subs:
            if q.filt and not q.filt(msg): continue
            try: q.put_nowait(msg)
            except queue.Full: pass            # slow client: it will resync from the REST endpoints

    @staticmethod
    def sse(msg):
        return f"id: {msg['id']}\nevent: {msg['type']}\ndata: {json.dumps(msg['data'], separators=(',', ':'))}\n\n".encode()
