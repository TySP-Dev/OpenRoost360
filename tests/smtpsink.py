"""TEST TOOL ONLY: a minimal SMTP server that accepts every message and appends it to a file. Not used by the app.

    python3 tests/smtpsink.py --port 8325 --out /tmp/mail.txt
"""
import argparse, socketserver


def run(port, out, bind='127.0.0.1'):
    class H(socketserver.StreamRequestHandler):
        def handle(self):
            w = lambda s: self.wfile.write((s + '\r\n').encode())
            w('220 sink'); data, in_data = [], False
            for raw in self.rfile:
                line = raw.decode(errors='replace').rstrip('\r\n')
                if in_data:
                    if line == '.':
                        in_data = False
                        with open(out, 'a') as f: f.write('\n'.join(data) + '\n=====\n')
                        data = []; w('250 queued')
                    else: data.append(line)
                    continue
                cmd = line[:4].upper()
                if cmd in ('EHLO', 'HELO'): w('250 sink')
                elif cmd == 'DATA': in_data = True; w('354 go')
                elif cmd == 'QUIT': w('221 bye'); return
                else: w('250 ok')
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer((bind, port), H).serve_forever()


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--port', type=int, default=8325); ap.add_argument('--out', required=True); ap.add_argument('--bind', default='127.0.0.1')
    a = ap.parse_args(); run(a.port, a.out, a.bind)
