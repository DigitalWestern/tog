"""In-sandbox relay for the PR 0 spike: the shape of `tog __resolution-relay`.

    python3 relay.py <unix socket> <port> -- <tool argv...>

Runs as the first process inside `bwrap --unshare-net --unshare-pid`. It
listens on 127.0.0.1:<port> in the private network namespace, connects the
bound Unix socket once per accepted TCP connection and splices the two, runs
the tool (whose argv starts with the seccomp wrapper), then kills every other
process in the PID namespace and exits with the tool's status. The relay
itself is outside the seccomp filter, so its AF_UNIX connect still works.
"""

import os
import signal
import socket
import subprocess
import sys
import threading


def pump(source, sink):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            sink.sendall(data)
    except OSError:
        pass
    finally:
        try:
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def serve(listener, path):
    while True:
        client, _ = listener.accept()
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            upstream.connect(path)
        except OSError:
            client.close()
            continue
        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


def kill_namespace():
    me = os.getpid()
    for entry in os.listdir("/proc"):
        if entry.isdigit() and int(entry) not in (1, me):
            try:
                os.kill(int(entry), signal.SIGKILL)
            except OSError:
                pass


def main():
    argv = sys.argv[1:]
    split = argv.index("--")
    path, port = argv[0], int(argv[1])
    tool = argv[split + 1 :]
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(128)
    threading.Thread(target=serve, args=(listener, path), daemon=True).start()
    status = subprocess.call(tool)
    kill_namespace()
    sys.exit(status if status >= 0 else 128 - status)


if __name__ == "__main__":
    main()
