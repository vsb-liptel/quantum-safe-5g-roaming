#!/usr/bin/env python3
"""
PQC Proxy - UDP-only, one-way, PERSISTENT PQC-TLS tunnel

Flow:
    UDP client :2152
        -> SAE (UDP listener)
        -> persistent PQC-TLS tunnel (openssl s_client -> s_server :8443)
        -> KME (TLS terminator)
        -> backend via UDP :2152

Fixes vs original:
- Adds framing to preserve UDP datagram boundaries over TLS stream.
- Uses a queue + single sender task on SAE with batching/draining (avoids IPC bottlenecks).
- KME deframes and forwards exact original datagrams (prevents "merged" payloads).
- Removed hard sleeps in favor of event-loop yielding.
"""

import asyncio
import socket
import subprocess
import sys
import os
import time
import threading
import struct

CERTS_DIR = "certs"
OPENSSL_BIN = "/usr/local/openssl-3.5/bin/openssl"

MAX_UDP = 65507  # max UDP payload


def log(label, msg):
    print(f"[{label}] {msg}", flush=True)


def setup_environment():
    env = os.environ.copy()
    # Adjust for your oqs-enabled OpenSSL if needed
    env.setdefault("OPENSSL_CONF", "/usr/local/openssl-3.5/ssl/openssl.cnf")
    env.setdefault("LD_LIBRARY_PATH", "/usr/local/openssl-3.5/lib")
    return env


def get_cert_paths(role, sig):
    """
    Flat layout:

        certs/ca_cert.pem
        certs/sae_<sig>.pem
        certs/sae_<sig>_key.pem
        certs/kme_<sig>.pem
        certs/kme_<sig>_key.pem
    """
    ca = os.path.join(CERTS_DIR, "ca_cert.pem")

    if role == "sae":
        cert = os.path.join(CERTS_DIR, f"sae_{sig}.pem")
        key = os.path.join(CERTS_DIR, f"sae_{sig}_key.pem")
    elif role == "kme":
        cert = os.path.join(CERTS_DIR, f"kme_{sig}.pem")
        key = os.path.join(CERTS_DIR, f"kme_{sig}_key.pem")
    else:
        raise ValueError("role must be 'sae' or 'kme'")

    return {"cert": cert, "key": key, "ca_cert": ca}


# ---------------- Framing helpers (UDP datagrams over TLS stream) ----------------

def frame_datagram(payload: bytes) -> bytes:
    """2-byte big-endian length + payload."""
    n = len(payload)
    if n > 0xFFFF:
        raise ValueError(f"payload too large for 2-byte length: {n}")
    return struct.pack("!H", n) + payload


class FrameDecoder:
    """Incrementally decodes framed datagrams from a byte stream."""
    __slots__ = ("buf",)

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes):
        self.buf.extend(data)

    def pop_all(self):
        out = []
        while True:
            if len(self.buf) < 2:
                break
            (n,) = struct.unpack("!H", self.buf[:2])
            if len(self.buf) < 2 + n:
                break
            out.append(bytes(self.buf[2:2 + n]))
            del self.buf[:2 + n]
        return out


# ================= SAE side: UDP in -> persistent PQC-TLS client =================

class PersistentTLSClient(object):
    """
    Single persistent 'openssl s_client' session.

    - Maintains one s_client process + socketpair.
    - Reconnects automatically on failure.
    - send_bytes(blob) is serialized via a lock.
    """

    def __init__(self, kem, sig, host, port):
        self.kem = kem
        self.sig = sig
        self.host = host
        self.port = port
        self.proc = None        # type: subprocess.Popen
        self.sock = None        # type: socket.socket
        self.lock = asyncio.Lock()
        self.env = setup_environment()

    async def _connect(self):
        # Cleanup previous if any
        self._cleanup()

        certs = get_cert_paths("sae", self.sig)
        for k in ("cert", "key", "ca_cert"):
            if not os.path.exists(certs[k]):
                raise FileNotFoundError("Missing %s: %s" % (k, certs[k]))

        sock_in, sock_out = socket.socketpair()

        args = [
            OPENSSL_BIN, "s_client",
            "-connect", f"{self.host}:{self.port}",
            "-cert", certs["cert"],
            "-key", certs["key"],
            "-CAfile", certs["ca_cert"],
            "-groups", self.kem,
            "-sigalgs", self.sig,
            "-quiet",
            "-verify_quiet",
            "-servername", self.host,
            "-no_ssl3", "-no_tls1", "-no_tls1_1",
            "-provider", "default",
            "-provider", "oqsprovider",
        ]

        try:
            self.proc = subprocess.Popen(
                args,
                stdin=sock_in,
                stdout=sock_in,
                stderr=subprocess.PIPE,   # capture stderr for diagnosis
                env=self.env,
            )
        except FileNotFoundError as e:
            sock_in.close()
            sock_out.close()
            log("SAE-TLS", "OpenSSL not found: %s" % e)
            self.proc = None
            self.sock = None
            raise

        sock_in.close()
        self.sock = sock_out
        self.sock.setblocking(False)

        # --- OPTIMIZATION: Removed hard sleep, yielding to event loop ---
        await asyncio.sleep(0)
        
        if self.proc.poll() is not None:
            rc = self.proc.returncode
            err = ""
            try:
                if self.proc.stderr:
                    err = self.proc.stderr.read().decode(errors="ignore").strip()
            except Exception:
                pass
            self._cleanup()
            raise RuntimeError("s_client exited immediately (rc=%s). stderr: %s" % (rc, err))

        log("SAE-TLS", "Persistent s_client connected to %s:%s" % (self.host, self.port))

    def _cleanup(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

        if self.proc is not None:
            try:
                if self.proc.poll() is None:
                    self.proc.terminate()
                    try:
                        self.proc.wait(timeout=1.0)
                    except Exception:
                        pass
            except Exception:
                pass
            self.proc = None

    async def ensure_connected(self):
        if self.sock is not None and self.proc is not None and self.proc.poll() is None:
            return
        await self._connect()

    async def send_bytes(self, blob: bytes):
        async with self.lock:
            try:
                await self.ensure_connected()
            except Exception as e:
                log("SAE-TLS", "Connect failed, dropping packet: %r" % (e,))
                return

            loop = asyncio.get_running_loop()
            try:
                await loop.sock_sendall(self.sock, blob)
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                log("SAE-TLS", "Send failed (%r), reconnecting once" % (e,))
                # Try one reconnect + resend
                self._cleanup()
                try:
                    await self._connect()
                    await loop.sock_sendall(self.sock, blob)
                except Exception as e2:
                    log("SAE-TLS", "Resend after reconnect failed, dropping: %r" % (e2,))
                    self._cleanup()

    async def close(self):
        async with self.lock:
            self._cleanup()


class SAEUDPHandler(asyncio.DatagramProtocol):
    """
    SAE:
      - Listens on UDP :2152.
      - Enqueues datagrams.
      - A single sender task frames + forwards over ONE persistent PQC-TLS tunnel.
    """

    def __init__(self, kem, sig, kme_host, kme_port, queue_max=20000):
        self.kem = kem
        self.sig = sig
        self.kme_host = kme_host
        self.kme_port = kme_port
        self.transport = None
        self.tls_client = None
        self.q = asyncio.Queue(maxsize=queue_max)
        self.sender_task = None
        self.drops = 0

    def connection_made(self, transport):
        self.transport = transport
        addr = transport.get_extra_info("sockname")
        log("SAE-UDP", "Listening on %s" % (addr,))
        self.tls_client = PersistentTLSClient(self.kem, self.sig, self.kme_host, self.kme_port)
        self.sender_task = asyncio.create_task(self._sender_loop())

        # Increase UDP receive buffer (best-effort; kernel may cap)
        try:
            sock = transport.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except Exception:
            pass

    def datagram_received(self, data, addr):
        if len(data) > MAX_UDP:
            log("SAE-UDP", "Dropping oversized UDP datagram: %d bytes" % len(data))
            return

        try:
            self.q.put_nowait(data)
        except asyncio.QueueFull:
            self.drops += 1
            if (self.drops % 100) == 1:
                log("SAE-UDP", "Queue full, dropping (total drops=%d)" % self.drops)

    async def _sender_loop(self):
        assert self.tls_client is not None
        while True:
            # Wait for at least one packet
            data = await self.q.get()
            
            # --- OPTIMIZATION: Queue Draining and Batching ---
            buffer = bytearray(frame_datagram(data))
            self.q.task_done()
            
            # Synchronously drain anything else that arrived in the queue
            while not self.q.empty():
                try:
                    next_data = self.q.get_nowait()
                    buffer.extend(frame_datagram(next_data))
                    self.q.task_done()
                except asyncio.QueueEmpty:
                    break
            
            # Send the entire batch of framed datagrams to OpenSSL at once
            await self.tls_client.send_bytes(bytes(buffer))

    async def close(self):
        if self.sender_task:
            self.sender_task.cancel()
            try:
                await self.sender_task
            except Exception:
                pass
        if self.tls_client:
            await self.tls_client.close()
        if self.transport:
            self.transport.close()


async def sae_handler(
    kem,
    sig,
    listen_host="0.0.0.0",
    listen_port=2152,
    kme_host="10.100.1.207",
    kme_port=8443,
):
    loop = asyncio.get_running_loop()
    handler = SAEUDPHandler(kem, sig, kme_host, kme_port)
    transport, _ = await loop.create_datagram_endpoint(
        lambda: handler,
        local_addr=(listen_host, listen_port),
    )
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        log("SAE", "Shutdown requested")
    finally:
        await handler.close()
        transport.close()


# ================= KME side: PQC-TLS server -> UDP backend =================

class KMEUDPProxy(object):
    """
    KME:
      - Runs 'openssl s_server' on :8443 with PQC params.
      - For each TLS connection:
            reads app data from stdin/stdout (via socketpair),
            DEFAMES stream into UDP datagrams,
            forwards each datagram via UDP to backend_host:backend_port.
      - When TLS connection closes, loops and waits for the next one.
    """

    def __init__(
        self,
        kem,
        sig,
        listen_port=8443,
        backend_host="10.100.2.205",
        backend_port=2152,
    ):
        self.kem = kem
        self.sig = sig
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.running = True

    def run(self):
        env = setup_environment()
        log(
            "KME",
            "PQC-TLS server on :%d, forwarding via UDP to %s:%d"
            % (self.listen_port, self.backend_host, self.backend_port),
        )

        while self.running:
            ssl_proc = None
            tls_sock = None
            backend_sock = None
            hard_fail = False

            try:
                certs = get_cert_paths("kme", self.sig)
                for k in ("cert", "key", "ca_cert"):
                    if not os.path.exists(certs[k]):
                        raise FileNotFoundError("Missing %s: %s" % (k, certs[k]))

                sock_in, sock_out = socket.socketpair()

                args = [
                    OPENSSL_BIN, "s_server",
                    "-accept", str(self.listen_port),
                    "-cert", certs["cert"],
                    "-key", certs["key"],
                    "-CAfile", certs["ca_cert"],
                    "-groups", self.kem,
                    "-sigalgs", self.sig,
                    "-quiet",
                    "-verify_quiet",
                    "-no_ssl3", "-no_tls1", "-no_tls1_1",
                    "-no_ticket",
                    "-ign_eof",
                    "-provider", "default",
                    "-provider", "oqsprovider",
                ]

                ssl_proc = subprocess.Popen(
                    args,
                    stdin=sock_in,
                    stdout=sock_in,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                sock_in.close()

                tls_sock = sock_out
                tls_sock.settimeout(5.0)

                backend_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # Increase UDP send buffer (best-effort)
                try:
                    backend_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
                except Exception:
                    pass

                log("KME", "Waiting for TLS connection from SAE")

                last_activity = time.time()
                decoder = FrameDecoder()

                while self.running:
                    try:
                        chunk = tls_sock.recv(65536)
                    except socket.timeout:
                        if time.time() - last_activity > 600:
                            log("KME", "Idle for too long, restarting s_server")
                            break
                        continue

                    if not chunk:
                        log("KME", "TLS connection closed (EOF)")
                        break

                    last_activity = time.time()
                    decoder.feed(chunk)

                    datagrams = decoder.pop_all()
                    if not datagrams:
                        continue

                    for payload in datagrams:
                        backend_sock.sendto(payload, (self.backend_host, self.backend_port))

            except Exception as e:
                log("KME-ERR", "%r" % (e,))
                hard_fail = True

            finally:
                if tls_sock is not None:
                    try:
                        tls_sock.close()
                    except OSError:
                        pass

                if backend_sock is not None:
                    try:
                        backend_sock.close()
                    except OSError:
                        pass

                if ssl_proc is not None:
                    try:
                        rc = ssl_proc.poll()
                        if rc is None:
                            try:
                                ssl_proc.terminate()
                            except OSError:
                                pass
                            try:
                                ssl_proc.wait(timeout=1.0)
                            except Exception:
                                pass
                            rc = ssl_proc.poll()

                        if ssl_proc.stderr:
                            try:
                                err = ssl_proc.stderr.read().decode(errors="ignore").strip()
                                if err:
                                    log("KME-OPENSSL", err)
                            except Exception:
                                pass

                        if rc not in (0, None):
                            hard_fail = True
                    except Exception:
                        hard_fail = True

                if hard_fail:
                    time.sleep(0.5)

    def start(self):
        t = threading.Thread(target=self.run, daemon=True)
        t.start()

    def stop(self):
        self.running = False


async def kme_handler(kem, sig):
    proxy = KMEUDPProxy(kem, sig)
    proxy.start()
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        log("KME", "Shutdown requested")
        proxy.stop()


# ================= MAIN =================

async def _amain():
    if len(sys.argv) != 4:
        print("Usage: %s [sae|kme] <kem> <sig>" % sys.argv[0])
        raise SystemExit(1)

    role, kem, sig = sys.argv[1:4]
    log("MAIN", "Role=%s, KEM=%s, SIG=%s" % (role.upper(), kem, sig))

    if role == "sae":
        await sae_handler(kem, sig)
    elif role == "kme":
        await kme_handler(kem, sig)
    else:
        print("Invalid role. Use 'sae' or 'kme'.")
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        asyncio.run(_amain())
    except Exception as e:
        log("FATAL", "%r" % (e,))
        raise