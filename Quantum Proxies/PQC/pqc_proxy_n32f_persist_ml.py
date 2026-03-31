#!/usr/bin/env python3
"""
PQC Proxy - chain-style, per-connection persistent TLS (ML-KEM + ML-DSA)

Chain per connection:
    5G core (TCP) -> SAE (TCP)
        -> SAE (PQC-TLS client) -> KME (PQC-TLS server)
        -> KME (TCP) -> other 5G core (backend)

Each incoming TCP connection on SAE gets:
    - one TLS session SAE<->KME
    - one backend TCP connection KME<->core2
and they all live & die together.

ML notes:
- Signature algorithm is taken from the certificate key type (ML-DSA),
  so we do NOT pass -sigalgs to OpenSSL.
- KEM group is selected via -groups (e.g., X25519MLKEM768).
- ML-KEM/ML-DSA are in OpenSSL 3.5 default provider, so oqsprovider is not needed.
"""

import asyncio
import socket
import subprocess
import sys
import os
import time
import threading
from asyncio import StreamReader, StreamWriter

CERTS_DIR = "certs_ml"
OPENSSL_BIN = "/usr/local/openssl-3.5/bin/openssl"


def log(label, message):
    print(f"[{label}] {message}", flush=True)


def setup_environment():
    env = os.environ.copy()
    env["OPENSSL_CONF"] = "/usr/local/openssl-3.5/openssl.cnf"
    env["LD_LIBRARY_PATH"] = "/usr/local/openssl-3.5/lib:" + env.get(
        "LD_LIBRARY_PATH", ""
    )
    return env


class OpenSSLClient:
    """
    One s_client instance for one SAE TCP connection.
    Lifetime:
        - start() when SAE receives TCP
        - used as TLS tunnel to KME
        - close() when TCP closes
    """

    def __init__(self, kem, sig, host, port):
        self.kem = kem
        self.sig = sig  # kept for CLI compatibility; not used for ML-DSA selection
        self.host = host
        self.port = port
        self.proc = None
        self.sock = None

    async def start(self):
        # ML-DSA cert/key filenames (fixed)
        cert = os.path.join(CERTS_DIR, "sae_mldsa.pem")
        key = os.path.join(CERTS_DIR, "sae_mldsa_key.pem")
        ca_cert = os.path.join(CERTS_DIR, "ca_cert.pem")

        # socketpair: one end for OpenSSL, one for Python
        sock_in, sock_out = socket.socketpair()
        # sock_in -> used as stdin/stdout for OpenSSL   (keep BLOCKING)
        # sock_out -> used from asyncio in Python       (make NON-BLOCKING)
        sock_out.setblocking(False)

        self.proc = subprocess.Popen(
            [
                OPENSSL_BIN,
                "s_client",
                "-connect",
                f"{self.host}:{self.port}",
                "-cert",
                cert,
                "-key",
                key,
                "-CAfile",
                ca_cert,
                "-groups",
                self.kem,
                "-quiet",
                "-provider",
                "default",
                "-provider",
                "oqsprovider",
                "-no_ssl3",
                "-no_tls1",
                "-no_tls1_1",
                "-no_ticket",
                "-ign_eof",
            ],
            stdin=sock_in,
            stdout=sock_in,
            stderr=subprocess.PIPE,
            env=setup_environment(),
        )

        # Close OpenSSL end in Python (OpenSSL keeps its own fd)
        sock_in.close()

        self.sock = sock_out
        log("SAE-TLS", f"s_client started to {self.host}:{self.port} (groups={self.kem})")

        # Yield to event loop briefly to allow immediate crash detection without a hard delay
        await asyncio.sleep(0)

        # Detect immediate failure
        if self.proc.poll() is not None:
            rc = self.proc.returncode
            err = ""
            try:
                if self.proc.stderr:
                    err = self.proc.stderr.read().decode(errors="ignore").strip()
            except Exception:
                pass
            self.close()
            raise RuntimeError(f"s_client exited immediately (rc={rc}). stderr: {err}")

        return self.sock

    def close(self):
        """
        Graceful-ish shutdown to allow s_client to flush.
        """
        # 1) Signal EOF to OpenSSL (best effort)
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        # 2) Stop process
        if self.proc:
            try:
                # give it a moment to exit cleanly
                self.proc.wait(timeout=0.3)
            except subprocess.TimeoutExpired:
                try:
                    self.proc.terminate()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    try:
                        self.proc.kill()
                    except OSError:
                        pass
                    try:
                        self.proc.wait()
                    except Exception:
                        pass

            if self.proc.stderr:
                try:
                    err = self.proc.stderr.read().decode(errors="ignore").strip()
                    if err:
                        log("SAE-OPENSSL", err)
                except Exception:
                    pass

        # 3) Close our end
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

        self.proc = None
        self.sock = None


async def pipe_data(reader, writer, label, loop, timeout=30):
    """
    Bidirectional pipe between:
      - StreamReader/StreamWriter for TCP side
      - raw socket for TLS side
    """
    try:
        while True:
            # Read
            if hasattr(reader, "read"):  # StreamReader
                try:
                    data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                except asyncio.TimeoutError:
                    log(label, f"No data for {timeout}s, closing direction")
                    break
            else:  # socket
                try:
                    data = await asyncio.wait_for(loop.sock_recv(reader, 65536), timeout=timeout)
                except asyncio.TimeoutError:
                    log(label, f"No data for {timeout}s, closing direction")
                    break

            if not data:
                log(label, "Connection closed by peer")
                break

            # Write
            if hasattr(writer, "write"):  # StreamWriter
                writer.write(data)
                await writer.drain()
            else:  # socket
                await loop.sock_sendall(writer, data)

    except Exception as e:
        log(f"{label} Error", str(e))
    finally:
        log(label, "Forwarding completed")


async def handle_sae_client(client_reader: StreamReader, client_writer: StreamWriter, kem, sig):
    """
    For each incoming TCP connection:
      - start one TLS client to KME
      - bidirectionally pipe TCP <-> TLS
      - when either side closes, teardown
    """
    ssl_client = None
    try:
        client_addr = client_writer.get_extra_info("peername")
        log("SAE", f"New TCP client connection from {client_addr}")

        # --- OPTIMIZATION: Disable Nagle's Algorithm (TCP_NODELAY) ---
        sock = client_writer.get_extra_info('socket')
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # -------------------------------------------------------------

        ssl_client = OpenSSLClient(kem, sig, "10.100.1.207", 8444)
        ssl_sock = await ssl_client.start()

        loop = asyncio.get_running_loop()

        t1 = asyncio.create_task(pipe_data(client_reader, ssl_sock, "TCP→TLS", loop, timeout=60))
        t2 = asyncio.create_task(pipe_data(ssl_sock, client_writer, "TLS→TCP", loop, timeout=60))

        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)

        # Cancel remaining
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.sleep(0.2)

        log("SAE", f"Client connection from {client_addr} completed")

    except Exception as e:
        log("SAE Client Error", str(e))
    finally:
        if ssl_client:
            ssl_client.close()
        if client_writer:
            try:
                if hasattr(client_writer, "is_closing") and not client_writer.is_closing():
                    client_writer.close()
                    await client_writer.wait_closed()
            except Exception:
                pass


async def sae_handler(kem, sig):
    """SAE TCP listener"""
    listen_host = "0.0.0.0"
    listen_port = 8081  # front-end port for 5G core
    log("SAE", f"Starting on {listen_host}:{listen_port}")
    log("SAE", "KME: 10.100.1.207:8444")

    try:
        server = await asyncio.start_server(
            lambda r, w: handle_sae_client(r, w, kem, sig),
            listen_host,
            listen_port,
            reuse_port=True,
        )

        log("SAE", f"Listening on {listen_host}:{listen_port} - Ready for connections")

        async with server:
            await server.serve_forever()

    except Exception as e:
        log("SAE Server Error", str(e))
    except KeyboardInterrupt:
        log("SAE", "Shutdown requested")


# ===================== KME side =====================


async def kme_handler(kem, sig):
    """
    KME side:
      - runs an OpenSSL s_server loop
      - for each TLS connection, only after first TLS app-data arrives:
            connects to backend TCP
      - then pipes TLS <-> backend TCP until close
    """
    log("KME", f"Starting on 0.0.0.0:8444")
    log("KME", f"Backend: 10.10.2.252:7777")

    import select

    def run_kme_sync():
        while True:
            ssl_proc, ssl_sock = None, None
            backend_sock = None
            sock_in = None

            try:
                # ML-DSA cert/key filenames (fixed)
                cert = os.path.join(CERTS_DIR, "kme_mldsa.pem")
                key = os.path.join(CERTS_DIR, "kme_mldsa_key.pem")
                ca_cert = os.path.join(CERTS_DIR, "ca_cert.pem")

                sock_in, sock_out = socket.socketpair()

                ssl_proc = subprocess.Popen(
                    [
                        OPENSSL_BIN, "s_server",
                        "-cert", cert,
                        "-key", key,
                        "-CAfile", ca_cert,
                        "-groups", kem,
                        "-accept", "8444",
                        "-quiet",
                        "-provider", "default",
                        "-provider", "oqsprovider",
                        "-no_ssl3", "-no_tls1", "-no_tls1_1",
                        "-no_ticket", "-ign_eof"
                    ],
                    stdin=sock_in,
                    stdout=sock_in,
                    stderr=subprocess.PIPE,
                    env=setup_environment()
                )

                # Close OpenSSL end in Python
                sock_in.close()
                sock_in = None

                ssl_sock = sock_out
                ssl_sock.settimeout(5.0)

                log("KME", "Waiting for TLS connection from SAE (first app-data)")

                # ---- PHASE 1: wait for first TLS application data ----
                first_chunk = None
                start_wait = time.time()
                while True:
                    try:
                        first_chunk = ssl_sock.recv(65536)
                        break
                    except socket.timeout:
                        if time.time() - start_wait > 60:
                            raise Exception("Timed out waiting for TLS application data")
                        continue

                if not first_chunk:
                    raise Exception("TLS connection closed before any data")

                # ---- PHASE 2: connect to backend only now ----
                backend_sock = socket.create_connection(("10.10.2.252", 7777), timeout=10)
                backend_sock.settimeout(5.0)
                
                # --- OPTIMIZATION: Disable Nagle's Algorithm (TCP_NODELAY) ---
                backend_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # -------------------------------------------------------------

                log("KME", "Connected to backend core")

                # Send the first chunk to backend
                backend_sock.sendall(first_chunk)
                log("TLS→Backend", f"{len(first_chunk)} bytes (first chunk)")
                last_activity = time.time()

                # ---- PHASE 3: full bidirectional forwarding ----
                sockets = [ssl_sock, backend_sock]

                while True:
                    if time.time() - last_activity > 60:
                        log("KME", "Connection timeout due to inactivity")
                        break

                    try:
                        readables, _, _ = select.select(sockets, [], [], 1.0)
                    except (ValueError, OSError):
                        break

                    if not readables:
                        continue

                    for s in readables:
                        if s is ssl_sock:
                            data = ssl_sock.recv(65536)
                            if not data:
                                raise Exception("TLS socket closed")
                            backend_sock.sendall(data)
                            last_activity = time.time()
                        else:
                            data = backend_sock.recv(65536)
                            if not data:
                                raise Exception("Backend socket closed")
                            ssl_sock.sendall(data)
                            last_activity = time.time()

            except Exception as e:
                log("KME Error", str(e))
                time.sleep(0.2)

            finally:
                # teardown
                if ssl_proc:
                    try:
                        ssl_proc.terminate()
                        ssl_proc.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        try:
                            ssl_proc.kill()
                            ssl_proc.wait()
                        except Exception:
                            pass

                    if ssl_proc.stderr:
                        try:
                            err = ssl_proc.stderr.read().decode(errors="ignore").strip()
                            if err:
                                log("KME-OPENSSL", err)
                        except Exception:
                            pass

                if ssl_sock:
                    try:
                        ssl_sock.close()
                    except OSError:
                        pass
                if backend_sock:
                    try:
                        backend_sock.close()
                    except OSError:
                        pass
                if sock_in:
                    try:
                        sock_in.close()
                    except OSError:
                        pass

                log("KME", "Connection cleaned up")

    # Run KME sync loop in a daemon thread so asyncio loop remains alive
    t = threading.Thread(target=run_kme_sync, daemon=True)
    t.start()

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        log("KME", "Shutdown requested")


async def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} [sae|kme] <kem> <sig>")
        sys.exit(1)

    role, kem, sig = sys.argv[1:4]
    log("MAIN", f"Starting {role.upper()} with KEM={kem}, SIG={sig} (SIG is a label for ML certs)")

    try:
        if role == "sae":
            await sae_handler(kem, sig)
        elif role == "kme":
            await kme_handler(kem, sig)
        else:
            print("Invalid role (use 'sae' or 'kme')")
    except KeyboardInterrupt:
        log("Main", "Shutdown requested")


if __name__ == "__main__":
    asyncio.run(main())