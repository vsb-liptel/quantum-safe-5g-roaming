#!/usr/bin/env python3
"""
PQC Proxy - chain-style, per-connection persistent TLS

Chain per connection:
    5G core (TCP) -> SAE (TCP)
        -> SAE (PQC-TLS client) -> KME (PQC-TLS server)
        -> KME (TCP) -> other 5G core (backend)

Each incoming TCP connection on SAE gets:
    - one TLS session SAE<->KME
    - one backend TCP connection KME<->core2
and they all live & die together.
"""

import asyncio
import socket
import subprocess
import sys
import os
import time
from asyncio import StreamReader, StreamWriter

CERTS_DIR = "certs"
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
        self.sig = sig
        self.host = host
        self.port = port
        self.proc = None
        self.sock = None

    async def start(self):
        cert = os.path.join(CERTS_DIR, f"sae_{self.sig}.pem")
        key = os.path.join(CERTS_DIR, f"sae_{self.sig}_key.pem")
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
                "-sigalgs",
                self.sig,
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

        sock_in.close()
        self.sock = sock_out
        log("SAE", "OpenSSL client started")

        # Tiny delay to let TLS handshake start (you can adjust if needed)
        # await asyncio.sleep(0.05)
        return self.sock

    def close(self):
        """
        Gracefully shut down s_client so it can flush any pending TLS records.
        """
        # 1) Tell s_client we're done sending cleartext
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        # 2) Give s_client a chance to exit cleanly
        if self.proc:
            try:
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
    Pipe data from reader -> writer, with a read timeout.
    reader: StreamReader or socket.socket
    writer: StreamWriter or socket.socket
    """
    try:
        while True:
            # Read with timeout
            if hasattr(reader, "read"):  # StreamReader
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                except asyncio.TimeoutError:
                    log(label, f"No data for {timeout} seconds, closing")
                    break
            else:  # raw socket
                try:
                    data = await asyncio.wait_for(
                        loop.sock_recv(reader, 4096), timeout=timeout
                    )
                except asyncio.TimeoutError:
                    log(label, f"No data for {timeout} seconds, closing")
                    break

            if not data:
                log(label, "Connection closed by peer")
                break

            log(label, f"Forwarded {len(data)} bytes")

            # Optional preview (NAS/HTTP/etc)
            try:
                preview = data[:100]
                text = preview.decode("utf-8", errors="ignore")
                if any(m in text for m in ["GET", "POST", "PUT", "DELETE", "HTTP"]):
                    log(label, f"HTTP: {text[:50]}...")
                elif text.strip():
                    log(label, f"Text: {text.strip()[:50]}...")
                else:
                    log(label, f"Binary: {preview.hex()[:50]}...")
            except Exception:
                log(label, f"Binary: {data[:50].hex()}...")

            # Write
            if hasattr(writer, "write"):  # StreamWriter
                writer.write(data)
                await writer.drain()
            else:  # raw socket
                await loop.sock_sendall(writer, data)

    except Exception as e:
        log(f"{label} Error", str(e))
    finally:
        log(label, "Forwarding completed")


async def handle_sae_client(client_reader: StreamReader, client_writer: StreamWriter, kem, sig):
    ssl_client = None
    try:
        client_addr = client_writer.get_extra_info("peername")
        log("SAE", f"New client connection from {client_addr}")

        # --- OPTIMIZATION: Disable Nagle's Algorithm (TCP_NODELAY) ---
        sock = client_writer.get_extra_info('socket')
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # -------------------------------------------------------------

        ssl_client = OpenSSLClient(kem, sig, "10.100.1.207", 8444)
        ssl_sock = await ssl_client.start()

        loop = asyncio.get_event_loop()

        # Bidirectional forwarding (pipe_data remains unchanged)
        client_to_tls = asyncio.create_task(
            pipe_data(client_reader, ssl_sock, "Client→TLS", loop, timeout=60)
        )
        tls_to_client = asyncio.create_task(
            pipe_data(ssl_sock, client_writer, "TLS→Client", loop, timeout=60)
        )

        done, pending = await asyncio.wait(
            [client_to_tls, tls_to_client],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for t in pending:
            t.cancel()
        if pending:
            await asyncio.sleep(0.2)

        log("SAE", f"Client connection from {client_addr} completed")

    # ... (rest of exception handling remains the same)

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
                elif not hasattr(client_writer, "is_closing"):
                    client_writer.close()
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
    """KME Proxy - With proper connection management"""
    log("KME", f"Starting on 0.0.0.0:8444")
    log("KME", f"Backend: 10.10.2.252:7777")

    import threading
    import select

    def run_kme_sync():
        while True:
            ssl_proc, ssl_sock = None, None
            backend_sock = None

            try:
                # Start OpenSSL server (one TLS connection per loop)
                cert = os.path.join(CERTS_DIR, f"kme_{sig}.pem")
                key = os.path.join(CERTS_DIR, f"kme_{sig}_key.pem")
                ca_cert = os.path.join(CERTS_DIR, "ca_cert.pem")

                sock_in, sock_out = socket.socketpair()

                ssl_proc = subprocess.Popen(
                    [
                        OPENSSL_BIN, "s_server",
                        "-cert", cert,
                        "-key", key,
                        "-CAfile", ca_cert,
                        "-groups", kem,
                        "-sigalgs", sig,
                        "-accept", "8444",
                        "-quiet",
                        "-provider", "default",
                        "-provider", "oqsprovider",
                        "-no_ssl3", "-no_tls1", "-no_tls1_1",
                        "-no_ticket", "-ign_eof",
                    ],
                    stdin=sock_in,
                    stdout=sock_in,
                    stderr=subprocess.PIPE,
                    env=setup_environment()
                )

                sock_in.close()
                ssl_sock = sock_out
                log("KME", "PQC-TLS server ready, waiting for SAE")

                # ---- PHASE 1: wait for first TLS app data from SAE ----
                ssl_sock.settimeout(60.0)  # how long we're willing to wait for SAE
                try:
                    first_chunk = ssl_sock.recv(65536)
                except socket.timeout:
                    log("KME", "No TLS client data within 60s, restarting")
                    raise Exception("No TLS data")

                if not first_chunk:
                    log("KME", "TLS connection closed before any data")
                    raise Exception("Empty first TLS read")

                log("KME", f"Received first {len(first_chunk)} bytes from SAE over TLS")

                # ---- PHASE 2: connect to backend only now ----
                backend_sock = socket.create_connection(('10.10.2.252', 7777), timeout=10)
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

                    for sock in readables:
                        if sock is ssl_sock:
                            data = ssl_sock.recv(65536)
                            if data:
                                log("TLS→Backend", f"{len(data)} bytes")
                                backend_sock.sendall(data)
                                last_activity = time.time()
                            else:
                                log("KME", "TLS socket closed")
                                raise Exception("SSL socket closed")
                        elif sock is backend_sock:
                            data = backend_sock.recv(65536)
                            if data:
                                log("Backend→TLS", f"{len(data)} bytes")
                                ssl_sock.sendall(data)
                                last_activity = time.time()
                            else:
                                log("KME", "Backend socket closed")
                                raise Exception("Backend socket closed")

            except Exception as e:
                log("KME Error", str(e))
                time.sleep(0.5)
            finally:
                if ssl_proc:
                    try:
                        ssl_proc.terminate()
                        ssl_proc.wait(timeout=2)
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
                log("KME", "Connection cleaned up, waiting for next TLS session")

    thread = threading.Thread(target=run_kme_sync, daemon=True)
    thread.start()

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        log("KME", "Shutdown requested")

# ===================== MAIN =====================


async def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} [sae|kme] <kem> <sig>")
        sys.exit(1)

    role, kem, sig = sys.argv[1:4]
    log("MAIN", f"Starting {role.upper()} with KEM={kem}, SIG={sig}")

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
