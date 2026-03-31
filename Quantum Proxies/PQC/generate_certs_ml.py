#!/usr/bin/env python3

import subprocess
import os

# ===== Configuration =====

CERTS_DIR = "certs_ml"
CA_CERT = os.path.join(CERTS_DIR, "ca_cert.pem")
CA_KEY = os.path.join(CERTS_DIR, "ca_key.pem")

OPENSSL = "/usr/local/openssl-3.5/bin/openssl"
CONFIG = "/usr/local/openssl-3.5/openssl.cnf"

# ML-DSA choice: ML-DSA-65 is a good middle ground
SIG = "ML-DSA-65"

# =========================

os.makedirs(CERTS_DIR, exist_ok=True)

def run_openssl(cmd_args):
    print(f"Running: {' '.join(cmd_args)}")
    subprocess.run(cmd_args, check=True)

# ----- Generate CA (ML-DSA) -----

if not os.path.exists(CA_CERT):
    run_openssl([
        OPENSSL, "req",
        "-x509",
        "-newkey", SIG,
        "-keyout", CA_KEY,
        "-out", CA_CERT,
        "-days", "365",
        "-nodes",
        "-subj", "/CN=Test CA ML-DSA",
        "-config", CONFIG
    ])
    print(f"✅ CA certificate generated: {CA_CERT}")

# ----- Generate SAE and KME certs -----

for role in ["sae", "kme"]:
    key = os.path.join(CERTS_DIR, f"{role}_mldsa_key.pem")
    csr = os.path.join(CERTS_DIR, f"{role}_mldsa.csr")
    cert = os.path.join(CERTS_DIR, f"{role}_mldsa.pem")

    run_openssl([
        OPENSSL, "req",
        "-newkey", SIG,
        "-nodes",
        "-keyout", key,
        "-out", csr,
        "-subj", f"/CN={role.upper()}-ML-DSA",
        "-config", CONFIG
    ])

    run_openssl([
        OPENSSL, "x509",
        "-req",
        "-in", csr,
        "-CA", CA_CERT,
        "-CAkey", CA_KEY,
        "-CAcreateserial",
        "-out", cert,
        "-days", "365"
    ])

    os.remove(csr)
    print(f"✅ Certificate generated for {role.upper()} at {cert}")

print("🎉 All ML-DSA certificates generated in ./certs_ml/")
