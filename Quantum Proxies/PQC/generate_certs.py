import subprocess
import os

CERTS_DIR = "certs"
CA_CERT = os.path.join(CERTS_DIR, "ca_cert.pem")
CA_KEY = os.path.join(CERTS_DIR, "ca_key.pem")
OPENSSL = "/usr/local/openssl-3.5/bin/openssl"
CONFIG = "/usr/local/openssl-3.5/openssl.cnf"

SIG = "falcon512"

os.makedirs(CERTS_DIR, exist_ok=True)

def run_openssl(cmd_args):
    print(f"Running: {' '.join(cmd_args)}")
    subprocess.run(cmd_args, check=True)

if not os.path.exists(CA_CERT):
    run_openssl([
        OPENSSL, "req", "-x509", "-newkey", SIG,
        "-keyout", CA_KEY, "-out", CA_CERT,
        "-days", "365", "-nodes",
        "-subj", "/CN=Test CA",
        "-provider", "oqsprovider",
        "-provider", "default",
        "-config", CONFIG
    ])
    print(f"✅ CA certificate generated: {CA_CERT}")

for role in ["sae", "kme"]:
    key = os.path.join(CERTS_DIR, f"{role}_{SIG}_key.pem")
    csr = os.path.join(CERTS_DIR, f"{role}_{SIG}.csr")
    cert = os.path.join(CERTS_DIR, f"{role}_{SIG}.pem")

    run_openssl([
        OPENSSL, "req", "-newkey", SIG, "-nodes",
        "-keyout", key, "-out", csr,
        "-subj", f"/CN={role.upper()}-{SIG}",
        "-provider", "oqsprovider",
        "-provider", "default",
        "-config", CONFIG
    ])

    run_openssl([
        OPENSSL, "x509", "-req",
        "-in", csr, "-CA", CA_CERT, "-CAkey", CA_KEY, "-CAcreateserial",
        "-out", cert, "-days", "365",
        "-provider", "oqsprovider",
        "-provider", "default"
    ])

    os.remove(csr)
    print(f"✅ Certificate generated for {role.upper()} at {cert}")

print("🎉 All certificates generated in ./certs/")
