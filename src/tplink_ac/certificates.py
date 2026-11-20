"""Generate fresh local lab credentials; never reuse the expired vendor key."""
from datetime import datetime,timedelta,timezone
from pathlib import Path

def generate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
    directory = Path(directory); directory.mkdir(parents=True,exist_ok=True)
    cert_path,key_path = directory/'lab-cert.pem',directory/'lab-key.pem'
    if cert_path.exists() or key_path.exists(): raise ValueError('测试证书已存在，不会覆盖；可直接选择现有文件')
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'TP-LINK AC Local Lab')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5))
            .not_valid_after(now+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
            .sign(key,hashes.SHA256()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    key_path.chmod(0o600)
    return {'cert':str(cert_path.resolve()),'key':str(key_path.resolve()),'ca':str(cert_path.resolve())}
