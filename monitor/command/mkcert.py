import os, time
import datetime
import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from typing  import Optional, Tuple
from pathlib import Path

def generate_ca_cert(
    ca_name: str = "Root CA",
    company: str = "Company",
    key_size: int = 2048,
    validity_days: int = 3650,
    country: Optional[str] = "CN",
    output_format: str = "PEM",
    password: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    生成符合 X.509 标准的自签名 CA 根证书。

    参数:
        ca_name:      证书的通用名称 (CN)
        company:      组织名称 (O)
        key_size:     RSA 密钥长度(位)
        validity_days:证书有效天数
        country:      可选的国家代码 (C)
        output_format:输出格式，'DER' 或 'PEM'
        password:     可选，私钥加密密码(bytes 类型)

    返回:
        (private_key_bytes, certificate_bytes) 元组，均为二进制格式。
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    name_attributes = []
    if  country:
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, company))
    name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, company))
    name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, ca_name))
    subject = issuer = x509.Name(name_attributes)

    serial_number = int.from_bytes(os.urandom(8), 'big')

    not_valid_before = datetime.datetime.now(datetime.timezone.utc)
    not_valid_after  = not_valid_before + datetime.timedelta(days=validity_days)

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)
    builder = builder.serial_number(serial_number)
    builder = builder.public_key(private_key.public_key())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )

    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
    )
    encryption_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()

    if output_format.upper() == "DER":
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        cert_bytes = certificate.public_bytes(
            encoding=serialization.Encoding.DER
        )
    else:  # PEM 格式
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        cert_bytes = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    return private_bytes, cert_bytes

def generate_cert(
    domain_or_ip: str,
    ca_private_key_bytes: bytes,
    ca_cert_bytes: bytes,
    validity_days: int = 365,
    output_format: str = "PEM",
    TLS_Web_AType: str = "SERVER",
    ca_private_key_password: Optional[bytes] = None,
    server_private_key_password: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    使用 CA 签发服务器证书。

    参数:
        domain_or_ip:               服务器的域名或 IP
        ca_private_key_bytes:       CA 私钥的字节数据
        ca_cert_bytes:              CA 证书的字节数据
        validity_days:              服务器证书有效天数
        output_format:              输出格式 'DER' 或 'PEM'
        TLS_Web_AType:              证书适用范围 'SERVER' 或 'CLIENT'
        ca_private_key_password:    CA 私钥的密码(如果加密)
        server_private_key_password:新服务器私钥的加密密码

    返回:
        (server_private_key_bytes, server_cert_bytes) 元组
    """
    if   TLS_Web_AType.upper() == "SERVER":
         TLS_Web_AType = ExtendedKeyUsageOID.SERVER_AUTH
    elif TLS_Web_AType.upper() == "CLIENT":
         TLS_Web_AType = ExtendedKeyUsageOID.CLIENT_AUTH
    else:TLS_Web_AType = ExtendedKeyUsageOID.SERVER_AUTH
    
    if  output_format.upper() == "DER":
        ca_cert = x509.load_der_x509_certificate(ca_cert_bytes)
        ca_private_key = serialization.load_der_private_key(
            ca_private_key_bytes, password=ca_private_key_password
        )
    else:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_bytes, password=ca_private_key_password
        )
    
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain_or_ip)
    ]))
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(server_key.public_key())

    try:    # Add Subject Alternative Name
        ip  = ipaddress.ip_address(domain_or_ip)
        san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
    except ValueError:
        san = x509.SubjectAlternativeName([x509.DNSName(domain_or_ip)])
    builder = builder.add_extension(san, critical=False)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            TLS_Web_AType
        ]),
        critical=False
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
        critical=False
    )

    server_cert = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256()
    )
    encryption_algo = serialization.BestAvailableEncryption(server_private_key_password) if server_private_key_password else serialization.NoEncryption()

    if output_format.upper() == "DER":
        server_key_bytes = server_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        server_cert_bytes = server_cert.public_bytes(
            encoding=serialization.Encoding.DER
        )
    else:
        server_key_bytes = server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
        )
        server_cert_bytes = server_cert.public_bytes(
            encoding=serialization.Encoding.PEM
        )

    return server_key_bytes, server_cert_bytes

def get_ca_time(
    ca_private_key_bytes: bytes,
    ca_cert_bytes: bytes,
    ca_format: str = "PEM",
    ca_private_key_password: Optional[bytes] = None
) -> Tuple[float, float]:
    if  ca_format.upper() == "DER":
        ca_cert = x509.load_der_x509_certificate(ca_cert_bytes)
        ca_private_key = serialization.load_der_private_key(
            ca_private_key_bytes, password=ca_private_key_password
        )
    else:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_bytes, password=ca_private_key_password
        )
    return (
        ca_cert.not_valid_before.timestamp(),
        ca_cert.not_valid_after.timestamp()
    )

def read_file(file_path: str) -> bytes:
    try:
        with open(file_path, 'rb') as f: return f.read()
    except: return b''

def write_file(file_path: str, data: bytes):
    try:
        with open(file_path, 'wb') as f: f.write(data)
    except: pass

class makecerts:
    ca_priv_data: bytes = b''
    ca_cert_data: bytes = b''
    def __init__(self, cert_path: Path = Path('certs')):
        self.cert_path=cert_path
        self.cert_path.mkdir(exist_ok=True)
        self.Load_Root_CA()
        try: self.Install_CA()
        except:pass
    
    def Load_Root_CA(self):
        ca_priv_path = str(self.cert_path / 'ca.key')
        ca_cert_path = str(self.cert_path / 'ca.crt')
        
        self.ca_priv_data = read_file(ca_priv_path)
        self.ca_cert_data = read_file(ca_cert_path)
        
        if  not self.ca_priv_data or\
            not self.ca_cert_data:
            self.ca_priv_data, self.ca_cert_data = generate_ca_cert(
                "Encrypted Root CA",
                company="Secure CA",
                output_format="PEM",
                validity_days=75000
            )
            
            write_file(ca_priv_path, self.ca_priv_data)
            write_file(ca_cert_path, self.ca_cert_data)
    
    def Rebuild_Root_CA(self):
        ca_priv_path = str(self.cert_path / 'ca.key')
        ca_cert_path = str(self.cert_path / 'ca.crt')
        
        self.ca_priv_data, self.ca_cert_data = generate_ca_cert(
            "Encrypted Root CA",
            company="Secure CA",
            output_format="PEM",
            validity_days=75000
        )
        
        write_file(ca_priv_path, self.ca_priv_data)
        write_file(ca_cert_path, self.ca_cert_data)
    
    def Install_CA(self):
        import platform
        system = platform.system()
        if system == "Windows":
            import subprocess
            subprocess.run(['certutil', '-addstore', '-f', 'Root', str(self.cert_path / 'ca.crt')], check=True)
        elif system == "Darwin":
            import subprocess
            subprocess.run(['sudo', 'security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', '/Library/Keychains/System.keychain', str(self.cert_path / 'ca.crt')], check=True)
        elif system == "Linux":
            import shutil
            if os.path.exists('/usr/local/share/ca-certificates/monitor_ca.crt'):
                os.remove('/usr/local/share/ca-certificates/monitor_ca.crt')
            shutil.copy(str(self.cert_path / 'ca.crt'), '/usr/local/share/ca-certificates/monitor_ca.crt')
            subprocess.run(['sudo', 'update-ca-certificates'], check=True)
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def get_ca_time(self) -> Tuple[float, float]:
        return get_ca_time(
            self.ca_priv_data,
            self.ca_cert_data,
            ca_format="PEM"
        )
    
    def get_ca_remain_day(self, sub_seconds: float = 60) -> int:
        remain_seconds = self.get_ca_time()[1] - time.time()
        return max(int( ( remain_seconds - sub_seconds ) / 24 / 3600), 0)
    
    def ca_is_available(self):
        return self.get_ca_time()[1] - time.time() > 0
    
    def generate_cert(self, domain: str, validity_days: Optional[int] = None, TLS_Web_AType: str = "SERVER", IncludeCaCert: bool = True) -> Tuple[bytes, bytes]:
        cert = generate_cert(
            domain,
            self.ca_priv_data,
            self.ca_cert_data,
            output_format="PEM",
            validity_days=validity_days or max(self.get_ca_remain_day(60), 1),
            TLS_Web_AType=TLS_Web_AType
        );  return cert[0], cert[1] + ( self.ca_cert_data if IncludeCaCert else b'' )