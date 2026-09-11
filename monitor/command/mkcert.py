import os, time
import datetime
import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from typing  import Optional, Union, Tuple, List
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
    domain: list,subject: str,
    ca_private_key_bytes: bytes,
    ca_cert_bytes: bytes,
    validity_days: int = 365,
    output_format: str = "PEM",
    TLS_Web_AType: str = "SERVER",
    ca_private_key_password: Optional[bytes] = None,
    server_private_key_password: Optional[bytes] = None,
    crl_distribution_points: Optional[List[str]] = None,
) -> Tuple[bytes, bytes]:
    """
    使用 CA 签发证书。

    参数:
        domain:                     服务器的域名或 IP
        subject:                    证书的主题名称 (CN)
        ca_private_key_bytes:       CA 私钥的字节数据
        ca_cert_bytes:              CA 证书的字节数据
        validity_days:              服务器证书有效天数
        output_format:              输出格式 'DER' 或 'PEM'
        TLS_Web_AType:              证书适用范围 'SERVER' 或 'CLIENT'
        ca_private_key_password:    CA 私钥的密码(如果加密)
        server_private_key_password:新服务器私钥的加密密码
        crl_distribution_points:    CRL 分发点扩展信息地址

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
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject)
    ]))
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    builder = builder.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(server_key.public_key())

    regist_domain = []
    
    for domain_name in domain:
        try:    # Add Subject Alternative Name
            ip  = ipaddress.ip_address(domain_name)
            regist_domain.append(x509.IPAddress(ip))
        except ValueError:
            regist_domain.append(x509.DNSName(domain_name))

    regist_san = x509.SubjectAlternativeName(regist_domain)
    builder = builder.add_extension(regist_san, critical=False)

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

    if crl_distribution_points:
        dps = []
        for url in crl_distribution_points:
            dps.append(
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(url)],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                )
            )
        builder = builder.add_extension(
            x509.CRLDistributionPoints(dps),
            critical=False  # 通常设为非关键
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


def generate_pfx(
    cert_pem: bytes,
    key_pem: bytes,
    pfx_password: Optional[bytes] = None,
    key_password: Optional[bytes] = None,
    name:         Optional[str] = None
) -> bytes:
    """
    将 PEM 格式的证书和私钥打包为 PFX (PKCS#12) 格式。

    参数:
        cert_pem:        PEM 编码的 X.509 证书（字节串）
        key_pem:         PEM 编码的私钥（字节串），可以是未加密或加密的
        pfx_password:    用于保护 PFX 的密码（字节串），若为 None 则不加密
        key_password:    私钥的解密密码（如果私钥是加密的），若未加密则传 None
        name:            名称（字符串），用于标识证书

    返回:
        PFX 格式的字节数据，可直接写入 .pfx 文件
    """
    # 1. 加载证书
    cert = x509.load_pem_x509_certificate(cert_pem)

    # 2. 加载私钥（支持加密/未加密）
    private_key = serialization.load_pem_private_key(
        key_pem,
        password=key_password
    )

    # 3. 序列化为 PKCS#12
    pfx_data = serialize_key_and_certificates(
        name=name.encode('utf-8') if name else None,
        key=private_key,
        cert=cert,
        cas=None,  # 未包含中间证书链，可根据需要扩展
        encryption_algorithm=(
            serialization.BestAvailableEncryption(pfx_password)
            if pfx_password
            else serialization.NoEncryption()
        )
    )
    return pfx_data


def generate_crl(
    ca_private_key_bytes: bytes,
    ca_cert_bytes: bytes,
    revoked_serial_numbers: Optional[List[Union[int, str]]] = None,
    this_update: Optional[datetime.datetime] = None,
    next_update_days: int = 30,
    output_format: str = "PEM",
    ca_private_key_password: Optional[bytes] = None,
    revocation_time: Optional[datetime.datetime] = None,
) -> bytes:
    """
    生成 X.509 CRL（证书吊销列表）。

    参数:
        ca_private_key_bytes:      CA 私钥的字节数据（PEM 或 DER）
        ca_cert_bytes:             CA 证书的字节数据（PEM 或 DER）
        revoked_serial_numbers:    要吊销的证书序列号列表（int 或十六进制字符串），默认为空列表
        this_update:               本次 CRL 发布时间，默认为当前 UTC 时间
        next_update_days:          下次 CRL 更新的天数偏移（自 this_update 起），默认 30 天
        output_format:             输出格式 'PEM' 或 'DER'，默认 'PEM'
        ca_private_key_password:   CA 私钥密码（如果有）
        revocation_time:           吊销时间，默认为 this_update（通常为吊销发生时刻）

    返回:
        CRL 数据的字节序列
    """
    if revoked_serial_numbers is None:
        revoked_serial_numbers = []

    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)
    except ValueError:
        ca_cert = x509.load_der_x509_certificate(ca_cert_bytes)

    try:
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_bytes, password=ca_private_key_password
        )
    except ValueError:
        ca_private_key = serialization.load_der_private_key(
            ca_private_key_bytes, password=ca_private_key_password
        )

    if this_update is None:
        this_update = datetime.datetime.now(datetime.timezone.utc)
    if not this_update.tzinfo:
        this_update = this_update.replace(tzinfo=datetime.timezone.utc)

    next_update = this_update + datetime.timedelta(days=next_update_days)

    if revocation_time is None:
        revocation_time = this_update
    if not revocation_time.tzinfo:
        revocation_time = revocation_time.replace(tzinfo=datetime.timezone.utc)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(this_update)
    builder = builder.next_update(next_update)

    for serial in revoked_serial_numbers:
        if isinstance(serial, str):
            serial_int = int(serial, 16) if serial.lower().startswith("0x") else int(serial, 16)
        else:
            serial_int = serial
        revoked_cert = x509.RevokedCertificateBuilder() \
            .serial_number(serial_int) \
            .revocation_date(revocation_time) \
            .build()
        builder = builder.add_revoked_certificate(revoked_cert)

    builder = builder.add_extension( # Add AuthorityKeyIdentifier Extensions
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
        critical=False
    )

    crl = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())

    if output_format.upper() == "DER":
        return crl.public_bytes(encoding=serialization.Encoding.DER)
    else:  # PEM
        return crl.public_bytes(encoding=serialization.Encoding.PEM)


def get_ca_time(
    ca_cert_bytes: bytes,
    ca_format: str = "PEM"
) -> Tuple[float, float]:
    if  ca_format.upper() == "DER":
        ca_cert = x509.load_der_x509_certificate(ca_cert_bytes)
    else:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)
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
    crl_distribution_points: Optional[List[str]] = None
    def __init__(self, cert_path: Path = Path('certs')):
        self.cert_path=cert_path
        self.cert_path.mkdir(exist_ok=True)
        self.Load_Root_CA()
    
    def Load_Root_CA(self):
        """
        加载根 CA 证书和私钥，如果不存在则生成新的。
        """
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

        self.install("Encrypted Root CA")
    
    def Rebuild_Root_CA(self):
        """
        重建根 CA 证书。
        """
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

        self.install("Encrypted Root CA")

    def install(self, cert_name: str = "Encrypted Root CA"):
        """
        安装根 CA 证书到系统信任存储。

        参数:
            cert_name: 证书的名称，用于标识安装的证书
        """
        ca_cert_path = str(self.cert_path / 'ca.crt')
        import subprocess
        if os.name == 'nt':  # Windows
            subprocess.run(['certutil', '-addstore', '-f', 'Root', ca_cert_path], check=True)
        elif os.name == 'posix':
            import sys
            if sys.platform == 'darwin':  # macOS
                subprocess.run(['sudo', 'security', 'add-trusted-cert', '-d', '-r', 'trustRoot', '-k', '/Library/Keychains/System.keychain', ca_cert_path], check=True)
            else:  # Linux
                import shutil
                trusted_cert_dir = '/usr/local/share/ca-certificates/'
                shutil.copy(ca_cert_path, trusted_cert_dir + cert_name + '.crt')
                subprocess.run(['sudo', 'update-ca-certificates'], check=True)

    def set_crl_distribution_points(self, crl_distribution_points: Optional[List[str]] = None):
        """
        设置 CRL 分发点扩展信息。

        参数:
            crl_distribution_points: CRL 分发点的 URL 列表，例如 ["http://example.com/crl"]
        """
        self.crl_distribution_points = crl_distribution_points

    def get_ca_time(self) -> Tuple[float, float]:
        """
        获取 CA 证书的有效时间范围。

        返回:
            一个包含 (not_valid_before, not_valid_after) 的元组，单位为秒（Unix 时间戳）
        """
        return get_ca_time(
            self.ca_cert_data,
            ca_format="PEM"
        )
    
    def get_ca_remain_day(self, sub_seconds: float = 60) -> int:
        """
        获取 CA 证书剩余有效天数。

        参数:
            sub_seconds: 从剩余时间中减去的秒数，默认为 60 秒

        返回:
            剩余有效天数
        """
        remain_seconds = self.get_ca_time()[1] - time.time()
        return max(int((remain_seconds - sub_seconds) / 24 / 3600), 0)
    
    def ca_is_available(self):
        """
        检查 CA 证书是否仍然有效。

        返回:
            True 如果 CA 证书仍然有效，否则 False
        """
        return self.get_ca_time()[1] - time.time() > 0

    def generate_pfx(self, name: Optional[str] = None, pfx_password: Optional[bytes] = None) -> bytes:
        """
        将 CA 证书和私钥打包为 PFX (PKCS#12) 格式。

        参数:
            name: 名称（字符串），用于标识证书
            pfx_password:  用于保护 PFX 的密码（字节串），若为 None 则不加密
        
        返回:
            PFX 格式的字节数据，可直接写入 .pfx 文件
        """
        return generate_pfx(
            self.ca_cert_data,
            self.ca_priv_data,
            pfx_password=pfx_password,
            name=name
        )

    def generate_crl(self,
        revoked_serial_numbers: Optional[List[Union[int, str]]] = None,
        this_update: Optional[datetime.datetime] = None,
        next_update_days: int = 30,
        revocation_time: Optional[datetime.datetime] = None,
    ) -> bytes:
        """
        生成 X.509 CRL（证书吊销列表）。
    
        参数:
            revoked_serial_numbers:    要吊销的证书序列号列表（int 或十六进制字符串），默认为空列表
            this_update:               本次 CRL 发布时间，默认为当前 UTC 时间
            next_update_days:          下次 CRL 更新的天数偏移（自 this_update 起），默认 30 天
            revocation_time:           吊销时间，默认为 this_update（通常为吊销发生时刻）
    
        返回:
            CRL 数据的字节序列
        """
        return generate_crl(
            self.ca_priv_data,
            self.ca_cert_data,
            revoked_serial_numbers,
            this_update,
            next_update_days,
            revocation_time=revocation_time
        )
    
    def generate_cert(self, domain: list, subject: str = "Encrypted Certificate", validity_days: Optional[int] = None, pfx_password: Optional[str] = None, TLS_Web_AType: str = "SERVER", IncludeCaCert: bool = True) -> Tuple[bytes, bytes, bytes]:
        """
        使用 CA 签发证书。

        参数:
            domain:          服务器的域名或 IP
            subject:         证书的主题名称 (CN)
            validity_days:   服务器证书有效天数，默认为 CA 证书剩余有效天数
            pfx_password:    用于保护 PFX 的密码（字节串），若为 None 则不加密
            TLS_Web_AType:   证书适用范围 'SERVER' 或 'CLIENT'
            IncludeCaCert:   是否在返回的证书中包含 CA 证书，
                             如果为 True，则返回的证书将包含 CA 证书的内容
        
        返回:
            (private_key_bytes, cert_bytes, pfx_bytes) 元组
        """
        cert = generate_cert(
            domain, subject,
            self.ca_priv_data,
            self.ca_cert_data,
            output_format="PEM",
            validity_days=validity_days or max(self.get_ca_remain_day(60), 1),
            TLS_Web_AType=TLS_Web_AType,
            crl_distribution_points=self.crl_distribution_points
        );  return cert[0], cert[1] + ( self.ca_cert_data if IncludeCaCert else b'' ), generate_pfx(
            cert[1] + ( self.ca_cert_data if IncludeCaCert else b'' ),
            cert[0], pfx_password=pfx_password.encode() if pfx_password else None, name=subject
        )
