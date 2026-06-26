import time, json, base64
from typing import Tuple, Callable
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends   import default_backend

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

class OIDC_Service:
    def __init__(self, issuer: str, audience: str, authorizator: Callable[[str, str], bool], endpoint:str = '/oauth2/token', expires: int = 3600):
        self._issuer = issuer
        self._expires = expires
        self._endpoint = endpoint
        self._audience = audience
        self._authorizator = authorizator
        self.reset_RS256_keypair()

    def reset_issuer(self, issuer: str):
        self._issuer = issuer

    def reset_expires(self, expires: int):
        self._expires = expires

    def reset_endpoint(self, endpoint: str):
        self._endpoint = endpoint

    def reset_audience(self, audience: str):
        self._audience = audience
    
    def reset_authorizator(self, authorizator: Callable[[str, str], bool]):
        self._authorizator = authorizator

    def reset_RS256_keypair(self):
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()

        pub_numbers = self._public_key.public_numbers()
        n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, byteorder='big')
        e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, byteorder='big')
        n_b64 = base64.urlsafe_b64encode(n_bytes).decode().rstrip("=")
        e_b64 = base64.urlsafe_b64encode(e_bytes).decode().rstrip("=")
        
        self._public_jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "1",
            "n": n_b64,
            "e": e_b64
        }

    def _generate_jwt(self, client_id: str) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": client_id,
            "iat": now,
            "exp": now + self._expires,
            "scope": "openid",
            "client_id": client_id
        }
        header_enc = base64url_encode(json.dumps(header).encode())
        payload_enc = base64url_encode(json.dumps(payload).encode())
        signing_input = f"{header_enc}.{payload_enc}".encode()
        signature = self._private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_enc = base64url_encode(signature)
        return f"{header_enc}.{payload_enc}.{signature_enc}"
    
    def openid_configuration(self) -> dict:
        return {
            "issuer": self._issuer,
            "token_endpoint": f"{self._issuer}{self._endpoint}",
            "jwks_uri": f"{self._issuer}/.well-known/jwks.json",
            "grant_types_supported": ["client_credentials"],
            "scopes_supported": ["openid"],
            "response_types_supported": ["token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"]
        }
    
    def jwks(self) -> dict:
        return {"keys": [self._public_jwk]}
    
    def token_endpoint(self, authorization: str) -> Tuple[dict, bool]:
        if authorization and authorization.startswith("Basic "):
            try:
                credentials = base64.b64decode(authorization[6:]).decode()
                if self._authorizator(*credentials.split(":", 1)):
                    return {
                        "access_token": self._generate_jwt(credentials.split(":", 1)[0]),
                        "expires_in": self._expires,
                        "token_type": "Bearer",
                        "scope": "openid"
                    }, True
            except: return {"error": "invalid_client"}, False
        return             {"error": "invalid_client"}, False