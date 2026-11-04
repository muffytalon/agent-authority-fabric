"""Independent ES256 JWS vectors for src/tokens.rs, built with pyca/cryptography."""
import base64, hashlib, json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SECRET = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721  # RFC 6979 A.2.5

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
def canon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

key = ec.derive_private_key(SECRET, ec.SECP256R1())
pub = key.public_key().public_numbers()
x, y = pub.x.to_bytes(32, "big"), pub.y.to_bytes(32, "big")
assert pub.x == 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6  # RFC 6979 A.2.5 Ux
kid = b64(hashlib.sha256(canon({"crv": "P-256", "kty": "EC", "x": b64(x), "y": b64(y)})).digest())

def sign(typ, claims):
    header = canon({"alg": "ES256", "kid": kid, "typ": typ})
    signing_input = (b64(header) + "." + b64(canon(claims))).encode()
    der = key.sign(signing_input, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    if s > N // 2:
        s = N - s
    key.public_key().verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    return signing_input.decode() + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

EID = "01JBAE0Z1TFCQ9Y41W9NF6YYMB"
episode = {"client_id": "gate1-harness", "eid": EID, "exp": 1_800_028_800, "iat": 1_800_000_000,
           "intent_digest": "sha-256:j3XfycsYi2G8jSVocXUTiPN2JWbcwQfOK1L4pLAdI1E", "peer_uid": 20001,
           "rar_digest": "sha-256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o", "release_epoch": 7,
           "sub": "operator@corp.example", "txn": EID}
proof = {"action_digest": "sha-256:j3XfycsYi2G8jSVocXUTiPN2JWbcwQfOK1L4pLAdI1E",
         "aud": "spiffe://corp.example/broker", "eid": EID, "exp": 1_800_000_060, "iat": 1_800_000_000,
         "iss": "spiffe://corp.example/pep", "jti": "AAAAAAAAAAAAAAAAAAAAAA", "release_epoch": 7,
         "server_id": "a", "tool_schema_digest": "sha-256:bdmNQo66RS-48sR_0n8pP5jmbo0a0Sh00gUWv8nEDNU",
         "rid": 1, "prov": ["sha-256:2pEVfWny8jku05UQCRDDarGnSs_F2tZB7_YtsC-7SYU"],
         "budget": {"amount_minor": 5000, "committed_minor": 0, "currency": "USD", "reserved_minor": 5000}}
print("KID", kid)
print("SEC1", (b"\x04" + x + y).hex())
print("EPISODE", sign("pep-episode+jwt", episode))
print("PROOF", sign("pep-callproof+jwt", proof))
