import base64
import hashlib
import hmac
from typing import Any, Optional


class OTP(object):
    """
    Base class for OTP handlers.
    """

    def __init__(
            self,
            s: str,
            digits: int = 6,
            digest: Any = hashlib.sha1,
            name: Optional[str] = None,
            issuer: Optional[str] = None,
    ) -> None:
        self.digits = digits
        if digits > 10:
            raise ValueError("digits must be no greater than 10")
        self.digest = digest
        if digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")
        self.secret = s
        self.name = name or "Secret"
        self.issuer = issuer

    def generate_otp(self, input: int) -> str:
        """
        :param input: the HMAC counter value to use as the OTP input.
            Usually either the counter, or the computed integer based on the Unix timestamp.
        """
        if input < 0:
            raise ValueError("input must be positive integer")
        hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(input), self.digest)
        if hasher.digest_size < 18:
            raise ValueError("digest size is lower than 18 bytes, which will trigger error on otp generation")
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xF
        code = (
                (hmac_hash[offset] & 0x7F) << 24
                | (hmac_hash[offset + 1] & 0xFF) << 16
                | (hmac_hash[offset + 2] & 0xFF) << 8
                | (hmac_hash[offset + 3] & 0xFF)
        )
        str_code = str(10_000_000_000 + (code % 10 ** self.digits))
        return str_code[-self.digits:]

    def byte_secret(self) -> bytes:
        """Decode a base32-encoded secret into its raw byte representation."""
        secret = self.secret
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += "=" * (8 - missing_padding)

        # `casefold=True`, which allows the decoder to process both uppercase and lowercase characters.
        return base64.b32decode(secret, casefold=True)

    @staticmethod
    def int_to_bytestring(i: int, padding: int = 8) -> bytes:
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret.
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        # It's necessary to convert the final result from bytearray to bytes
        # because the hmac functions in python 2.6 and 3.3 don't work with
        # bytearray
        return bytes(bytearray(reversed(result)).rjust(padding, b"\0"))
