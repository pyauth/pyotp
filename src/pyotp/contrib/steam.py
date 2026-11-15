from __future__ import annotations

import hashlib

from ..totp import TOTP

STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY"  # steam's custom alphabet
STEAM_DEFAULT_DIGITS = 5  # Steam TOTP code length


class Steam(TOTP):
    """
    Steam's custom TOTP. Subclass of `pyotp.totp.TOTP`.
    """

    def __init__(
        self, s: str, *, name: str | None = None, issuer: str | None = None, interval: int = 30, digits: int = 5
    ) -> None:
        """
        :param s: secret in base32 format
        :param interval: the time interval in seconds for OTP. This defaults to 30.
        :param name: account name
        :param issuer: issuer
        """
        if interval <= 0:
            raise ValueError("interval must be positive")
        self.interval = interval
        super().__init__(s=s, digits=10, digest=hashlib.sha1, name=name, issuer=issuer)

    def generate_otp(self, input: int) -> str:
        """
        :param input: the HMAC counter value to use as the OTP input.
            Usually either the counter, or the computed integer based on the Unix timestamp
        """
        int_code = int(super().generate_otp(input))
        total_chars = len(STEAM_CHARS)

        digits = []
        for _ in range(STEAM_DEFAULT_DIGITS):
            digits.append(STEAM_CHARS[int_code % total_chars])
            int_code //= total_chars

        return "".join(digits)
