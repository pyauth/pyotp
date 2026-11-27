from __future__ import annotations

import hashlib

from .. import utils
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
        :param interval: the time interval in seconds, greater than 0 and at most 120. Defaults to 30.
        :param name: account name
        :param issuer: issuer

        See `NIST SP 800-63B-4 section 3.1.4.1
        <https://pages.nist.gov/800-63-4/sp800-63b.html>`_.
        """
        # NIST SP 800-63B-4 section 3.1.4.1 requires a new nonce at least every two minutes.
        if not 0 < interval <= 120:
            raise ValueError("interval must be positive and at most 120 seconds")
        self.interval = interval
        super().__init__(s=s, digits=10, digest=hashlib.sha1, name=name, issuer=issuer)

    def provisioning_uri(self, name: Optional[str] = None, issuer_name: Optional[str] = None, **kwargs) -> str:
        """
        Returns the provisioning URI for this Steam OTP.

        This differs from :meth:`pyotp.totp.TOTP.provisioning_uri` in two ways, so that the URI
        round-trips back through :func:`pyotp.parse_uri` as a ``Steam`` instance:

        * ``encoder=steam`` is included, which is what ``parse_uri()`` uses to select this class.
        * ``digits`` is omitted. ``self.digits`` is 10 because the Steam code is derived from a
          10-digit HOTP value, but that is an internal detail; the code shown to the user is 5
          characters from a custom alphabet, and ``digits=10`` is not a legal value for the
          ``otpauth://`` ``digits`` parameter.
        """
        kwargs.setdefault("encoder", "steam")
        return utils.build_uri(
            self.secret,
            name if name else self.name,
            issuer=issuer_name if issuer_name else self.issuer,
            algorithm=self.digest().name,
            period=self.interval,
            **kwargs,
        )

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
