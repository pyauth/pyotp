from __future__ import annotations

import unicodedata
from hmac import compare_digest
from urllib.parse import quote, urlencode, urlparse

_MAX_COMPARISON_LENGTH = 1024


def build_uri(
    secret: str,
    name: str,
    initial_count: int | None = None,
    issuer: str | None = None,
    algorithm: str | None = None,
    digits: int | None = None,
    period: int | None = None,
    **kwargs: str,
) -> str:
    """
    Returns the provisioning URI for the OTP; works for either TOTP or HOTP.

    This can then be encoded in a QR Code and used to provision the Google
    Authenticator app.

    For module-internal use.

    See also:
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    :param secret: the hotp/totp secret used to generate the URI
    :param name: name of the account
    :param initial_count: starting counter value, defaults to None.
        If none, the OTP type will be assumed as TOTP.
    :param issuer: the name of the OTP issuer; this will be the
        organization title of the OTP entry in Authenticator
    :param algorithm: the algorithm used in the OTP generation.
    :param digits: the length of the OTP generated code.
    :param period: the number of seconds the OTP generator is set to
        expire every code.
    :param kwargs: other query string parameters to include in the URI
    :returns: provisioning uri
    """
    # initial_count may be 0 as a valid param
    is_initial_count_present = initial_count is not None

    # Handling values different from defaults
    is_algorithm_set = algorithm is not None and algorithm != "sha1"
    is_digits_set = digits is not None and digits != 6
    is_period_set = period is not None and period != 30

    otp_type = "hotp" if is_initial_count_present else "totp"
    base_uri = "otpauth://{0}/{1}?{2}"

    url_args: dict[str, None | int | str] = {"secret": secret}

    label = quote(name)
    if issuer is not None:
        label = quote(issuer) + ":" + label
        url_args["issuer"] = issuer

    if is_initial_count_present:
        url_args["counter"] = initial_count
    if is_algorithm_set:
        url_args["algorithm"] = algorithm.upper()  # type: ignore
    if is_digits_set:
        url_args["digits"] = digits
    if is_period_set:
        url_args["period"] = period
    for k, v in kwargs.items():
        if not isinstance(v, str):
            raise TypeError("All otpauth uri parameters must be strings")
        if k == "image":
            image_uri = urlparse(v)
            if image_uri.scheme != "https" or not image_uri.netloc or not image_uri.path:
                raise ValueError(f"{image_uri} is not a valid url")
        url_args[k] = v

    uri = base_uri.format(otp_type, label, urlencode(url_args).replace("+", "%20"))
    return uri


def strings_equal(s1: str, s2: str) -> bool:
    """
    Timing-attack resistant string comparison.

    Normal comparison using == will short-circuit on the first mismatching
    character. This avoids that by scanning the whole string, though we
    still reveal to a timing attack whether the strings are the same
    length.

    Returns False if either input exceeds 1024 Unicode code points.
    The limit is checked before normalization to bound its CPU cost
    and mitigate CVE-2026-3276.
    """
    if len(s1) > _MAX_COMPARISON_LENGTH or len(s2) > _MAX_COMPARISON_LENGTH:
        return False
    s1 = unicodedata.normalize("NFKC", s1)
    s2 = unicodedata.normalize("NFKC", s2)
    return compare_digest(s1.encode("utf-8"), s2.encode("utf-8"))
