PyOTP - The Python One-Time Password Library
============================================

PyOTP is a Python library for generating and verifying one-time passwords. It can be used to implement two-factor (2FA)
or multi-factor (MFA) authentication methods in web applications and in other systems that require users to log in.

Open MFA standards are defined in `RFC 4226 <https://tools.ietf.org/html/rfc4226>`_ (HOTP: An HMAC-Based One-Time
Password Algorithm) and in `RFC 6238 <https://tools.ietf.org/html/rfc6238>`_ (TOTP: Time-Based One-Time Password
Algorithm). PyOTP implements server-side support for both of these standards. Client-side support can be enabled by
sending authentication codes to users over SMS or email (HOTP) or, for TOTP, by instructing users to use `Google
Authenticator <https://en.wikipedia.org/wiki/Google_Authenticator>`_, `Authy <https://www.authy.com/>`_, or another
compatible app. Users can set up auth tokens in their apps easily by using their phone camera to scan `otpauth://
<https://github.com/google/google-authenticator/wiki/Key-Uri-Format>`_ QR codes provided by PyOTP.

Implementers should read and follow the `HOTP security requirements <https://tools.ietf.org/html/rfc4226#section-7>`_
and `TOTP security considerations <https://tools.ietf.org/html/rfc6238#section-5>`_ sections of the relevant RFCs. At
minimum, application implementers should follow this checklist:

- Ensure transport confidentiality by using HTTPS
- Ensure HOTP/TOTP secret confidentiality by storing secrets in a controlled access database
- Deny replay attacks by persisting the last accepted OTP counter for each credential and rejecting reused counters.
  For TOTP, use ``verify_and_get_timecode()`` as described in `Preventing replay attacks`_ below.
- Throttle (rate limit) brute-force attacks against your application's login functionality (see RFC 4226, section 7.3)
- When implementing a "greenfield" application, consider supporting
  `FIDO U2F <https://en.wikipedia.org/wiki/Universal_2nd_Factor>`_/`WebAuthn <https://www.w3.org/TR/webauthn/>`_ in
  addition to or instead of HOTP/TOTP. U2F uses asymmetric cryptography to avoid using a shared secret design, which
  strengthens your MFA solution against server-side attacks. Hardware U2F also sequesters the client secret in a
  dedicated single-purpose device, which strengthens your clients against client-side attacks. And by automating scoping
  of credentials to relying party IDs (application origin/domain names), U2F adds protection against phishing attacks.
  One implementation of FIDO U2F/WebAuthn is PyOTP's sister project, `PyWARP <https://github.com/pyauth/pywarp>`_.

We also recommend that implementers read `NIST SP 800-63 Digital Identity Guidelines <https://pages.nist.gov/800-63-4/>`_,
including sections 3.1.4 (Single-Factor OTP) and 3.1.5 (Multi-Factor OTPs), for an in-depth discussion of authentication,
as well as the `OWASP Authentication Cheat Sheet
<https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md>`_ for a high level
overview of authentication best practices.

Quick overview of using One Time Passwords on your phone
--------------------------------------------------------

* OTPs involve a shared secret, stored both on the phone and the server
* OTPs can be generated on a phone without internet connectivity
* OTPs should always be used as a second factor of authentication (if your phone is lost, you account is still secured
  with a password)
* Google Authenticator and other OTP client apps allow you to store multiple OTP secrets and provision those using a QR
  Code

Installation
------------
::

    pip install pyotp

Usage
-----

Time-based OTPs
~~~~~~~~~~~~~~~
.. code:: python

    import pyotp

    totp = pyotp.TOTP('base32secret32323232323232')
    totp.now()  # Current OTP; changes with the clock.

    # A fixed Unix timestamp makes these example outputs reproducible.
    totp.at(1234567890) # => '763850'
    totp.verify('763850', for_time=1234567890) # => True
    totp.verify('763850', for_time=1234567920) # => False

Preventing replay attacks
~~~~~~~~~~~~~~~~~~~~~~~~~

``TOTP.verify()`` and ``TOTP.verify_and_get_timecode()`` are stateless: they can accept the same OTP repeatedly while
it remains valid. To prevent reuse, call ``verify_and_get_timecode()`` and persist its returned timecode for each
credential in a database shared by all application workers. The timecode identifies the matching TOTP interval;
it is not the wall-clock timestamp when verification occurred. Reject a timecode that is less than or equal to the
last accepted timecode.

``verify_and_get_timecode()`` raises ``pyotp.OTPVerificationError`` (a subclass of ``pyotp.PyOTPError``) if the OTP
does not match within the allowed window. Successful verification always returns an integer timecode.

The check and update must be atomic, so two concurrent requests cannot both accept the same timecode. For example,
the following function uses a ``sqlite3.Connection`` named ``db`` and a ``totp_credentials`` table with one existing
row per credential, an ``id`` primary key, and a nullable integer ``last_timecode`` column. Initialize
``last_timecode`` to ``NULL`` for a new credential. ``totp`` and ``credential_id`` must refer to the same credential.

.. code:: python

    import pyotp

    def verify_totp_once(db, credential_id, totp, otp):
        try:
            matched_timecode = totp.verify_and_get_timecode(otp)
        except pyotp.OTPVerificationError:
            return False

        with db:
            updated = db.execute(
                "UPDATE totp_credentials SET last_timecode = ? "
                "WHERE id = ? AND (last_timecode IS NULL OR last_timecode < ?)",
                (matched_timecode, credential_id, matched_timecode),
            )
        return updated.rowcount == 1

Grant authentication only when this function returns ``True``, after the database transaction has committed.
If you enable ``valid_window``, persist the returned matching timecode, which may differ from the server's current timecode.

.. warning::

    For both HOTP and TOTP, do not use the raw submitted OTP, or a hash of that raw value, as the replay-detection key.
    PyOTP applies Unicode NFKC normalization when comparing OTPs: for example, ``123456`` and ``１２３４５６`` are treated
    as the same code, but their raw strings and hashes differ. An attacker could submit another spelling of an
    already-used code to bypass such a check. Track the accepted counter instead.

Counter-based OTPs
~~~~~~~~~~~~~~~~~~
.. code:: python

    import pyotp
    
    hotp = pyotp.HOTP('base32secret32323232323232')
    hotp.at(0) # => '995369'
    hotp.at(1) # => '511453'
    hotp.at(1401) # => '666948'

    # OTP verified with a counter
    hotp.verify('666948', 1401) # => True
    hotp.verify('666948', 1402) # => False

Generating a Secret Key
~~~~~~~~~~~~~~~~~~~~~~~
A helper function is provided to generate a 32-character base32 secret, compatible with Google Authenticator and other
OTP apps:

.. code:: python

    pyotp.random_base32()

Some applications want the secret key to be formatted as a hex-encoded string:

.. code:: python

    pyotp.random_hex()  # returns a 40-character hex-encoded secret

Secret strength and hash functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`NIST SP 800-63B-4 section 3.1.4.1 <https://pages.nist.gov/800-63-4/sp800-63b.html>`_
requires the OTP key and algorithm to provide at least 112 bits of security strength; section 3.1.4.2 describes
verifier requirements. PyOTP rejects secrets shorter than 112 bits (14 bytes) after Base32 decoding when generating
or verifying an OTP. Character count alone is not the check, and sufficient length does not establish entropy.
Generate a fresh random secret for each credential with ``random_base32()``, whose default is 160 bits.
The recognizable seeds in this README are public teaching examples, not production secrets.

PyOTP uses HMAC hash functions, not encryption ciphers. The URI parser supports SHA-1, SHA-256, and SHA-512.
`NIST SP 800-131A Rev. 2 sections 9 and 10 <https://doi.org/10.6028/NIST.SP.800-131Ar2>`_ permit these for HMAC
with keys of at least 112 bits. SHA-1 remains the interoperability default, but NIST recommends migrating to SHA-2
or SHA-3 and has announced a `SHA-1 transition by December 31, 2030
<https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions>`_. Use SHA-256 or SHA-512 when both
the authenticator and verifier support it.

The ``digest`` argument also accepts other compatible hash implementations; it does not enforce a NIST allowlist.
SHA-224, SHA-384, SHA-512/224, SHA-512/256, and the four fixed-length SHA-3 functions are on the
`NIST approved hash list <https://csrc.nist.gov/projects/hash-functions>`_. BLAKE2b, BLAKE2s, SM3, RIPEMD-160,
and MD5-SHA1 are not on that list, even where the Python/OpenSSL installation lets PyOTP use them.
MD5 and SHAKE are not supported OTP digests. Passing a key-length check alone does not establish NIST conformance.

The RFC 4226 and RFC 6238 test vectors use 160-, 256-, or 512-bit keys and meet the key-length requirement.
Their published, predictable keys are only suitable for testing. Legacy 80-bit example seeds do not meet the
requirement and must be replaced through re-enrollment, not by padding an existing production secret.

Google Authenticator Compatible
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PyOTP works with the Google Authenticator iPhone and Android app, as well as other OTP apps like Authy. PyOTP includes
the ability to generate provisioning URIs for use with the QR Code scanner built into these MFA client apps:

.. code:: python

    pyotp.totp.TOTP('JBSWY3DPEHPK3PXPJBSWY3DP').provisioning_uri(name='alice@google.com', issuer_name='Secure App')

    # => 'otpauth://totp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=Secure%20App'

    pyotp.hotp.HOTP('JBSWY3DPEHPK3PXPJBSWY3DP').provisioning_uri(name="alice@google.com", issuer_name="Secure App", initial_count=0)

    # => 'otpauth://hotp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=Secure%20App&counter=0'

This URL can then be rendered as a QR Code (for example, using https://github.com/soldair/node-qrcode) which can then be
scanned and added to the users list of OTP credentials.

Parsing these URLs is also supported:

.. code:: python

    totp = pyotp.parse_uri('otpauth://totp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=Secure%20App')

    type(totp).__name__ # => 'TOTP'

    hotp = pyotp.parse_uri('otpauth://hotp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=Secure%20App&counter=0')

    type(hotp).__name__ # => 'HOTP'

Working example
~~~~~~~~~~~~~~~

Scan the following barcode with your phone's OTP app (e.g. Google Authenticator):

.. image:: https://quickchart.io/qr?size=250&text=otpauth%3A%2F%2Ftotp%2Falice%40google.com%3Fsecret%3DJBSWY3DPEHPK3PXPJBSWY3DP

Now run the following and compare the output:

.. code:: python

    import pyotp
    totp = pyotp.TOTP("JBSWY3DPEHPK3PXPJBSWY3DP")
    print("Current OTP:", totp.now())

Third-party contributions
~~~~~~~~~~~~~~~~~~~~~~~~~
The following third-party contributions are not described by a standard, not officially supported, and provided for
reference only:

* ``pyotp.contrib.Steam()``: An implementation of Steam TOTP. Uses the same API as `pyotp.TOTP()`.

Links
~~~~~

* `Project home page (GitHub) <https://github.com/pyauth/pyotp>`_
* `Documentation <https://pyauth.github.io/pyotp/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/pyotp>`_
* `Change log <https://github.com/pyauth/pyotp/blob/master/Changes.rst>`_
* `RFC 4226: HOTP: An HMAC-Based One-Time Password <https://tools.ietf.org/html/rfc4226>`_
* `RFC 6238: TOTP: Time-Based One-Time Password Algorithm <https://tools.ietf.org/html/rfc6238>`_
* `ROTP <https://github.com/mdp/rotp>`_ - Original Ruby OTP library by `Mark Percival <https://github.com/mdp>`_
* `OTPHP <https://github.com/lelag/otphp>`_ - PHP port of ROTP by `Le Lag <https://github.com/lelag>`_
* `OWASP Authentication Cheat Sheet <https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md>`_
* `NIST SP 800-63 Digital Identity Guidelines <https://pages.nist.gov/800-63-4/>`_

For new applications:

* `WebAuthn <https://www.w3.org/TR/webauthn/>`_
* `PyWARP <https://github.com/pyauth/pywarp>`_

Versioning
~~~~~~~~~~
This package follows the `Semantic Versioning 2.0.0 <http://semver.org/>`_ standard. To control changes, it is
recommended that application developers pin the package version and manage it using `pip-tools
<https://github.com/jazzband/pip-tools>`_ or similar. For library developers, pinning the major version is
recommended.

.. image:: https://github.com/pyauth/pyotp/workflows/Python%20package/badge.svg
        :target: https://github.com/pyauth/pyotp/actions
.. image:: https://img.shields.io/codecov/c/github/pyauth/pyotp/master.svg
        :target: https://codecov.io/github/pyauth/pyotp?branch=master
.. image:: https://img.shields.io/pypi/v/pyotp.svg
        :target: https://pypi.python.org/pypi/pyotp
.. image:: https://img.shields.io/pypi/l/pyotp.svg
        :target: https://pypi.python.org/pypi/pyotp
.. image:: https://readthedocs.org/projects/pyotp/badge/?version=latest
        :target: https://pyotp.readthedocs.io/
