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
- Throttle (rate limit) brute-force attacks against your application's login functionality (see RFC 4226, section 7.3
  and NIST SP 800-63B, section 3.2.2)
- When implementing a "greenfield" application, consider supporting
  `FIDO U2F <https://en.wikipedia.org/wiki/Universal_2nd_Factor>`_/`WebAuthn <https://www.w3.org/TR/webauthn/>`_ in
  addition to or instead of HOTP/TOTP. U2F uses asymmetric cryptography to avoid using a shared secret design, which
  strengthens your MFA solution against server-side attacks. Hardware U2F also sequesters the client secret in a
  dedicated single-purpose device, which strengthens your clients against client-side attacks. And by automating scoping
  of credentials to relying party IDs (application origin/domain names), U2F adds protection against phishing attacks.
  One implementation of FIDO U2F/WebAuthn is PyOTP's sister project, `PyWARP <https://github.com/pyauth/pywarp>`_.

We also recommend that implementers read and follow the following resources:

- `NIST SP 800-63 Digital Identity Guidelines <https://pages.nist.gov/800-63-4/>`_, including sections 3.1.4
  (Single-Factor OTP) and 3.1.5 (Multi-Factor OTPs), for an in-depth discussion of authentication
- The `OWASP Authentication Cheat Sheet
  <https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Authentication_Cheat_Sheet.md>`_ for a high level
  overview of authentication best practices
- The `OWASP Multifactor Authentication Cheat Sheet
  <https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Multifactor_Authentication_Cheat_Sheet.md>`_ for
  an intermediate level practical architecture guide to MFA

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

Google Authenticator Compatible
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PyOTP works with the Google Authenticator iPhone and Android app, as well as other OTP apps like Authy. PyOTP includes
the ability to generate provisioning URIs for use with the QR Code scanner built into these MFA client apps:

.. code:: python

    pyotp.totp.TOTP('JBSWY3DPEHPK3PXPJBSWY3DP').provisioning_uri(name='alice@google.com', issuer_name='Secure App')

    >>> 'otpauth://totp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=Secure%20App'

    pyotp.hotp.HOTP('JBSWY3DPEHPK3PXPJBSWY3DP').provisioning_uri(name="alice@google.com", issuer_name="Secure App", initial_count=0)

    >>> 'otpauth://hotp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=Secure%20App&counter=0'

This URL can then be rendered as a QR Code (for example, using https://github.com/soldair/node-qrcode) which can then be
scanned and added to the users list of OTP credentials.

Parsing these URLs is also supported:

.. code:: python

    pyotp.parse_uri('otpauth://totp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=Secure%20App')

    >>> <pyotp.totp.TOTP object at 0xFFFFFFFF>

    pyotp.parse_uri('otpauth://hotp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=Secure%20App&counter=0')

    >>> <pyotp.hotp.HOTP object at 0xFFFFFFFF>

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
recommended that application developers pin the package version and manage it using `uv
<https://github.com/astral-sh/uv>`_ or similar. For library developers, pinning the major version is
recommended.
