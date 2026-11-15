Changes for v2.12.0 (2026-11-15)
================================

-  Require 112-bit OTP secrets and update illustrative examples (#205)

-  Limit TOTP intervals to 120 seconds (#206)

-  Update recommendations for authentication best practices

-  Update required minimum Python version to 3.10

Changes for v2.11.2 (2026-11-14)
================================

-  Validate OTP configuration and URI parameters (#203)

-  Harden OTP verification APIs and document replay prevention (#202)

Changes for v2.11.1 (2026-11-14)
================================

-  Fix PyPI README markup and validate distributions before release
   (#200)

Changes for v2.11.0 (2026-11-14)
================================

-  Fix DST rollbacks and normalize TOTP timestamp inputs (#197)

-  Respect initial_count=0 in HOTP.provisioning_uri() (#190)

-  Implement verify_and_get_timecode, a method for TOTP that verifies
   and returns the matching timecode (#191)

Changes for v2.10.0 (2026-06-13)
================================

- Fix parse_uri mis-parsing of encoded colon in issuer/account name
  (#187)

- Simplified and improved generate_otp() performance in Steam class
  (#179)

- Check digest function to prevent error on OTP Generation (#170)

- Ignore non-standard otpauth parameters

- use strings as immutable default arguments (#162)

Changes for v2.9.0 (2023-07-27)
===============================

-  Add ``parse_uri()`` support for Steam TOTP (#153)

-  Test and documentation improvements

Changes for v2.8.0 (2022-12-13)
===============================

-  Modify OTP generation to run in constant time (#148)

-  Documentation improvements

-  Drop Python 3.6 support; introduce Python 3.11 support

Changes for v2.7.0 (2022-09-11)
===============================

-  Support Steam TOTP (#142)

-  Build, test, and documentation updates

Changes for v2.6.0 (2021-02-04)
===============================

-  Raise default and minimum base32 secret length to 32, and hex secret
   length to 40 (160 bits as recommended by the RFC) (#115).

-  Fix issue where provisioning_uri would return invalid results after
   calling verify() (#115).

Changes for v2.5.1 (2021-01-29)
===============================

-  parse_uri accepts and ignores optional image parameter (#114)

Changes for v2.5.0 (2021-01-29)
===============================

-  Add optional image parameter to provisioning_uri (#113)

-  Support for 7-digit codes in ‘parse_uri’ (#111)

-  Raise default and minimum base32 secret length to 26

Changes for v2.4.1 (2020-10-16)
===============================

-  parse_uri: Fix handling of period, counter (#108)

-  Add support for timezone aware datetime as argument to
   ``TOTP.timecode()`` (#107)

Changes for v2.4.0 (2020-07-29)
===============================

-  Fix data type for at(for_time) (#85)

-  Add support for parsing provisioning URIs (#84)

-  Raise error when trying to generate secret that is too short (The
   secret must be at least 128 bits)

-  Add random_hex function (#82)

Changes for v2.3.0 (2019-07-26)
===============================

-  Fix comparison behavior on Python 2.7

Changes for v2.2.8 (2019-07-26)
===============================

-  Fix comparison of unicode chars (#78)

-  Minor documentation and test fixes

Changes for v2.2.7 (2018-11-05)
===============================

-  Have random_base32() use ‘secrets’ as rand source (#66)

-  Documentation: Add security considerations, minimal security
   checklist, other improvements

-  Update setup.py to reference correct license

Changes for v2.2.6 (2017-06-10)
===============================

-  Fix tests wrt double-quoting in provisioning URIs

Changes for v2.2.5 (2017-06-03)
===============================

-  Quote issuer QS parameter in provisioning\_uri. Fixes #47.

-  Raise an exception if a negative integer is passed to at() (#41).

-  Documentation and release infrastructure improvements.

Changes for v2.2.4 (2017-01-04)
===============================

-  Restore Python 2.6 compatibility (however, Python 2.6 is not
   supported)

-  Documentation and test improvements

-  Fix release infra script, part 2

Changes for v2.2.3 (2017-01-04)
===============================

-  Restore Python 2.6 compatibility (however, Python 2.6 is not
   supported)

-  Documentation and test improvements

-  Fix release infra script

Changes for v2.2.2 (2017-01-04)
===============================

-  Restore Python 2.6 compatibility (however, Python 2.6 is not
   supported)

-  Documentation and test improvements

Changes for v2.2.1 (2016-08-30)
===============================

-  Avoid using python-future; it has subdependencies that limit
   compatibility (#34)
-  Make test suite pass on 32-bit platforms (#30)
-  Timing attack resistance fix: don't reveal string length to attacker.
   Thanks to Eeo Jun (#28).
-  Support algorithm, digits, period parameters in provisioning\_uri.
   Thanks to Dionisio E Alonso (#33).
-  Minor style and packaging infrastructure fixes.

Changes for v2.2.0 (2016-08-30)
===============================

-  See v2.2.1

Version 2.1.0 (2016-05-02)
--------------------------
- Add extended range support to TOTP.verify. Thanks to Zeev Rotshtein (PR #19).
- Handle missing padding of encoded secret. Thanks to Kun Yan (#20).
- Miscellaneous fixes.

Version 2.0.1 (2015-09-28)
--------------------------
- Fix packaging issue in v2.0.0 that prevented installation with easy_install.

Version 2.0.0 (2015-08-22)
--------------------------
- The ``pyotp.HOTP.at()``, ``pyotp.TOTP.at()``, and
  ``pyotp.TOTP.now()`` methods now return strings instead of
  integers. Thanks to Rohan Dhaimade (PR #16).

Version 1.4.2 (2015-07-21)
--------------------------
- Begin tracking changes in change log.
- Update documentation.
- Introduce Travis CI integration.

Version 1.3.1 (2012-02-29)
--------------------------
- Initial release.
