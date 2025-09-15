#!/usr/bin/env python

import base64
import contextlib
import datetime
import hashlib
import os
import sys
import typing
import unittest.mock
from urllib.parse import parse_qsl, urlparse
from warnings import warn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
import pyotp  # noqa


class HOTPExampleValuesFromTheRFC(unittest.TestCase):
    def test_match_rfc(self):
        # 12345678901234567890 in Bas32
        # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        hotp = pyotp.HOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.assertEqual(hotp.at(0), "755224")
        self.assertEqual(hotp.at(1), "287082")
        self.assertEqual(hotp.at(2), "359152")
        self.assertEqual(hotp.at(3), "969429")
        self.assertEqual(hotp.at(4), "338314")
        self.assertEqual(hotp.at(5), "254676")
        self.assertEqual(hotp.at(6), "287922")
        self.assertEqual(hotp.at(7), "162583")
        self.assertEqual(hotp.at(8), "399871")
        self.assertEqual(hotp.at(9), "520489")

    def test_invalid_input(self):
        hotp = pyotp.HOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        with self.assertRaises(ValueError):
            hotp.at(-1)

    def test_verify_otp_reuse(self):
        hotp = pyotp.HOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.assertTrue(hotp.verify("520489", 9))
        self.assertFalse(hotp.verify("520489", 10))
        self.assertFalse(hotp.verify("520489", 10))

    def test_provisioning_uri(self):
        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival")

        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "counter": "0"})
        parsed_otp = pyotp.parse_uri(hotp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.HOTP)
        self.assertEqual(hotp.provisioning_uri(), parsed_otp.provisioning_uri())

        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival", initial_count=12)
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "counter": "12"})
        parsed_otp = pyotp.parse_uri(hotp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.HOTP)
        self.assertEqual(hotp.provisioning_uri(), parsed_otp.provisioning_uri())

        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival", issuer="FooCorp!")
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/FooCorp%21:mark%40percival")
        self.assertEqual(
            dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "counter": "0", "issuer": "FooCorp!"}
        )
        parsed_otp = pyotp.parse_uri(hotp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.HOTP)
        self.assertEqual(hotp.provisioning_uri(), parsed_otp.provisioning_uri())

        key = "c7uxuqhgflpw7oruedmglbrk7u6242vb"
        hotp = pyotp.HOTP(key, digits=8, digest=hashlib.sha256, name="baco@peperina", issuer="FooCorp")
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {
                "secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb",
                "counter": "0",
                "issuer": "FooCorp",
                "digits": "8",
                "algorithm": "SHA256",
            },
        )
        parsed_otp = pyotp.parse_uri(hotp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.HOTP)
        self.assertEqual(hotp.provisioning_uri(), parsed_otp.provisioning_uri())

        hotp = pyotp.HOTP(key, digits=8, name="baco@peperina", issuer="Foo Corp", initial_count=10)
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/Foo%20Corp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "counter": "10", "issuer": "Foo Corp", "digits": "8"},
        )
        parsed_otp = pyotp.parse_uri(hotp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.HOTP)
        self.assertEqual(hotp.provisioning_uri(), parsed_otp.provisioning_uri())

        code = pyotp.totp.TOTP("S46SQCPPTCNPROMHWYBDCTBZXV")
        self.assertEqual(code.provisioning_uri(), "otpauth://totp/Secret?secret=S46SQCPPTCNPROMHWYBDCTBZXV")
        code.verify("123456")
        self.assertEqual(code.provisioning_uri(), "otpauth://totp/Secret?secret=S46SQCPPTCNPROMHWYBDCTBZXV")

    def test_other_secret(self):
        hotp = pyotp.HOTP("N3OVNIBRERIO5OHGVCMDGS4V4RJ3AUZOUN34J6FRM4P6JIFCG3ZA")
        self.assertEqual(hotp.at(0), "737863")
        self.assertEqual(hotp.at(1), "390601")
        self.assertEqual(hotp.at(2), "363354")
        self.assertEqual(hotp.at(3), "936780")
        self.assertEqual(hotp.at(4), "654019")


class TOTPExampleValuesFromTheRFC(unittest.TestCase):
    RFC_VALUES = {
        (hashlib.sha1, b"12345678901234567890"): (
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ),
        (hashlib.sha256, b"12345678901234567890123456789012"): (
            (59, 46119246),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ),
        (hashlib.sha512, b"1234567890123456789012345678901234567890123456789012345678901234"): (
            (59, 90693936),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ),
    }

    def test_match_rfc(self):
        for digest, secret in self.RFC_VALUES:
            totp = pyotp.TOTP(base64.b32encode(secret).decode(), 8, digest)
            for utime, code in self.RFC_VALUES[(digest, secret)]:
                if utime > sys.maxsize:
                    warn(
                        "32-bit platforms use native functions to handle timestamps, so they fail this test"
                        + " (and will fail after 19 January 2038)"
                    )
                    continue
                value = totp.at(utime)
                msg = "%s != %s (%s, time=%d)"
                msg %= (value, code, digest().name, utime)
                self.assertEqual(value, str(code), msg)

    def test_match_rfc_digit_length(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        self.assertEqual(totp.at(1111111111), "050471")
        self.assertEqual(totp.at(1234567890), "005924")
        self.assertEqual(totp.at(2000000000), "279037")

    def test_match_google_authenticator_output(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr")
        with timecop(1297553958):
            self.assertEqual(totp.now(), "102705")

    def test_validate_totp(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr")
        with timecop(1297553958):
            self.assertTrue(totp.verify("102705"))
            self.assertTrue(totp.verify("102705"))
        with timecop(1297553958 + 30):
            self.assertFalse(totp.verify("102705"))

    def test_return_timecode_on_verify(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr")
        with timecop(1297553958):
            timecode1 = totp.verify("102705", valid_window=1, return_timecode=True)
            self.assertTrue(isinstance(timecode1, int))
        with timecop(1297553958 + 30):
            timecode2 = totp.verify("102705", valid_window=1, return_timecode=True)
        self.assertEqual(timecode1, timecode2)

        with timecop(1297553958 + 60):
            timecode3 = totp.verify("102705", valid_window=1, return_timecode=True)
            self.assertFalse(timecode3)

    def test_input_before_epoch(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        # -1 and -29.5 round down to 0 (epoch)
        self.assertEqual(totp.at(-1), "755224")
        self.assertEqual(totp.at(-29.5), "755224")
        with self.assertRaises(ValueError):
            totp.at(-30)

    def test_validate_totp_with_digit_length(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        with timecop(1111111111):
            self.assertTrue(totp.verify("050471"))
        with timecop(1297553958 + 30):
            self.assertFalse(totp.verify("050471"))

    def test_provisioning_uri(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr", name="mark@percival")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr"})
        parsed_otp = pyotp.parse_uri(totp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.TOTP)
        self.assertEqual(totp.provisioning_uri(), parsed_otp.provisioning_uri())

        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr", name="mark@percival", issuer="FooCorp!")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp%21:mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "issuer": "FooCorp!"})
        parsed_otp = pyotp.parse_uri(totp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.TOTP)
        self.assertEqual(totp.provisioning_uri(), parsed_otp.provisioning_uri())

        key = "c7uxuqhgflpw7oruedmglbrk7u6242vb"
        totp = pyotp.TOTP(key, digits=8, interval=60, digest=hashlib.sha256, name="baco@peperina", issuer="FooCorp")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {
                "secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb",
                "issuer": "FooCorp",
                "digits": "8",
                "period": "60",
                "algorithm": "SHA256",
            },
        )
        parsed_otp = pyotp.parse_uri(totp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.TOTP)
        self.assertEqual(totp.provisioning_uri(), parsed_otp.provisioning_uri())

        totp = pyotp.TOTP(key, digits=8, interval=60, name="baco@peperina", issuer="FooCorp")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "issuer": "FooCorp", "digits": "8", "period": "60"},
        )
        parsed_otp = pyotp.parse_uri(totp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.TOTP)
        self.assertEqual(totp.provisioning_uri(), parsed_otp.provisioning_uri())

        totp = pyotp.TOTP(key, digits=8, name="baco@peperina", issuer="FooCorp")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "issuer": "FooCorp", "digits": "8"},
        )
        parsed_otp = pyotp.parse_uri(totp.provisioning_uri())
        assert isinstance(parsed_otp, pyotp.TOTP)
        self.assertEqual(totp.provisioning_uri(), parsed_otp.provisioning_uri())

    def test_random_key_generation(self):
        self.assertEqual(len(pyotp.random_base32()), 32)
        self.assertEqual(len(pyotp.random_base32(length=34)), 34)
        self.assertEqual(len(pyotp.random_hex()), 40)
        self.assertEqual(len(pyotp.random_hex(length=42)), 42)
        with self.assertRaises(ValueError):
            pyotp.random_base32(length=31)
        with self.assertRaises(ValueError):
            pyotp.random_hex(length=39)


class SteamTOTP(unittest.TestCase):
    def test_match_examples(self):
        steam = pyotp.contrib.Steam("BASE32SECRET3232")

        self.assertEqual(steam.at(0), "2TC8B")
        self.assertEqual(steam.at(30), "YKKK4")
        self.assertEqual(steam.at(60), "M4HQB")
        self.assertEqual(steam.at(90), "DTVB3")

        steam = pyotp.contrib.Steam("FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW")

        self.assertEqual(steam.at(0), "C5V56")
        self.assertEqual(steam.at(30), "QJY8Y")
        self.assertEqual(steam.at(60), "R3WQY")
        self.assertEqual(steam.at(90), "JG3T3")

    def test_verify(self):
        steam = pyotp.contrib.Steam("BASE32SECRET3232")
        with timecop(1662883100):
            self.assertTrue(steam.verify("N3G63"))
        with timecop(1662883100 + 30):
            self.assertFalse(steam.verify("N3G63"))

        with timecop(946681223):
            self.assertTrue(steam.verify("7VP3X"))
        with timecop(946681223 + 30):
            self.assertFalse(steam.verify("7VP3X"))

        steam = pyotp.contrib.Steam("FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW")
        with timecop(1662884261):
            self.assertTrue(steam.verify("V6WKJ"))
        with timecop(1662884261 + 30):
            self.assertFalse(steam.verify("V6WKJ"))

        with timecop(946681223):
            self.assertTrue(steam.verify("4MK54"))
        with timecop(946681223 + 30):
            self.assertFalse(steam.verify("4MK54"))


class CompareDigestTest(unittest.TestCase):
    method = staticmethod(pyotp.utils.compare_digest)

    def test_comparisons(self):
        self.assertTrue(self.method("", ""))
        self.assertTrue(self.method("a", "a"))
        self.assertTrue(self.method("a" * 1000, "a" * 1000))

        self.assertFalse(self.method("", "a"))
        self.assertFalse(self.method("a", ""))
        self.assertFalse(self.method("a" * 999 + "b", "a" * 1000))


class StringComparisonTest(CompareDigestTest):
    method = staticmethod(pyotp.utils.strings_equal)

    def test_fullwidth_input(self):
        self.assertTrue(self.method("ｘs１２３45", "xs12345"))

    def test_unicode_equal(self):
        self.assertTrue(self.method("ěšč45", "ěšč45"))


class CounterOffsetTest(unittest.TestCase):
    def test_counter_offset(self):
        totp = pyotp.TOTP("ABCDEFGH")
        self.assertEqual(totp.at(200), "028307")
        self.assertTrue(totp.at(200, 1), "681610")


class ValidWindowTest(unittest.TestCase):
    def test_valid_window(self):
        totp = pyotp.TOTP("ABCDEFGH")
        self.assertTrue(totp.verify("451564", 200, 1))
        self.assertTrue(totp.verify("028307", 200, 1))
        self.assertTrue(totp.verify("681610", 200, 1))
        self.assertFalse(totp.verify("195979", 200, 1))


class DigestFunctionTest(unittest.TestCase):
    def test_md5(self):
        with self.assertRaises(ValueError) as cm:
            pyotp.OTP(s="secret", digest=hashlib.md5)
        self.assertEqual(
            "selected digest function must generate digest size greater than or equals to 18 bytes", str(cm.exception)
        )

    def test_shake128(self):
        with self.assertRaises(ValueError) as cm:
            pyotp.OTP(s="secret", digest=hashlib.shake_128)
        self.assertEqual(
            "selected digest function must generate digest size greater than or equals to 18 bytes", str(cm.exception)
        )


class ParseUriTest(unittest.TestCase):
    def test_invalids(self):
        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("http://hello.com")
        self.assertEqual("Not an otpauth URI", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://totp")
        self.assertEqual("No secret found in URI", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://derp?secret=foo")
        self.assertEqual("Not a supported OTP type", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://totp?digits=-1")
        self.assertEqual("Digits may only be 6, 7, or 8", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://totp/SomeIssuer:?issuer=AnotherIssuer")
        self.assertEqual("If issuer is specified in both label and parameters, it should be equal.", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri("otpauth://totp?algorithm=aes")
        self.assertEqual("Invalid value for algorithm, must be SHA1, SHA256 or SHA512", str(cm.exception))

    def test_parse_steam(self):
        otp = pyotp.parse_uri("otpauth://totp/Steam:?secret=SOME_SECRET&encoder=steam")
        self.assertEqual(type(otp), pyotp.contrib.Steam)

        otp = pyotp.parse_uri("otpauth://totp/Steam:?secret=SOME_SECRET")
        self.assertNotEqual(type(otp), pyotp.contrib.Steam)

    @unittest.skipIf(sys.version_info < (3, 6), "Skipping test that requires deterministic dict key enumeration")
    def test_algorithms(self):
        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1")
        assert isinstance(otp, pyotp.TOTP)
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "734055")
        self.assertEqual(otp.at(30), "662488")
        self.assertEqual(otp.at(60), "289363")
        self.assertEqual(otp.provisioning_uri(), "otpauth://totp/Secret?secret=GEZDGNBV")
        self.assertEqual(otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://totp/i:n?secret=GEZDGNBV&issuer=i")

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1&period=60")
        assert isinstance(otp, pyotp.TOTP)
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(30), "734055")
        self.assertEqual(otp.at(60), "662488")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://totp/i:n?secret=GEZDGNBV&issuer=i&period=60"
        )

        otp = pyotp.parse_uri("otpauth://hotp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1")
        assert isinstance(otp, pyotp.HOTP)
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "734055")
        self.assertEqual(otp.at(1), "662488")
        self.assertEqual(otp.at(2), "289363")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://hotp/i:n?secret=GEZDGNBV&issuer=i&counter=0"
        )

        otp = pyotp.parse_uri("otpauth://hotp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1&counter=1")
        assert isinstance(otp, pyotp.HOTP)
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "662488")
        self.assertEqual(otp.at(1), "289363")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://hotp/i:n?secret=GEZDGNBV&issuer=i&counter=1"
        )

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA256")
        assert isinstance(otp, pyotp.TOTP)
        self.assertEqual(hashlib.sha256, otp.digest)
        self.assertEqual(otp.at(0), "918961")
        self.assertEqual(otp.at(9000), "934470")

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA512")
        assert isinstance(otp, pyotp.TOTP)
        self.assertEqual(hashlib.sha512, otp.digest)
        self.assertEqual(otp.at(0), "816660")
        self.assertEqual(otp.at(9000), "524153")

        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i", image="https://test.net/test.png"),
            "otpauth://totp/i:n?secret=GEZDGNBV&issuer=i&algorithm=SHA512&image=https%3A%2F%2Ftest.net%2Ftest.png",
        )
        with self.assertRaises(ValueError):
            otp.provisioning_uri(name="n", issuer_name="i", image="nourl")

        otp = pyotp.parse_uri(otp.provisioning_uri(name="n", issuer_name="i", image="https://test.net/test.png"))
        self.assertEqual(hashlib.sha512, otp.digest)

        otp = pyotp.parse_uri("otpauth://totp/Steam:?secret=FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW&encoder=steam")
        assert isinstance(otp, pyotp.contrib.Steam)
        self.assertEqual(otp.at(0), "C5V56")
        self.assertEqual(otp.at(30), "QJY8Y")
        self.assertEqual(otp.at(60), "R3WQY")
        self.assertEqual(otp.at(90), "JG3T3")

        # period and digits should be ignored
        otp = pyotp.parse_uri(
            "otpauth://totp/Steam:?secret=FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW&period=15&digits=7&encoder=steam"
        )
        assert isinstance(otp, pyotp.contrib.Steam)
        self.assertEqual(otp.at(0), "C5V56")
        self.assertEqual(otp.at(30), "QJY8Y")
        self.assertEqual(otp.at(60), "R3WQY")
        self.assertEqual(otp.at(90), "JG3T3")

        pyotp.parse_uri("otpauth://totp?secret=abc&image=foobar")


@contextlib.contextmanager
def timecop(freeze_timestamp: int) -> typing.Generator[None, None, None]:
    class FrozenDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz: datetime.tzinfo | None = None) -> "FrozenDateTime":
            return cls.fromtimestamp(freeze_timestamp, tz=tz)

    with unittest.mock.patch("datetime.datetime", FrozenDateTime):
        yield


if __name__ == "__main__":
    unittest.main()
