#!/usr/bin/env python

import base64
import datetime
import hashlib
import os
import sys
import time
import unittest
from typing import ClassVar
from unittest.mock import patch
from urllib.parse import parse_qsl, urlparse
from warnings import warn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
import pyotp


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
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival", initial_count=12)
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "counter": "12"})
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival", issuer="FooCorp!")
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/FooCorp%21:mark%40percival")
        self.assertEqual(
            dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "counter": "0", "issuer": "FooCorp!"}
        )
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

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
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        hotp = pyotp.HOTP(key, digits=8, name="baco@peperina", issuer="Foo Corp", initial_count=10)
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "hotp")
        self.assertEqual(url.path, "/Foo%20Corp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "counter": "10", "issuer": "Foo Corp", "digits": "8"},
        )
        self.assertEqual(hotp.provisioning_uri(), pyotp.parse_uri(hotp.provisioning_uri()).provisioning_uri())

        # initial_count=0 must be respected even though 0 is falsy
        hotp = pyotp.HOTP("wrn3pqx5uqxqvnqr", name="mark@percival", initial_count=7)
        url = urlparse(hotp.provisioning_uri(initial_count=0))
        self.assertEqual(dict(parse_qsl(url.query))["counter"], "0")

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
    RFC_VALUES: ClassVar[dict] = {
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
            totp = pyotp.TOTP(base64.b32encode(secret), 8, digest)
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
        with patch("pyotp.totp.time.time", return_value=1297553958):
            self.assertEqual(totp.now(), "102705")

    def test_validate_totp(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr")
        with patch("pyotp.totp.time.time", return_value=1297553958):
            self.assertTrue(totp.verify("102705"))
            self.assertTrue(totp.verify("102705"))
        with patch("pyotp.totp.time.time", return_value=1297553958 + 30):
            self.assertFalse(totp.verify("102705"))

    def test_input_before_epoch(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        for timestamp in (-30, -29.5, -1, -0.1):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(ValueError):
                    totp.at(timestamp)

    def test_validate_totp_with_digit_length(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        with patch("pyotp.totp.time.time", return_value=1111111111):
            self.assertTrue(totp.verify("050471"))
        with patch("pyotp.totp.time.time", return_value=1297553958 + 30):
            self.assertFalse(totp.verify("050471"))

    def test_provisioning_uri(self):
        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr", name="mark@percival")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr"})
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

        totp = pyotp.TOTP("wrn3pqx5uqxqvnqr", name="mark@percival", issuer="FooCorp!")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp%21:mark%40percival")
        self.assertEqual(dict(parse_qsl(url.query)), {"secret": "wrn3pqx5uqxqvnqr", "issuer": "FooCorp!"})
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

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
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

        totp = pyotp.TOTP(key, digits=8, interval=60, name="baco@peperina", issuer="FooCorp")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "issuer": "FooCorp", "digits": "8", "period": "60"},
        )
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

        totp = pyotp.TOTP(key, digits=8, name="baco@peperina", issuer="FooCorp")
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, "otpauth")
        self.assertEqual(url.netloc, "totp")
        self.assertEqual(url.path, "/FooCorp:baco%40peperina")
        self.assertEqual(
            dict(parse_qsl(url.query)),
            {"secret": "c7uxuqhgflpw7oruedmglbrk7u6242vb", "issuer": "FooCorp", "digits": "8"},
        )
        self.assertEqual(totp.provisioning_uri(), pyotp.parse_uri(totp.provisioning_uri()).provisioning_uri())

    def test_provisioning_uri_parameter_types(self):
        for otp_type in (pyotp.TOTP, pyotp.HOTP):
            with self.subTest(otp_type=otp_type):
                otp = otp_type("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
                with self.assertRaises(TypeError):
                    otp.provisioning_uri(image=123)
                with self.assertRaises(ValueError):
                    otp.provisioning_uri(image="not-a-url")

    def test_random_key_generation(self):
        self.assertEqual(len(pyotp.random_base32()), 32)
        self.assertEqual(len(pyotp.random_base32(length=34)), 34)
        self.assertEqual(len(pyotp.random_hex()), 40)
        self.assertEqual(len(pyotp.random_hex(length=42)), 42)
        with self.assertRaises(ValueError):
            pyotp.random_base32(length=31)
        with self.assertRaises(ValueError):
            pyotp.random_hex(length=39)


@unittest.skipUnless(hasattr(time, "tzset"), "Local timezone tests require time.tzset()")
class TOTPTimezones(unittest.TestCase):
    def setUp(self):
        self.original_tz = os.environ.get("TZ")
        self.addCleanup(self.restore_timezone)

    def restore_timezone(self):
        if self.original_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self.original_tz
        time.tzset()

    def test_repeated_local_times(self):
        # POSIX rules keep these tests independent of the installed timezone database.
        transitions = (
            ("GMT0BST,M3.5.0/1,M10.5.0/2", "2026-10-25T00:30:00+00:00", "2026-10-25T01:30:00+00:00"),
            ("EST5EDT,M3.2.0/2,M11.1.0/2", "2026-11-01T05:30:00+00:00", "2026-11-01T06:30:00+00:00"),
            ("LHST-10:30LHDT-11,M10.1.0/2,M4.1.0/2", "2026-04-04T14:45:00+00:00", "2026-04-04T15:15:00+00:00"),
        )
        for timezone, first, second in transitions:
            os.environ["TZ"] = timezone
            time.tzset()
            timestamps = [int(datetime.datetime.fromisoformat(value).timestamp()) for value in (first, second)]
            local_times = [datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).astimezone() for ts in timestamps]
            self.assertEqual(local_times[0].replace(tzinfo=None), local_times[1].replace(tzinfo=None))
            self.assertNotEqual(local_times[0].utcoffset(), local_times[1].utcoffset())
            for fold, timestamp in enumerate(timestamps):
                for otp_type in (pyotp.TOTP, pyotp.contrib.Steam):
                    for interval in (30, 60) if otp_type is pyotp.TOTP else (30,):
                        totp = otp_type("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", interval=interval)
                        for delta in (-1, 0, 1):
                            with self.subTest(
                                timezone=timezone, fold=fold, otp=otp_type, interval=interval, delta=delta
                            ):
                                ts = timestamp + delta
                                counter = ts // interval
                                expected = totp.generate_otp(counter)
                                aware = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).astimezone()
                                naive = aware.replace(tzinfo=None, fold=fold)
                                for for_time in (ts, ts + 0.5, naive, aware):
                                    self.assertEqual(totp.timecode(for_time), counter)
                                    self.assertEqual(totp.at(for_time), expected)
                                    self.assertTrue(totp.verify(expected, for_time))
                                    self.assertEqual(totp.verify_and_get_timecode(expected, for_time), counter)
                                    for offset in (-1, 1):
                                        adjacent = totp.generate_otp(counter + offset)
                                        self.assertEqual(totp.at(for_time, offset), adjacent)
                                        self.assertTrue(totp.verify(adjacent, for_time, valid_window=1))
                                        self.assertEqual(
                                            totp.verify_and_get_timecode(adjacent, for_time, valid_window=1),
                                            counter + offset,
                                        )
                                other = totp.generate_otp((timestamps[1 - fold] + delta) // interval)
                                self.assertFalse(totp.verify(other, naive, valid_window=1))
                                self.assertIs(totp.verify_and_get_timecode(other, naive, valid_window=1), False)
                                with patch("pyotp.totp.time.time", return_value=ts):
                                    self.assertEqual(totp.now(), expected)
                                    self.assertTrue(totp.verify(expected))
                                    self.assertEqual(totp.verify_and_get_timecode(expected), counter)

    def test_naive_fractional_seconds(self):
        os.environ["TZ"] = "UTC0"
        time.tzset()
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        for for_time, counter in TOTPTimecode.FRACTIONAL_SECONDS:
            with self.subTest(for_time=for_time):
                self.assertEqual(totp.timecode(for_time.replace(tzinfo=None)), counter)

    def test_naive_time_range(self):
        os.environ["TZ"] = "UTC0"
        time.tzset()
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc).replace(tzinfo=None)
        self.assertEqual(totp.timecode(epoch), 0)
        self.assertEqual(totp.timecode(datetime.datetime.max), 8446743359)
        for for_time in (datetime.datetime.min, epoch - datetime.timedelta(microseconds=1)):
            with self.subTest(for_time=for_time):
                with self.assertRaisesRegex(ValueError, "for_time must be"):
                    totp.timecode(for_time)
                with self.assertRaises(ValueError):
                    totp.at(for_time)
                with self.assertRaises(ValueError):
                    totp.verify("invalid", for_time=for_time)
                with self.assertRaises(ValueError):
                    totp.verify_and_get_timecode("invalid", for_time=for_time)


class TOTPTimecode(unittest.TestCase):
    FRACTIONAL_SECONDS = (
        (datetime.datetime(1970, 1, 1, 0, 0, 29, 999999, tzinfo=datetime.timezone.utc), 0),
        (datetime.datetime(1970, 1, 1, 0, 0, 30, tzinfo=datetime.timezone.utc), 1),
        (datetime.datetime(2600, 1, 1, 0, 0, 29, 999999, tzinfo=datetime.timezone.utc), 662696640),
    )

    def test_aware_fractional_seconds(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        for for_time, counter in self.FRACTIONAL_SECONDS:
            for timezone in (datetime.timezone.utc, datetime.timezone(datetime.timedelta(hours=5, minutes=30))):
                aware = for_time.astimezone(timezone)
                with self.subTest(for_time=aware):
                    self.assertEqual(totp.timecode(aware), counter)

    def test_numeric_timestamps(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        cases = (
            (0, 0),
            (29.999999, 0),
            (30.0, 1),
            (59.999999, 1),
            (60, 2),
            (253402300799, 8446743359),
            (253402300799.5, 8446743359),
        )
        for timestamp, counter in cases:
            with self.subTest(timestamp=timestamp):
                self.assertEqual(totp.timecode(timestamp), counter)
                code = totp.generate_otp(counter)
                self.assertEqual(totp.at(timestamp), code)
                self.assertTrue(totp.verify(code, for_time=timestamp))
                matched = totp.verify_and_get_timecode(code, for_time=timestamp)
                self.assertIsNot(matched, False)
                self.assertEqual(matched, counter)

    def test_timestamps_outside_datetime_range(self):
        for timestamp in (-30.5, -29.5, -1, -0.1, 253402300800, 253402300800.0, 10**12):
            self.assert_time_out_of_range(timestamp)

    def test_nonfinite_timestamps(self):
        for timestamp in (float("nan"), float("inf"), float("-inf")):
            self.assert_time_out_of_range(timestamp)

    def test_current_time_outside_range(self):
        for otp_type in (pyotp.TOTP, pyotp.contrib.Steam):
            totp = otp_type("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            for timestamp in (-0.1, 253402300800):
                with self.subTest(otp_type=otp_type, timestamp=timestamp):
                    with patch("pyotp.totp.time.time", return_value=timestamp):
                        with self.assertRaisesRegex(ValueError, "for_time must be"):
                            totp.now()
                        with self.assertRaises(ValueError):
                            totp.verify("invalid")
                        with self.assertRaises(ValueError):
                            totp.verify_and_get_timecode("invalid")

    def test_datetimes_outside_range(self):
        cases = (
            datetime.datetime.min,
            datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
            datetime.datetime(1969, 12, 31, 23, 59, 59, 999999, tzinfo=datetime.timezone.utc),
            datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone(datetime.timedelta(hours=1))),
            datetime.datetime.max.replace(tzinfo=datetime.timezone(datetime.timedelta(hours=-1))),
        )
        for for_time in cases:
            self.assert_time_out_of_range(for_time)

    def test_datetime_range_boundaries(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        cases = (
            (datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc), 0),
            (datetime.datetime(1969, 12, 31, 23, tzinfo=datetime.timezone(datetime.timedelta(hours=-1))), 0),
            (datetime.datetime.max.replace(tzinfo=datetime.timezone.utc), 8446743359),
        )
        for for_time, counter in cases:
            with self.subTest(for_time=for_time):
                code = totp.generate_otp(counter)
                self.assertEqual(totp.timecode(for_time), counter)
                self.assertEqual(totp.at(for_time), code)
                self.assertTrue(totp.verify(code, for_time=for_time))
                self.assertEqual(totp.verify_and_get_timecode(code, for_time=for_time), counter)

    def assert_time_out_of_range(self, for_time):
        for otp_type in (pyotp.TOTP, pyotp.contrib.Steam):
            totp = otp_type("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            calls = (
                (totp.timecode, (for_time,)),
                (totp.at, (for_time,)),
                (totp.verify, ("invalid", for_time)),
                (totp.verify_and_get_timecode, ("invalid", for_time)),
            )
            for method, args in calls:
                with self.subTest(otp_type=otp_type, method=method.__name__, for_time=for_time):
                    with self.assertRaisesRegex(ValueError, "for_time must be"):
                        method(*args)

    def test_verification_normalizes_time_once(self):
        totp = pyotp.TOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        timestamp = 200.5
        counter = 6
        code = totp.generate_otp(counter + 2)
        for verify in (totp.verify, totp.verify_and_get_timecode):
            for candidate in (code, "invalid"):
                with self.subTest(method=verify.__name__, candidate=candidate):
                    with patch.object(totp, "timecode", wraps=totp.timecode) as normalize:
                        result = verify(candidate, for_time=timestamp, valid_window=2)
                        normalize.assert_called_once_with(timestamp)
                    if candidate == code:
                        self.assertTrue(result)
                    else:
                        self.assertIs(result, False)


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
        with patch("pyotp.totp.time.time", return_value=1662883100):
            self.assertTrue(steam.verify("N3G63"))
        with patch("pyotp.totp.time.time", return_value=1662883100 + 30):
            self.assertFalse(steam.verify("N3G63"))

        with patch("pyotp.totp.time.time", return_value=946681223):
            self.assertTrue(steam.verify("7VP3X"))
        with patch("pyotp.totp.time.time", return_value=946681223 + 30):
            self.assertFalse(steam.verify("7VP3X"))

        steam = pyotp.contrib.Steam("FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW")
        with patch("pyotp.totp.time.time", return_value=1662884261):
            self.assertTrue(steam.verify("V6WKJ"))
        with patch("pyotp.totp.time.time", return_value=1662884261 + 30):
            self.assertFalse(steam.verify("V6WKJ"))

        with patch("pyotp.totp.time.time", return_value=946681223):
            self.assertTrue(steam.verify("4MK54"))
        with patch("pyotp.totp.time.time", return_value=946681223 + 30):
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


class GetTimeCodeTest(unittest.TestCase):
    def test_timecode(self):
        totp = pyotp.TOTP("ABCDEFGH")
        self.assertEqual(totp.verify_and_get_timecode("451564", 200, 1), 5)
        self.assertEqual(totp.verify_and_get_timecode("028307", 200, 1), 6)
        self.assertEqual(totp.verify_and_get_timecode("681610", 200, 1), 7)
        self.assertFalse(totp.verify_and_get_timecode("195979", 200, 1))


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
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "734055")
        self.assertEqual(otp.at(30), "662488")
        self.assertEqual(otp.at(60), "289363")
        self.assertEqual(otp.provisioning_uri(), "otpauth://totp/Secret?secret=GEZDGNBV")
        self.assertEqual(otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://totp/i:n?secret=GEZDGNBV&issuer=i")

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1&period=60")
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(30), "734055")
        self.assertEqual(otp.at(60), "662488")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://totp/i:n?secret=GEZDGNBV&issuer=i&period=60"
        )

        otp = pyotp.parse_uri("otpauth://hotp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1")
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "734055")
        self.assertEqual(otp.at(1), "662488")
        self.assertEqual(otp.at(2), "289363")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://hotp/i:n?secret=GEZDGNBV&issuer=i&counter=0"
        )

        otp = pyotp.parse_uri("otpauth://hotp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA1&counter=1")
        self.assertEqual(hashlib.sha1, otp.digest)
        self.assertEqual(otp.at(0), "662488")
        self.assertEqual(otp.at(1), "289363")
        self.assertEqual(
            otp.provisioning_uri(name="n", issuer_name="i"), "otpauth://hotp/i:n?secret=GEZDGNBV&issuer=i&counter=1"
        )

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA256")
        self.assertEqual(hashlib.sha256, otp.digest)
        self.assertEqual(otp.at(0), "918961")
        self.assertEqual(otp.at(9000), "934470")

        otp = pyotp.parse_uri("otpauth://totp?algorithm=SHA1&secret=GEZDGNBV&algorithm=SHA512")
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
        self.assertEqual(type(otp), pyotp.contrib.Steam)
        self.assertEqual(otp.at(0), "C5V56")
        self.assertEqual(otp.at(30), "QJY8Y")
        self.assertEqual(otp.at(60), "R3WQY")
        self.assertEqual(otp.at(90), "JG3T3")

        # period and digits should be ignored
        otp = pyotp.parse_uri(
            "otpauth://totp/Steam:?secret=FMXNK4QEGKVPULRTADY6JIDK5VHUBGZW&period=15&digits=7&encoder=steam"
        )
        self.assertEqual(type(otp), pyotp.contrib.Steam)
        self.assertEqual(otp.at(0), "C5V56")
        self.assertEqual(otp.at(30), "QJY8Y")
        self.assertEqual(otp.at(60), "R3WQY")
        self.assertEqual(otp.at(90), "JG3T3")

        pyotp.parse_uri("otpauth://totp?secret=abc&image=foobar")

    def test_parse_encoded_colon_in_label(self):
        # Regression test for issue #174: an encoded colon (%3A) inside the
        # issuer or account name must not be treated as the issuer:account
        # separator. The label issuer and the query issuer should still match.
        otp = pyotp.parse_uri(
            "otpauth://totp/Text%3A%20More%20Text:Secret?secret=FFFFFFFAAAAAABBBBBBB&issuer=Text%3A%20More%20Text"
        )
        self.assertEqual(otp.name, "Secret")
        self.assertEqual(otp.issuer, "Text: More Text")

        # An encoded colon in the account name (no issuer) is kept intact.
        otp = pyotp.parse_uri("otpauth://totp/a%3Ab?secret=GEZDGNBV")
        self.assertEqual(otp.name, "a:b")
        self.assertIsNone(otp.issuer)

        # Round-trip: building the URI and parsing it back preserves both parts.
        source = pyotp.TOTP("FFFFFFFAAAAAABBBBBBB", name="Secret", issuer="Text: More Text")
        roundtrip = pyotp.parse_uri(source.provisioning_uri())
        self.assertEqual(roundtrip.name, "Secret")
        self.assertEqual(roundtrip.issuer, "Text: More Text")

        # A percent-encoded space in a plain issuer (no colon) still decodes.
        otp = pyotp.parse_uri("otpauth://totp/Big%20Corp:bob?secret=GEZDGNBV&issuer=Big%20Corp")
        self.assertEqual(otp.name, "bob")
        self.assertEqual(otp.issuer, "Big Corp")


if __name__ == "__main__":
    unittest.main()
