class PyOTPError(Exception):
    """Base class for PyOTP-specific errors."""


class OTPVerificationError(PyOTPError):
    """Raised when an OTP does not match any permitted counter."""
