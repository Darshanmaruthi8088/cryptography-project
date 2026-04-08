"""Input validation utilities."""

from pathlib import Path

from config import (
    ALLOWED_IMAGE_EXTENSIONS,
    ALLOWED_SCAN_EXTENSIONS,
    MAX_TEXT_LENGTH,
)


class ValidationError(ValueError):
    """Raised when user input fails validation."""


def validate_non_empty_text(value: str, field_name: str = "text") -> str:
    if value is None:
        raise ValidationError(f"{field_name} is required.")
    cleaned = value.strip()
    if not cleaned:
        raise ValidationError(f"{field_name} cannot be empty.")
    if len(cleaned) > MAX_TEXT_LENGTH:
        raise ValidationError(
            f"{field_name} is too long. Maximum allowed is {MAX_TEXT_LENGTH} characters."
        )
    return cleaned


def validate_hex_string(value: str, field_name: str = "cipher") -> str:
    cleaned = validate_non_empty_text(value, field_name)
    try:
        bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValidationError(f"{field_name} must be valid hexadecimal.") from exc
    return cleaned


def validate_nonce(value: str) -> str:
    cleaned = validate_non_empty_text(value, "nonce")
    if len(cleaned) < 4:
        raise ValidationError("nonce is too short.")
    return cleaned


def validate_uploaded_extension(filename: str, mode: str) -> None:
    ext = Path(filename or "").suffix.lower()
    if mode == "image" and ext not in ALLOWED_IMAGE_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_IMAGE_EXTENSIONS))
        raise ValidationError(f"Unsupported image type. Allowed: {allowed}")
    if mode == "scan" and ext not in ALLOWED_SCAN_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_SCAN_EXTENSIONS))
        raise ValidationError(f"Unsupported scan file type. Allowed: {allowed}")


def validate_positive_int(value, field_name: str, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field_name} must be a valid integer.") from exc
    if not minimum <= number <= maximum:
        raise ValidationError(f"{field_name} must be between {minimum} and {maximum}.")
    return number

