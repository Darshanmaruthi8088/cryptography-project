from __future__ import annotations

import logging
import os
import secrets
import time
from io import BytesIO
from pathlib import Path
from threading import Lock

from flask import Flask, jsonify, render_template, request, send_file, send_from_directory, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from app_logger import configure_logging
from benchmarking import run_benchmarks
from config import (
    APP_SECRET_KEY,
    DEFAULT_PBKDF2_ITERATIONS,
    LOG_FOLDER,
    MAX_CONTENT_LENGTH,
    OUTPUT_FOLDER,
    UPLOAD_FOLDER,
)
from crypto_algorithms import (
    CryptoError,
    decrypt_binary_payload,
    decrypt_message,
    encrypt_binary_payload,
    encrypt_message,
    parse_encrypted_payload,
    serialize_encrypted_payload,
)
from diffie_hellman import simulate_key_exchange
from hash_algorithms import pbkdf2_sha256, sha256_hex
from malware_scanner import scan_gif
from rate_limiter import RateLimiter
from rsa_algorithms import (
    RSAError,
    generate_rsa_keypair,
    rsa_decrypt,
    rsa_encrypt,
    rsa_sign,
    rsa_verify,
)
from steganography import StegoError, detect_steganography, extract_message, hide_message, image_capacity_chars
from validators import (
    ValidationError,
    validate_hex_string,
    validate_nonce,
    validate_non_empty_text,
    validate_positive_int,
    validate_uploaded_extension,
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SECRET_KEY"] = APP_SECRET_KEY

IN_MEMORY_DOWNLOAD_TTL_SECONDS = max(int(os.environ.get("IN_MEMORY_DOWNLOAD_TTL_SECONDS", "900")), 60)
MAX_IN_MEMORY_DOWNLOADS = max(int(os.environ.get("MAX_IN_MEMORY_DOWNLOADS", "25")), 1)

_download_cache_lock = Lock()
_download_cache: dict[str, dict[str, object]] = {}

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)
configure_logging(LOG_FOLDER)
logger = logging.getLogger(__name__)
rate_limiter = RateLimiter()


def _json_data() -> dict:
    return request.get_json(silent=True) or {}


def _save_upload(file_storage, destination_dir: Path) -> Path:
    filename = secure_filename(file_storage.filename or "upload.bin")
    if not filename:
        filename = "upload.bin"
    stamped_name = f"{int(time.time() * 1000)}_{filename}"
    path = destination_dir / stamped_name
    file_storage.save(path)
    return path


def _parse_cipher_blocks(value):
    if isinstance(value, list):
        return [int(item) for item in value]
    if isinstance(value, str):
        return [int(item.strip()) for item in value.split(",") if item.strip()]
    raise ValidationError("cipher_blocks must be a list of integers or comma-separated string.")


def _require_int(value, field_name: str) -> int:
    try:
        if value is None:
            raise ValueError
        return int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field_name} must be a valid integer.") from exc


def _download_url(filename: str) -> str:
    return url_for("download", filename=filename)


def _cleanup_download_cache(now: float | None = None) -> None:
    current_ts = now if now is not None else time.time()
    expired_tokens = [
        token
        for token, metadata in _download_cache.items()
        if float(metadata.get("expires_at", 0.0)) <= current_ts
    ]
    for token in expired_tokens:
        _download_cache.pop(token, None)

    overflow = len(_download_cache) - MAX_IN_MEMORY_DOWNLOADS
    if overflow > 0:
        oldest_tokens = sorted(
            _download_cache.items(),
            key=lambda item: float(item[1].get("created_at", current_ts)),
        )[:overflow]
        for token, _ in oldest_tokens:
            _download_cache.pop(token, None)


def _store_in_memory_download(payload_bytes: bytes, download_name: str) -> str:
    now = time.time()
    safe_download_name = secure_filename(download_name) or "download.bin"

    with _download_cache_lock:
        _cleanup_download_cache(now)
        token = secrets.token_urlsafe(18)
        while token in _download_cache:
            token = secrets.token_urlsafe(18)
        _download_cache[token] = {
            "bytes": payload_bytes,
            "download_name": safe_download_name,
            "created_at": now,
            "expires_at": now + IN_MEMORY_DOWNLOAD_TTL_SECONDS,
        }
    return token


def _resolve_in_memory_download(token: str) -> tuple[bytes, str] | None:
    with _download_cache_lock:
        _cleanup_download_cache()
        metadata = _download_cache.get(token)
        if metadata is None:
            return None
        return bytes(metadata["bytes"]), str(metadata["download_name"])


@app.before_request
def apply_rate_limit():
    if request.endpoint in {"home", "static"}:
        return None

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    key = f"{client_ip}:{request.path}"
    if rate_limiter.is_limited(key):
        return jsonify({"error": "Rate limit exceeded. Please retry after one minute."}), 429
    return None


@app.errorhandler(ValidationError)
def handle_validation_error(error: ValidationError):
    return jsonify({"error": str(error)}), 400


@app.errorhandler(CryptoError)
@app.errorhandler(StegoError)
@app.errorhandler(RSAError)
def handle_crypto_errors(error):
    return jsonify({"error": str(error)}), 400


@app.errorhandler(HTTPException)
def handle_http_exception(error: HTTPException):
    return jsonify({"error": error.description}), error.code


@app.errorhandler(Exception)
def handle_unexpected_error(error: Exception):
    logger.exception("Unexpected error: %s", error)
    return jsonify({"error": "Internal server error"}), 500


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/encrypt", methods=["POST"])
def encrypt():
    payload = _json_data()
    message = validate_non_empty_text(payload.get("message"), "message")
    password = (payload.get("password") or "").strip() or None
    demo_mode = bool(payload.get("demo_mode", False))
    iterations = validate_positive_int(
        payload.get("iterations"),
        "iterations",
        DEFAULT_PBKDF2_ITERATIONS,
        500,
        100_000,
    )

    logger.info("Encrypt request | message_length=%s demo_mode=%s", len(message), demo_mode)
    result = encrypt_message(
        message=message,
        password=password,
        demo_mode=demo_mode,
        iterations=iterations,
    )
    return jsonify(result)


@app.route("/decrypt", methods=["POST"])
def decrypt():
    payload = _json_data()
    cipher = validate_hex_string(payload.get("cipher"), "cipher")
    nonce = validate_nonce(payload.get("nonce"))
    salt = (payload.get("salt") or "").strip() or None
    if salt:
        salt = validate_hex_string(salt, "salt")
    password = (payload.get("password") or "").strip() or None
    demo_mode = bool(payload.get("demo_mode", False))
    iterations = validate_positive_int(
        payload.get("iterations"),
        "iterations",
        DEFAULT_PBKDF2_ITERATIONS,
        500,
        100_000,
    )

    logger.info("Decrypt request | cipher_bytes=%s has_salt=%s", len(cipher) // 2, bool(salt))
    result = decrypt_message(
        ciphertext_hex=cipher,
        nonce=nonce,
        salt_hex=salt,
        password=password,
        iterations=iterations,
        demo_mode=demo_mode,
    )
    return jsonify(result)


@app.route("/hide", methods=["POST"])
def hide():
    file = request.files.get("image")
    if file is None or not file.filename:
        raise ValidationError("Image file is required.")
    validate_uploaded_extension(file.filename, mode="image")

    message = validate_non_empty_text(request.form.get("message"), "message")
    upload_path = _save_upload(file, UPLOAD_FOLDER)

    capacity = image_capacity_chars(str(upload_path))
    detect_before = detect_steganography(str(upload_path))

    start = time.perf_counter()
    output_path = hide_message(str(upload_path), message, OUTPUT_FOLDER)
    duration_ms = round((time.perf_counter() - start) * 1000, 3)

    logger.info("Stego hide | image=%s output=%s", upload_path.name, output_path.name)
    return jsonify(
        {
            "result": "Message hidden successfully",
            "steganography_detected": detect_before["detected"],
            "detection_report": detect_before,
            "capacity_chars": capacity,
            "output_file": output_path.name,
            "download_url": _download_url(output_path.name),
            "duration_ms": duration_ms,
        }
    )


@app.route("/extract", methods=["POST"])
def extract():
    file = request.files.get("image")
    if file is None or not file.filename:
        raise ValidationError("Image file is required.")
    validate_uploaded_extension(file.filename, mode="image")

    upload_path = _save_upload(file, UPLOAD_FOLDER)
    start = time.perf_counter()
    message = extract_message(str(upload_path))
    duration_ms = round((time.perf_counter() - start) * 1000, 3)

    detect_report = detect_steganography(str(upload_path))
    return jsonify(
        {
            "message": message,
            "steganography_detected": detect_report["detected"],
            "detection_report": detect_report,
            "duration_ms": duration_ms,
        }
    )


@app.route("/scan", methods=["POST"])
def scan():
    file = request.files.get("file")
    if file is None or not file.filename:
        raise ValidationError("A GIF file is required.")
    validate_uploaded_extension(file.filename, mode="scan")

    upload_path = _save_upload(file, UPLOAD_FOLDER)
    start = time.perf_counter()
    report = scan_gif(str(upload_path))
    report["duration_ms"] = round((time.perf_counter() - start) * 1000, 3)
    return jsonify(report)


@app.route("/encrypt-file", methods=["POST"])
def encrypt_file():
    file = request.files.get("file")
    if file is None or not file.filename:
        raise ValidationError("A file is required.")

    password = validate_non_empty_text(request.form.get("password"), "password")
    iterations = validate_positive_int(
        request.form.get("iterations"),
        "iterations",
        DEFAULT_PBKDF2_ITERATIONS,
        500,
        100_000,
    )

    payload_bytes = file.read() or b""
    payload = encrypt_binary_payload(payload_bytes, password=password, iterations=iterations)
    payload["original_filename"] = secure_filename(file.filename) or "file.bin"

    out_name = f"{int(time.time())}_{Path(payload['original_filename']).stem}.cst"
    download_token = _store_in_memory_download(serialize_encrypted_payload(payload), out_name)

    return jsonify(
        {
            "result": "File encrypted successfully",
            "output_file": out_name,
            "download_url": _download_url(download_token),
        }
    )


@app.route("/decrypt-file", methods=["POST"])
def decrypt_file():
    file = request.files.get("file")
    if file is None or not file.filename:
        raise ValidationError("Encrypted .cst file is required.")

    password = validate_non_empty_text(request.form.get("password"), "password")
    payload = parse_encrypted_payload(file.read() or b"")

    plain_data = decrypt_binary_payload(payload, password=password)
    original_filename = secure_filename(str(payload.get("original_filename") or "decrypted_output.bin"))
    output_name = f"{int(time.time())}_decrypted_{original_filename}"
    download_token = _store_in_memory_download(plain_data, output_name)

    return jsonify(
        {
            "result": "File decrypted successfully",
            "output_file": output_name,
            "download_url": _download_url(download_token),
        }
    )


@app.route("/download/<path:filename>")
def download(filename: str):
    cached_download = _resolve_in_memory_download(filename)
    if cached_download is not None:
        payload_bytes, download_name = cached_download
        return send_file(
            BytesIO(payload_bytes),
            as_attachment=True,
            download_name=download_name,
            mimetype="application/octet-stream",
        )

    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)


@app.route("/hash/sha256", methods=["POST"])
def hash_sha256():
    payload = _json_data()
    text = validate_non_empty_text(payload.get("text"), "text")
    digest = sha256_hex(text.encode("utf-8"))
    return jsonify({"algorithm": "SHA-256 (handwritten)", "digest": digest})


@app.route("/kdf/pbkdf2", methods=["POST"])
def kdf_pbkdf2():
    payload = _json_data()
    password = validate_non_empty_text(payload.get("password"), "password")
    iterations = validate_positive_int(payload.get("iterations"), "iterations", 3000, 100, 200_000)
    dklen = validate_positive_int(payload.get("dklen"), "dklen", 32, 16, 128)

    salt_raw = payload.get("salt")
    if salt_raw:
        try:
            salt = bytes.fromhex(str(salt_raw))
        except ValueError:
            salt = str(salt_raw).encode("utf-8")
    else:
        salt = os.urandom(8)

    derived = pbkdf2_sha256(password=password.encode("utf-8"), salt=salt, iterations=iterations, dklen=dklen)
    return jsonify(
        {
            "algorithm": "PBKDF2-HMAC-SHA256 (handwritten)",
            "iterations": iterations,
            "dklen": dklen,
            "salt_hex": salt.hex(),
            "derived_key_hex": derived.hex(),
        }
    )


@app.route("/dh/simulate", methods=["POST"])
def diffie_hellman_simulation():
    return jsonify(simulate_key_exchange())


@app.route("/rsa/generate", methods=["POST"])
def rsa_generate():
    payload = _json_data()
    bits = validate_positive_int(payload.get("bits"), "bits", 512, 64, 2048)
    start = time.perf_counter()
    keys = generate_rsa_keypair(bits=bits)
    duration_ms = round((time.perf_counter() - start) * 1000, 3)

    return jsonify(
        {
            "public_key": {"n": str(keys["n"]), "e": keys["e"]},
            "private_key": {"n": str(keys["n"]), "d": str(keys["d"])},
            "meta": {"bits": keys["bits"], "duration_ms": duration_ms},
        }
    )


@app.route("/rsa/encrypt", methods=["POST"])
def rsa_encrypt_route():
    payload = _json_data()
    message = validate_non_empty_text(payload.get("message"), "message")
    n = _require_int(payload.get("n"), "n")
    e = _require_int(payload.get("e", 65537), "e")
    cipher_blocks = rsa_encrypt(message, e=e, n=n)
    return jsonify({"cipher_blocks": cipher_blocks})


@app.route("/rsa/decrypt", methods=["POST"])
def rsa_decrypt_route():
    payload = _json_data()
    n = _require_int(payload.get("n"), "n")
    d = _require_int(payload.get("d"), "d")
    cipher_blocks = _parse_cipher_blocks(payload.get("cipher_blocks"))
    message = rsa_decrypt(cipher_blocks, d=d, n=n)
    return jsonify({"message": message})


@app.route("/rsa/sign", methods=["POST"])
def rsa_sign_route():
    payload = _json_data()
    message = validate_non_empty_text(payload.get("message"), "message")
    n = _require_int(payload.get("n"), "n")
    d = _require_int(payload.get("d"), "d")
    signature = rsa_sign(message, d=d, n=n)
    return jsonify({"signature": str(signature)})


@app.route("/rsa/verify", methods=["POST"])
def rsa_verify_route():
    payload = _json_data()
    message = validate_non_empty_text(payload.get("message"), "message")
    n = _require_int(payload.get("n"), "n")
    e = _require_int(payload.get("e"), "e")
    signature = _require_int(payload.get("signature"), "signature")
    valid = rsa_verify(message, signature=signature, e=e, n=n)
    return jsonify({"valid": valid})


@app.route("/benchmark", methods=["POST"])
def benchmark():
    payload = _json_data()
    sample = (payload.get("message") or "Benchmark message for crypto toolkit").strip()
    if not sample:
        sample = "Benchmark message for crypto toolkit"
    return jsonify(run_benchmarks(sample))


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
