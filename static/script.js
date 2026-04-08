const el = (id) => document.getElementById(id);
const HEX_RE = /^[0-9a-fA-F]*$/;

function animateProgress(id) {
  const bar = el(id);
  if (!bar) return;
  bar.classList.remove("active");
  bar.style.width = "0%";
  void bar.offsetWidth;
  bar.classList.add("active");
  setTimeout(() => {
    bar.classList.remove("active");
  }, 1100);
}

function setInvalid(inputEl, isInvalid) {
  if (!inputEl) return;
  inputEl.classList.toggle("invalid", Boolean(isInvalid));
}

function parseJsonSafe(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  const data = parseJsonSafe(text) || {};

  if (!response.ok) {
    throw new Error(data.error || `Request failed with status ${response.status}`);
  }
  return data;
}

function showModal(title, message) {
  const modal = el("statusModal");
  el("modalTitle").textContent = title;
  el("modalMessage").textContent = message;
  modal.hidden = false;
}

function closeModal() {
  el("statusModal").hidden = true;
}

function normalizeNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function stringifyOutput(data) {
  if (typeof data === "string") return data;
  return JSON.stringify(data, null, 2);
}

async function copyTarget(targetId) {
  const target = el(targetId);
  if (!target) {
    showModal("Copy Error", "Unable to find target content.");
    return;
  }

  const text = target.value || target.textContent || "";
  if (!text.trim()) {
    showModal("Nothing to Copy", "Target output is empty.");
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    showModal("Copied", "Output copied to clipboard.");
  } catch {
    showModal("Copy Error", "Clipboard access failed in this browser context.");
  }
}

function renderDownload(linkId, url) {
  const link = el(linkId);
  if (!link) return;
  if (!url) {
    link.hidden = true;
    return;
  }
  link.href = url;
  link.hidden = false;
}

async function encrypt() {
  const message = el("msg").value.trim();
  if (!message) {
    setInvalid(el("msg"), true);
    showModal("Validation", "Message is required for encryption.");
    return;
  }

  setInvalid(el("msg"), false);
  animateProgress("encryptBar");

  try {
    const payload = {
      message,
      password: el("encPassword").value,
      iterations: normalizeNumber(el("encIterations").value, 3000),
      demo_mode: el("encDemoMode").checked,
    };

    const data = await requestJson("/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    let output =
      `Cipher:\n${data.cipher}\n\n` +
      `Nonce: ${data.nonce}\n` +
      `Salt: ${data.salt}\n` +
      `Iterations: ${data.iterations}\n` +
      `Duration: ${data.duration_ms} ms`;

    if (data.demo_steps) {
      output += `\n\nDemo Steps:\n${stringifyOutput(data.demo_steps)}`;
    }

    el("enc").textContent = output;
    el("cipher").value = data.cipher;
    el("nonce").value = data.nonce;
    el("salt").value = data.salt;
    el("decIterations").value = data.iterations;

    showModal("Encryption Complete", "Cipher generated successfully.");
  } catch (error) {
    showModal("Encryption Failed", error.message);
  }
}

async function decrypt() {
  const cipher = el("cipher").value.trim();
  const nonce = el("nonce").value.trim();
  const salt = el("salt").value.trim();

  const cipherInvalid = !cipher || !HEX_RE.test(cipher) || cipher.length % 2 !== 0;
  const saltInvalid = salt && (!HEX_RE.test(salt) || salt.length % 2 !== 0);

  setInvalid(el("cipher"), cipherInvalid);
  setInvalid(el("salt"), saltInvalid);
  setInvalid(el("nonce"), !nonce);

  if (cipherInvalid || saltInvalid || !nonce) {
    showModal("Validation", "Cipher, nonce, and optional salt format must be valid.");
    return;
  }

  animateProgress("decryptBar");

  try {
    const payload = {
      cipher,
      nonce,
      salt,
      password: el("decPassword").value,
      iterations: normalizeNumber(el("decIterations").value, 3000),
      demo_mode: el("decDemoMode").checked,
    };

    const data = await requestJson("/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    let output = `Decrypted: ${data.decrypted}\nDuration: ${data.duration_ms} ms`;
    if (data.demo_steps) {
      output += `\n\nDemo Steps:\n${stringifyOutput(data.demo_steps)}`;
    }
    el("dec").textContent = output;
    showModal("Decryption Complete", "Ciphertext decrypted successfully.");
  } catch (error) {
    showModal("Decryption Failed", error.message);
  }
}

async function hideMessage() {
  const image = el("img").files[0];
  const message = el("hiddenmsg").value.trim();

  setInvalid(el("hiddenmsg"), !message);
  if (!image || !message) {
    showModal("Validation", "Select an image and enter a message to hide.");
    return;
  }

  animateProgress("hideBar");

  const form = new FormData();
  form.append("image", image);
  form.append("message", message);

  try {
    const data = await requestJson("/hide", { method: "POST", body: form });
    el("hideStatus").textContent =
      `${data.result}\n` +
      `Capacity: ${data.capacity_chars} chars\n` +
      `Detected Before Hide: ${data.steganography_detected}\n` +
      `Duration: ${data.duration_ms} ms`;

    renderDownload("hideDownload", data.download_url);
    showModal("Steganography", "Message embedded successfully.");
  } catch (error) {
    renderDownload("hideDownload", null);
    showModal("Hide Failed", error.message);
  }
}

async function extractMessage() {
  const image = el("extractimg").files[0];
  if (!image) {
    showModal("Validation", "Select an image to extract from.");
    return;
  }

  animateProgress("extractBar");

  const form = new FormData();
  form.append("image", image);

  try {
    const data = await requestJson("/extract", { method: "POST", body: form });
    el("extracted").textContent =
      `Hidden Message: ${data.message}\n` +
      `Steganography Detected: ${data.steganography_detected}\n` +
      `Duration: ${data.duration_ms} ms`;
    showModal("Extract Complete", "Hidden message extracted.");
  } catch (error) {
    showModal("Extract Failed", error.message);
  }
}

async function scanGif() {
  const file = el("gif").files[0];
  if (!file) {
    showModal("Validation", "Select a GIF file to scan.");
    return;
  }
  if (!file.name.toLowerCase().endsWith(".gif")) {
    setInvalid(el("gif"), true);
    showModal("Validation", "Only .gif files are supported for scanning.");
    return;
  }

  setInvalid(el("gif"), false);
  animateProgress("scanBar");

  const form = new FormData();
  form.append("file", file);

  try {
    const data = await requestJson("/scan", { method: "POST", body: form });
    el("report").textContent = stringifyOutput(data);
    showModal("Scan Complete", `Threat level: ${data.threat_level}`);
  } catch (error) {
    showModal("Scan Failed", error.message);
  }
}

async function encryptFile() {
  const file = el("fileEncInput").files[0];
  const password = el("filePassword").value.trim();

  setInvalid(el("filePassword"), !password);
  if (!file || !password) {
    showModal("Validation", "Select a file and enter a password.");
    return;
  }

  const form = new FormData();
  form.append("file", file);
  form.append("password", password);

  try {
    const data = await requestJson("/encrypt-file", { method: "POST", body: form });
    el("fileStatus").textContent = `${data.result}\nEncrypted file: ${data.output_file}`;
    renderDownload("encryptFileDownload", data.download_url);
    showModal("File Encryption", "Encrypted payload generated.");
  } catch (error) {
    renderDownload("encryptFileDownload", null);
    showModal("File Encryption Failed", error.message);
  }
}

async function decryptFile() {
  const file = el("fileDecInput").files[0];
  const password = el("fileDecPassword").value.trim();

  setInvalid(el("fileDecPassword"), !password);
  if (!file || !password) {
    showModal("Validation", "Select an encrypted file and enter password.");
    return;
  }

  const form = new FormData();
  form.append("file", file);
  form.append("password", password);

  try {
    const data = await requestJson("/decrypt-file", { method: "POST", body: form });
    el("fileStatus").textContent = `${data.result}\nDecrypted file: ${data.output_file}`;
    renderDownload("decryptFileDownload", data.download_url);
    showModal("File Decryption", "File decrypted successfully.");
  } catch (error) {
    renderDownload("decryptFileDownload", null);
    showModal("File Decryption Failed", error.message);
  }
}

async function computeHash() {
  const text = el("hashText").value.trim();
  setInvalid(el("hashText"), !text);
  if (!text) {
    showModal("Validation", "Text is required for hashing.");
    return;
  }

  try {
    const data = await requestJson("/hash/sha256", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    el("hashResult").textContent = `${data.algorithm}\n${data.digest}`;
  } catch (error) {
    showModal("Hash Failed", error.message);
  }
}

async function deriveKey() {
  const password = el("kdfPassword").value.trim();
  const salt = el("kdfSalt").value.trim();
  const iterations = normalizeNumber(el("kdfIterations").value, 3000);

  setInvalid(el("kdfPassword"), !password);
  if (!password) {
    showModal("Validation", "Password is required for PBKDF2.");
    return;
  }

  try {
    const data = await requestJson("/kdf/pbkdf2", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password, salt, iterations, dklen: 32 }),
    });

    el("kdfResult").textContent = stringifyOutput(data);
  } catch (error) {
    showModal("KDF Failed", error.message);
  }
}

function rsaInputs() {
  const n = el("rsaN").value.trim();
  const e = el("rsaE").value.trim() || "65537";
  const d = el("rsaD").value.trim();
  return { n, e, d };
}

async function rsaGenerate() {
  try {
    const bits = normalizeNumber(el("rsaBits").value, 512);
    const data = await requestJson("/rsa/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bits }),
    });

    el("rsaN").value = data.public_key.n;
    el("rsaE").value = data.public_key.e;
    el("rsaD").value = data.private_key.d;
    el("rsaOutput").textContent = `Generated RSA keys (${data.meta.bits} bits) in ${data.meta.duration_ms} ms.`;
    showModal("RSA", "RSA key pair generated.");
  } catch (error) {
    showModal("RSA Generation Failed", error.message);
  }
}

async function rsaEncryptAction() {
  const message = el("rsaMessage").value.trim();
  const { n, e } = rsaInputs();

  if (!message || !n || !e) {
    showModal("Validation", "Message, n, and e are required for RSA encryption.");
    return;
  }

  try {
    const data = await requestJson("/rsa/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, n, e }),
    });

    el("rsaCipherBlocks").value = data.cipher_blocks.join(",");
    el("rsaOutput").textContent = `RSA cipher blocks generated (${data.cipher_blocks.length} blocks).`;
  } catch (error) {
    showModal("RSA Encrypt Failed", error.message);
  }
}

async function rsaDecryptAction() {
  const { n, d } = rsaInputs();
  const blocks = el("rsaCipherBlocks").value.trim();

  if (!blocks || !n || !d) {
    showModal("Validation", "Cipher blocks, n, and d are required for RSA decryption.");
    return;
  }

  const parsedBlocks = blocks
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => Number(item));

  if (!parsedBlocks.length || parsedBlocks.some((value) => !Number.isFinite(value))) {
    showModal("Validation", "Cipher blocks must be comma-separated integers.");
    return;
  }

  try {
    const data = await requestJson("/rsa/decrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n, d, cipher_blocks: parsedBlocks }),
    });

    el("rsaOutput").textContent = `Decrypted message: ${data.message}`;
  } catch (error) {
    showModal("RSA Decrypt Failed", error.message);
  }
}

async function rsaSignAction() {
  const message = el("rsaMessage").value.trim();
  const { n, d } = rsaInputs();

  if (!message || !n || !d) {
    showModal("Validation", "Message, n, and d are required for signing.");
    return;
  }

  try {
    const data = await requestJson("/rsa/sign", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, n, d }),
    });

    el("rsaSignature").value = data.signature;
    el("rsaOutput").textContent = `Signature generated.`;
  } catch (error) {
    showModal("RSA Sign Failed", error.message);
  }
}

async function rsaVerifyAction() {
  const message = el("rsaMessage").value.trim();
  const { n, e } = rsaInputs();
  const signature = el("rsaSignature").value.trim();

  if (!message || !n || !e || !signature) {
    showModal("Validation", "Message, n, e, and signature are required for verification.");
    return;
  }

  try {
    const data = await requestJson("/rsa/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, n, e, signature }),
    });

    el("rsaOutput").textContent = `Signature valid: ${data.valid}`;
  } catch (error) {
    showModal("RSA Verify Failed", error.message);
  }
}

async function runBenchmark() {
  const message = el("benchmarkMessage").value.trim() || "Benchmark message for crypto toolkit";

  try {
    const data = await requestJson("/benchmark", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    el("benchmarkOutput").textContent = stringifyOutput(data);
  } catch (error) {
    showModal("Benchmark Failed", error.message);
  }
}

async function runDiffieHellman() {
  try {
    const data = await requestJson("/dh/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    el("benchmarkOutput").textContent = stringifyOutput(data);
  } catch (error) {
    showModal("Diffie-Hellman Failed", error.message);
  }
}

function attachDropZone(zoneId, inputId, validator) {
  const zone = el(zoneId);
  const input = el(inputId);
  if (!zone || !input) return;

  const selectFile = (file) => {
    if (!file) return;
    if (validator && !validator(file)) {
      showModal("Validation", "Selected file type is not allowed here.");
      return;
    }

    const transfer = new DataTransfer();
    transfer.items.add(file);
    input.files = transfer.files;
    zone.textContent = `Selected: ${file.name}`;
  };

  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input.click();
    }
  });

  zone.addEventListener("dragover", (event) => {
    event.preventDefault();
    zone.classList.add("dragover");
  });

  zone.addEventListener("dragleave", () => {
    zone.classList.remove("dragover");
  });

  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("dragover");
    selectFile(event.dataTransfer.files[0]);
  });

  input.addEventListener("change", () => {
    const file = input.files[0];
    if (!file) return;
    if (validator && !validator(file)) {
      input.value = "";
      showModal("Validation", "Selected file type is not allowed here.");
      return;
    }
    zone.textContent = `Selected: ${file.name}`;
  });
}

function setupTheme() {
  const savedTheme = localStorage.getItem("cst_theme");
  if (savedTheme === "light") {
    document.body.dataset.theme = "light";
  }

  el("themeToggle").addEventListener("click", () => {
    const nextTheme = document.body.dataset.theme === "light" ? "dark" : "light";
    if (nextTheme === "dark") {
      delete document.body.dataset.theme;
      localStorage.setItem("cst_theme", "dark");
    } else {
      document.body.dataset.theme = "light";
      localStorage.setItem("cst_theme", "light");
    }
  });
}

function setupValidationHints() {
  const cipher = el("cipher");
  const salt = el("salt");

  cipher.addEventListener("input", () => {
    const value = cipher.value.trim();
    const invalid = value && (!HEX_RE.test(value) || value.length % 2 !== 0);
    setInvalid(cipher, invalid);
  });

  salt.addEventListener("input", () => {
    const value = salt.value.trim();
    const invalid = value && (!HEX_RE.test(value) || value.length % 2 !== 0);
    setInvalid(salt, invalid);
  });
}

function setupEvents() {
  el("encryptBtn").addEventListener("click", encrypt);
  el("decryptBtn").addEventListener("click", decrypt);
  el("hideBtn").addEventListener("click", hideMessage);
  el("extractBtn").addEventListener("click", extractMessage);
  el("scanBtn").addEventListener("click", scanGif);

  el("encryptFileBtn").addEventListener("click", encryptFile);
  el("decryptFileBtn").addEventListener("click", decryptFile);

  el("hashBtn").addEventListener("click", computeHash);
  el("kdfBtn").addEventListener("click", deriveKey);

  el("rsaGenerateBtn").addEventListener("click", rsaGenerate);
  el("rsaEncryptBtn").addEventListener("click", rsaEncryptAction);
  el("rsaDecryptBtn").addEventListener("click", rsaDecryptAction);
  el("rsaSignBtn").addEventListener("click", rsaSignAction);
  el("rsaVerifyBtn").addEventListener("click", rsaVerifyAction);

  el("benchmarkBtn").addEventListener("click", runBenchmark);
  el("dhBtn").addEventListener("click", runDiffieHellman);

  el("modalCloseBtn").addEventListener("click", closeModal);
  el("statusModal").addEventListener("click", (event) => {
    if (event.target.id === "statusModal") closeModal();
  });

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", () => copyTarget(button.dataset.copyTarget));
  });
}

document.addEventListener("DOMContentLoaded", () => {
  setupTheme();
  setupEvents();
  setupValidationHints();

  attachDropZone("imageDrop", "img", (file) => file.type.startsWith("image/"));
  attachDropZone("gifDrop", "gif", (file) => file.name.toLowerCase().endsWith(".gif"));
});