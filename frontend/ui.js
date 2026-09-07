function toast(msg, isErr) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.style.borderColor = isErr ? "#ff4f6f" : "#22c98f";
  t.style.display = "block";
  clearTimeout(t._hideTimer);
  t._hideTimer = setTimeout(() => { t.style.display = "none"; }, 5000);
}

function show(id, obj) {
  document.getElementById(id).textContent = JSON.stringify(obj, null, 2);
}

async function requestJson(url, options = {}) {
  const opts = { ...options };
  opts.headers = opts.headers || {};
  const isForm = opts.body instanceof FormData;
  if (!isForm) opts.headers["Content-Type"] = "application/json";
  try {
    const res = await fetch(url, opts);
    const data = await res.json();
    return { httpOk: res.ok, status: res.status, data };
  } catch (e) {
    return { httpOk: false, status: 0, data: { ok: false, reason: "network_or_server_error", detail: String(e) } };
  }
}

function withLoading(btn, fn) {
  return async (...args) => {
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Working...";
    try {
      await fn(...args);
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  };
}

document.getElementById("fileInput").addEventListener("change", () => {
  const f = document.getElementById("fileInput").files[0];
  document.getElementById("fileNameShown").textContent = f ? `Selected: ${f.name} (${f.size} bytes)` : "";
});

async function setupVault() {
  const password = document.getElementById("setupPassword").value.trim();
  const email = document.getElementById("setupEmail").value.trim();
  const { data } = await requestJson("/api/setup", { method: "POST", body: JSON.stringify({ password, email }) });
  show("responseBox", data);
  toast(data.ok ? "Vault initialized" : `Setup failed: ${data.reason}`, !data.ok);

  if (data.ok) refreshStatus(password);
}

async function testEmail() {
  const { data } = await requestJson("/api/test_email", { method: "POST" });
  show("responseBox", data);
  toast(data.ok ? "Test email sent, check inbox" : `Email failed: ${data.detail || data.reason}`, !data.ok);
}

async function requestOtp() {
  const password = document.getElementById("otpPassword").value.trim();
  const { data } = await requestJson("/api/request_otp", { method: "POST", body: JSON.stringify({ password }) });
  show("responseBox", data);
  toast(data.ok ? data.message : `OTP failed: ${data.detail || data.reason}`, !data.ok);
}

async function lockFile() {
  const file = document.getElementById("fileInput").files[0];
  const box = document.getElementById("encryptedLinkBox");
  box.innerHTML = "";
  if (!file) {
    show("responseBox", { ok: false, reason: "select_file_first" });
    toast("Select a file first", true);
    return;
  }

  const password = document.getElementById("password").value.trim();
  const fd = new FormData();
  fd.append("file", file);
  fd.append("password", password);
  fd.append("otp", document.getElementById("otp").value.trim());

  const { data } = await requestJson("/api/lock", { method: "POST", body: fd });
  show("responseBox", data);

  if (data.ok) {
    document.getElementById("vaultId").value = data.vault_id;
    toast(`File encrypted. Vault ID: ${data.vault_id}`, false);
    const a = document.createElement("a");
    a.href = data.encrypted_download_url;
    a.className = "dl-link";
    a.textContent = "⬇ Download Encrypted File (real scrambled bytes, not your original)";
    box.appendChild(a);
  } else {
    toast(`Lock failed: ${data.detail || data.reason}`, true);
  }
  refreshStatus(password);
}

async function unlockVault() {
  const vault_id = document.getElementById("vaultId").value.trim();
  const password = document.getElementById("unlockPassword").value.trim();
  const box = document.getElementById("decryptedLinkBox");
  box.innerHTML = "";

  const { data } = await requestJson("/api/unlock", { method: "POST", body: JSON.stringify({ vault_id, password }) });
  show("responseBox", data);

  if (data.ok && data.honeypot) {
    toast("Wrong password -- real fake decoy file generated", true);
    const a = document.createElement("a");
    a.href = data.honeypot_download_url;
    a.className = "dl-link honeypot";
    a.textContent = `⬇ Download Decoy File (${data.honeypot_filename}) -- this is what an attacker would get`;
    box.appendChild(a);
  } else if (data.ok && data.decrypted_download_url) {
    const integrityBadge = data.integrity_verified ? "✔ integrity verified" : "⚠ integrity check failed";
    toast(`Correct password -- real file decrypted (${integrityBadge})`, !data.integrity_verified);
    const btn = document.createElement("button");
    btn.textContent = "⬇ Download Real Decrypted File";
    btn.onclick = () => downloadDecrypted(vault_id, password);
    box.appendChild(btn);
  } else if (!data.ok) {
    toast(`Unlock rejected (attempt #${data.attempts || "?"}, threat score ${data.threat_score ?? "?"})`, true);
  }

  if (data.ok) refreshStatus(password);
}

async function downloadDecrypted(vault_id, password) {
  const res = await fetch(`/api/download_decrypted/${vault_id}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    toast(`Download failed: ${err.detail || err.reason || res.status}`, true);
    // NEW: backend now returns honeypot info here too on wrong password.
    if (err.honeypot) {
      const box = document.getElementById("decryptedLinkBox");
      const a = document.createElement("a");
      a.href = err.honeypot_download_url;
      a.className = "dl-link honeypot";
      a.textContent = `⬇ Download Decoy File (${err.honeypot_filename})`;
      box.appendChild(a);
    }
    return;
  }
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const filename = match ? match[1] : "decrypted_file";
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
  toast(`Downloaded: ${filename}`, false);
}

async function deleteAttempt() {
  const vault_id = document.getElementById("vaultId").value.trim();
  const password = document.getElementById("unlockPassword").value.trim();
  const { data } = await requestJson("/api/delete_attempt", { method: "POST", body: JSON.stringify({ vault_id, password }) });
  show("responseBox", data);
  const box = document.getElementById("decryptedLinkBox");
  if (data.ok && data.honeypot_download_url) {
    const a = document.createElement("a");
    a.href = data.honeypot_download_url;
    a.className = "dl-link honeypot";
    a.textContent = `⬇ Download Decoy File (${data.honeypot_filename})`;
    box.appendChild(a);
  }
  if (data.ok) {
    if (data.message === "vault_deleted_by_owner") toast("Real delete completed (correct password)", false);
    else toast(`Delete blocked. ${data.message} (threat score ${data.threat_score})`, true);
  } else {
    toast(`Delete attempt error: ${data.reason}`, true);
  }
  refreshStatus(password);
}

async function refreshStatus(password) {
  if (!password) {
    show("statusBox", { ok: false, reason: "enter_master_password_to_view_status" });
    return;
  }
  const { data } = await requestJson("/api/status", { method: "POST", body: JSON.stringify({ password }) });
  show("statusBox", data);
  if (data.ok === false && data.reason === "bad_password") {
    toast("Wrong password -- can't load status", true);
  }
}

function viewStatus() {
  const input = document.getElementById("statusPassword");
  const password = input ? input.value.trim() : "";
  refreshStatus(password);
}

document.getElementById("btnSetup").onclick = withLoading(document.getElementById("btnSetup"), setupVault);
document.getElementById("btnTestEmail").onclick = withLoading(document.getElementById("btnTestEmail"), testEmail);
document.getElementById("btnOtp").onclick = withLoading(document.getElementById("btnOtp"), requestOtp);
document.getElementById("btnLock").onclick = withLoading(document.getElementById("btnLock"), lockFile);
document.getElementById("btnUnlock").onclick = withLoading(document.getElementById("btnUnlock"), unlockVault);
document.getElementById("btnDelete").onclick = withLoading(document.getElementById("btnDelete"), deleteAttempt);

const btnStatus = document.getElementById("btnStatus");
if (btnStatus) btnStatus.onclick = withLoading(btnStatus, viewStatus);
