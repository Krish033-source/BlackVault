// ============================================================
// BlackVault Terminal Mode
// A REPL in the browser. Reuses helpers already defined in ui.js
// (requestJson, toast, show, refreshStatus, downloadDecrypted) so
// there is exactly ONE place that talks to each API endpoint.
// ============================================================

const termOutput = document.getElementById("termOutput");
const termInput = document.getElementById("termInput");
const termPromptLabel = document.getElementById("termPromptLabel");
const termFileInput = document.getElementById("termFileInput");

let pendingResolve = null;

function printLine(text, cls) {
  const div = document.createElement("div");
  div.className = cls ? `term-line-${cls}` : "";
  div.textContent = text;
  termOutput.appendChild(div);
  termOutput.scrollTop = termOutput.scrollHeight;
}

function printBanner() {
  printLine("BLACKVAULT TERMINAL -- type 'help' for commands.", "info");
  printLine("Same backend as GUI mode; switch back anytime with 'mode gui'.", "info");
  printLine("");
}

function printHelp() {
  const lines = [
    "Available commands:",
    "  setup                 - initialize vault (master password + recovery email)",
    "  otp                   - email yourself a fresh OTP",
    "  lock                  - pick a file and encrypt/lock it",
    "  unlock [vault_id]     - attempt to unlock a vault",
    "  download [vault_id]   - decrypt & save the full original file",
    "  delete [vault_id]     - attempt to delete a vault",
    "  status                - view vaults + audit log (also updates the side panel)",
    "  test-email            - send a test email (checks .env config)",
    "  clear                 - clear this terminal",
    "  mode gui              - switch back to GUI mode",
    "  help                  - show this help"
  ];
  lines.forEach(l => printLine(l, "info"));
}

function termAsk(promptText, masked = false) {
  return new Promise(resolve => {
    termPromptLabel.textContent = promptText;
    termInput.type = masked ? "password" : "text";
    pendingResolve = { resolve, masked };
  });
}

function pickTermFile() {
  return new Promise(resolve => {
    termFileInput.value = "";
    termFileInput.onchange = () => resolve(termFileInput.files[0] || null);
    termFileInput.click();
  });
}

function resetPrompt() {
  termPromptLabel.textContent = "blackvault>";
  termInput.type = "text";
}

termInput.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  const val = termInput.value;
  termInput.value = "";

  if (pendingResolve) {
    const { resolve, masked } = pendingResolve;
    pendingResolve = null;
    printLine(`${termPromptLabel.textContent} ${masked ? "*".repeat(val.length) : val}`, "echo");
    resetPrompt();
    resolve(val);
    return;
  }

  printLine(`blackvault> ${val}`, "echo");
  if (val.trim()) handleCommand(val);
});

async function handleCommand(raw) {
  const parts = raw.trim().split(/\s+/).filter(Boolean);
  const cmd = (parts[0] || "").toLowerCase();
  const arg = parts[1];

  termInput.disabled = true;
  try {
    switch (cmd) {
      case "help": printHelp(); break;
      case "setup": await cmdSetup(); break;
      case "otp": await cmdOtp(); break;
      case "lock": await cmdLock(); break;
      case "unlock": await cmdUnlock(arg); break;
      case "download": await cmdDownload(arg); break;
      case "delete": await cmdDelete(arg); break;
      case "status": await cmdStatus(); break;
      case "test-email": await cmdTestEmail(); break;
      case "clear": termOutput.innerHTML = ""; break;
      case "mode":
        if (arg === "gui") setMode("gui");
        else printLine("Usage: mode gui", "err");
        break;
      default:
        printLine(`Unknown command: '${cmd}'. Type 'help' for a list.`, "err");
    }
  } catch (e) {
    printLine(`Error: ${e}`, "err");
  } finally {
    termInput.disabled = false;
    termInput.focus();
  }
}

async function cmdSetup() {
  const password = await termAsk("Set master password (min 8 chars):", true);
  const confirm = await termAsk("Confirm master password:", true);
  if (password !== confirm) { printLine("Passwords didn't match.", "err"); return; }
  const email = await termAsk("Recovery email:", false);

  const { data } = await requestJson("/api/setup", { method: "POST", body: JSON.stringify({ password, email }) });
  show("responseBox", data);
  if (data.ok) {
    printLine("Vault initialized.", "ok");
    refreshStatus(password);
  } else {
    printLine(`Setup failed: ${data.reason}`, "err");
  }
}

async function cmdOtp() {
  const password = await termAsk("Master password:", true);
  const { data } = await requestJson("/api/request_otp", { method: "POST", body: JSON.stringify({ password }) });
  show("responseBox", data);
  if (data.ok) printLine(data.message, "ok");
  else printLine(`OTP failed: ${data.detail || data.reason}`, "err");
}

async function cmdLock() {
  printLine("Opening file picker...", "info");
  const file = await pickTermFile();
  if (!file) { printLine("No file selected.", "err"); return; }
  printLine(`Selected: ${file.name} (${file.size} bytes)`, "info");

  const password = await termAsk("Master password:", true);
  const otp = await termAsk("OTP from email:", false);

  const fd = new FormData();
  fd.append("file", file);
  fd.append("password", password);
  fd.append("otp", otp);

  const { data } = await requestJson("/api/lock", { method: "POST", body: fd });
  show("responseBox", data);
  if (data.ok) {
    document.getElementById("vaultId").value = data.vault_id;
    printLine(`Locked. Vault ID: ${data.vault_id}`, "ok");
    printLine(`SHA-256: ${data.original_sha256}`, "info");
    printLine(`Encrypted download: ${data.encrypted_download_url}`, "info");
    refreshStatus(password);
  } else {
    printLine(`Lock failed: ${data.detail || data.reason}`, "err");
  }
}

async function cmdUnlock(argVaultId) {
  const vault_id = argVaultId || await termAsk("Vault ID:", false);
  const password = await termAsk("Master password:", true);

  const { data } = await requestJson("/api/unlock", { method: "POST", body: JSON.stringify({ vault_id, password }) });
  show("responseBox", data);
  document.getElementById("vaultId").value = vault_id;

  if (data.ok && data.honeypot) {
    printLine("Wrong password -- a real fake decoy file was generated:", "err");
    printLine(`  ${data.honeypot_download_url}`, "err");
  } else if (data.ok && data.decrypted_download_url) {
    printLine(`Unlocked. Integrity verified: ${data.integrity_verified}`, "ok");
    printLine("Preview:", "info");
    printLine(data.content_preview || "(empty)");
    printLine(`Run 'download ${vault_id}' to save the full file.`, "info");
    refreshStatus(password);
  } else {
    printLine(`Unlock rejected (attempt #${data.attempts ?? "?"}, threat score ${data.threat_score ?? "?"})`, "err");
  }
}

async function cmdDownload(argVaultId) {
  const vault_id = argVaultId || await termAsk("Vault ID:", false);
  const password = await termAsk("Master password:", true);
  printLine("Requesting decrypted file...", "info");
  await downloadDecrypted(vault_id, password);
  printLine("(check your browser downloads)", "info");
}

async function cmdDelete(argVaultId) {
  const vault_id = argVaultId || await termAsk("Vault ID:", false);
  const password = await termAsk("Master password:", true);

  const { data } = await requestJson("/api/delete_attempt", { method: "POST", body: JSON.stringify({ vault_id, password }) });
  show("responseBox", data);

  if (data.ok && data.message === "vault_deleted_by_owner") {
    printLine("Vault deleted (correct password).", "ok");
    refreshStatus(password);
  } else if (data.ok) {
    printLine(`Delete blocked: ${data.message} (threat score ${data.threat_score})`, "err");
    if (data.honeypot_download_url) printLine(`  Decoy: ${data.honeypot_download_url}`, "err");
  } else {
    printLine(`Delete attempt error: ${data.reason}`, "err");
  }
}

async function cmdStatus() {
  const password = await termAsk("Master password:", true);
  await refreshStatus(password);
  printLine("Status updated -- see panel on the right.", "ok");
}

async function cmdTestEmail() {
  const { data } = await requestJson("/api/test_email", { method: "POST" });
  show("responseBox", data);
  if (data.ok) printLine("Test email sent.", "ok");
  else printLine(`Email failed: ${data.detail || data.reason}`, "err");
}

// ============================================================
// GUI <-> Terminal toggle
// ============================================================
const guiPanel = document.getElementById("guiPanel");
const terminalPanel = document.getElementById("terminalPanel");
const modeGuiBtn = document.getElementById("modeGuiBtn");
const modeTermBtn = document.getElementById("modeTermBtn");

function setMode(mode) {
  const isGui = mode !== "terminal";
  guiPanel.style.display = isGui ? "" : "none";
  terminalPanel.style.display = isGui ? "none" : "block";
  modeGuiBtn.classList.toggle("active", isGui);
  modeTermBtn.classList.toggle("active", !isGui);
  try { localStorage.setItem("blackvault_mode", isGui ? "gui" : "terminal"); } catch (e) {}
  if (!isGui) termInput.focus();
}

modeGuiBtn.onclick = () => setMode("gui");
modeTermBtn.onclick = () => setMode("terminal");

let savedMode = "gui";
try { savedMode = localStorage.getItem("blackvault_mode") || "gui"; } catch (e) {}
setMode(savedMode);

printBanner();
