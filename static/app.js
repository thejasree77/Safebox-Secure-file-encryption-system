(function () {
  const $ = id => document.getElementById(id);

  // ---------- shared helpers ----------
  const SETS = ["abcdefghijkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%*?"];
  const rnd = n => { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; };
  function generateKey(len) {
    const all = SETS.join(""), pick = s => s[rnd(s.length)];
    const c = SETS.map(pick);
    while (c.length < (len || 18)) c.push(pick(all));
    for (let i = c.length - 1; i > 0; i--) { const j = rnd(i + 1); [c[i], c[j]] = [c[j], c[i]]; }
    return c.join("");
  }
  function copyText(text, btn) {
    const done = () => { if (btn) { const old = btn.textContent; btn.textContent = "Copied ✓"; setTimeout(() => btn.textContent = old, 1500); } };
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done); return; }
    const t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select();
    document.execCommand("copy"); t.remove(); done();
  }
  function saveText(filename, text) {
    const blob = new Blob([text], { type: "text/plain" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = filename; a.click(); URL.revokeObjectURL(a.href);
  }
  function strength(s) {
    const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(s)).length;
    if (s.length >= 12 && kinds >= 3) return "Strong ✓";
    return s.length >= 8 ? "Okay (12+ characters with mixed types is stronger)" : "Too short (8+ needed)";
  }

  // ---------- generic buttons ----------
  document.addEventListener("click", e => {
    const t = e.target.closest("[data-toggle]");
    if (t) { const i = $(t.dataset.toggle); const show = i.type === "password"; i.type = show ? "text" : "password"; t.textContent = show ? "Hide" : "Show"; }
    const c = e.target.closest("[data-copy-from]");
    if (c) { copyText($(c.dataset.copyFrom).value, c); }
  });

  // ---------- share links page ----------
  const lpw = $("lpw");
  if (lpw) {
    const lgen = $("lgen");
    const setLink = () => {
      const auto = document.querySelector("input[name=lpmode]:checked").value === "gen";
      lpw.readOnly = auto; lpw.type = auto ? "text" : "password";
      lpw.value = auto ? generateKey(14) : "";
      lgen.hidden = !auto;
    };
    document.querySelectorAll("input[name=lpmode]").forEach(r => r.onchange = setLink);
    lgen.onclick = () => { lpw.value = generateKey(14); };
    $("ldl").onclick = () => { if (lpw.value) saveText("safebox-link-password.txt", "SafeBox link password\nPassword: " + lpw.value + "\n"); };
    setLink();
  }
  const mk = $("mk");
  if (mk) {
    const boxes = () => [...document.querySelectorAll("input[name=file_ids]")];
    const update = () => { mk.disabled = !boxes().some(b => b.checked); };
    document.addEventListener("change", e => {
      if (e.target.name === "file_ids") update();
      if (e.target.id === "allfiles") { boxes().forEach(b => b.checked = e.target.checked); update(); }
    });
    update();
  }

  // ---------- lock a file page ----------
  const drop = $("drop");
  if (!drop) return;
  const file = $("file"), go = $("go"), secret = $("secret"), status = $("keyStatus");
  const fmt = n => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
  const mode = () => document.querySelector("input[name=mode]:checked").value;

  function refresh() {
    const v = secret.value;
    status.textContent = !v ? "Password check: not ready"
      : v.length < 8 ? "Password check: " + strength(v)
      : "Password check: ✓ Ready (" + strength(v) + ")";
    go.disabled = !(file.files.length && v.length >= 8);
  }
  function showFile() {
    const f = file.files[0]; if (!f) return;
    $("fName").textContent = f.name; $("fSize").textContent = fmt(f.size); $("fileCard").hidden = false; refresh();
  }
  function setMode() {
    const gen = mode() === "gen";
    secret.readOnly = gen; secret.type = gen ? "text" : "password"; secret.value = gen ? generateKey(18) : "";
    secret.placeholder = gen ? "" : "Choose a strong password (12+ characters)";
    $("gen").hidden = !gen; $("toggle").hidden = gen; $("toggle").textContent = "Show";
    refresh();
  }

  $("browse").onclick = () => file.click();
  file.onchange = showFile;
  ["dragenter", "dragover"].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => { if (e.dataTransfer.files.length) { file.files = e.dataTransfer.files; showFile(); } });

  document.querySelectorAll("input[name=mode]").forEach(r => r.onchange = setMode);
  $("gen").onclick = () => { secret.value = generateKey(18); refresh(); };
  $("toggle").onclick = () => { const s = secret.type === "password"; secret.type = s ? "text" : "password"; $("toggle").textContent = s ? "Hide" : "Show"; };
  $("copy").onclick = e => { if (secret.value) copyText(secret.value, e.target); };
  $("dl").onclick = () => {
    if (!secret.value) return;
    const name = file.files[0] ? file.files[0].name : "file";
    saveText("safebox-password.txt", "SafeBox password\nFile: " + name + "\nPassword: " + secret.value + "\n");
  };
  secret.addEventListener("input", refresh);
  setMode();
})();