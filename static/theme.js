(function () {
  const THEMES = ["ocean", "forest", "sunset", "grape", "rose", "night"];
  let saved = null;
  try { saved = localStorage.getItem("theme"); } catch (e) {}
  const start = THEMES.includes(saved) ? saved : "ocean";
  document.documentElement.dataset.theme = start;

  function mark(name) {
    const sel = document.getElementById("theme");
    if (sel) sel.value = name;
    document.querySelectorAll("[data-theme-set]").forEach(b =>
      b.classList.toggle("picked", b.dataset.themeSet === name));
  }
  function setTheme(name) {
    document.documentElement.dataset.theme = name;
    try { localStorage.setItem("theme", name); } catch (e) {}
    mark(name);
  }
  document.addEventListener("DOMContentLoaded", () => {
    mark(document.documentElement.dataset.theme);
    const sel = document.getElementById("theme");
    if (sel) sel.onchange = () => setTheme(sel.value);
    document.addEventListener("click", e => {
      const b = e.target.closest("[data-theme-set]");
      if (b) setTheme(b.dataset.themeSet);
    });
  });
})();