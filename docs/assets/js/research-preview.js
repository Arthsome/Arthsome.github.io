/* research board — selecting a publication switches figure, forensic
   metadata, and technical thread together. WHT ships five real article
   figures; CVE is rendered as a verified data card only (the article has
   no figures — no invented imagery). */
(function () {
  "use strict";
  var board = document.querySelector("[data-board]");
  if (!board) return;
  var panel = board.querySelector(".board-panel");
  var img = board.querySelector("#boardImg");
  var chip = board.querySelector("#boardChip");
  var dim = board.querySelector("#boardDim");
  var label = board.querySelector("#boardLabel");
  var cta = board.querySelector("#boardCta");
  var rows = board.querySelector("#boardRows");
  var foot = board.querySelector("#boardFoot");
  var tech = board.querySelector("#boardTech");
  var entries = board.querySelectorAll(".board-entry");
  var figBtns = board.querySelectorAll(".bf-btn");
  var figRail = board.querySelector(".board-fig-rail");
  if (!panel || !img || !chip || !rows) return;

  var FIGS = [
    { file: "assets/img/wht-shellcode/01-hexdump-comparison.png", tag: "FIG. 01 — HEX DUMP COMPARISON", dim: "2268 × 1422 · PNG", alt: "Hex dump comparison: raw shellcode bytes versus permuted output" },
    { file: "assets/img/wht-shellcode/02-pipeline-flow.png", tag: "FIG. 02 — OBFUSCATION PIPELINE", dim: "2268 × 1006 · PNG", alt: "Obfuscation pipeline: shellcode input, WHT transform, spectral permutation, byte output" },
    { file: "assets/img/wht-shellcode/03-spectral-analysis.png", tag: "FIG. 03 — SPECTRAL ANALYSIS", dim: "2394 × 1267 · PNG", alt: "Spectral analysis of the Walsh-Hadamard transform output" },
    { file: "assets/img/wht-shellcode/04-butterfly-values.png", tag: "FIG. 04 — BUTTERFLY VALUES", dim: "1988 × 1286 · PNG", alt: "Butterfly stage values before and after integer transform" },
    { file: "assets/img/wht-shellcode/05-key-sensitivity.png", tag: "FIG. 05 — KEY SENSITIVITY", dim: "2359 × 1323 · PNG", alt: "Key sensitivity analysis of the spectral permutation key space" },
  ];
  FIGS.forEach(function (f) { var pre = new Image(); pre.src = f.file; });

  var WHT = {
    label: "Mechanism",
    cta: "Open the technique note",
    href: "posts/wht-shellcode-obfuscation/index.html",
    foot: "Integer-only butterfly · no S-boxes · no crypto constants · no math library",
    rows: [
      ["01", "Input · shellcode bytes"],
      ["02", "Transform · Walsh&ndash;Hadamard"],
      ["03", "Permute · spectral key"],
      ["04", "Output · permuted bytes"],
    ],
    techLabel: "Implementation",
    tech: [
      ["Integer-only", "Butterfly, no S-boxes"],
      ["Detection", "YARA + Sigma inside"],
      ["MITRE", "T1027 / T1055"],
    ],
  };
  var CVE = {
    label: "Admission path — data card",
    cta: "Read the full analysis",
    href: "posts/cve-2025-20281/index.html",
    foot: "Evidence-backed · post-patch only · no invented imagery",
    rows: [
      ["01", "Unauth request"],
      ["02", "Management API · role check missing"],
      ["03", "Elevated command execution"],
    ],
    techLabel: "Classification",
    tech: [
      ["CWE", "862 · Missing Authorization"],
      ["CVSS", "10.0 · Critical"],
      ["Disclosure", "Post-patch only"],
    ],
  };

  function rowHtml(idx, text, acid) {
    var acidCls = acid ? " fv-acid" : "";
    return '<div class="fv-row' + acidCls + '"><span>' + idx + "</span><b>" + text + "</b></div>";
  }

  var curFig = 2;
  function setFig(i) {
    curFig = i;
    var f = FIGS[i];
    img.src = f.file;
    img.alt = f.alt;
    chip.textContent = f.tag;
    if (dim) dim.textContent = f.dim;
    figBtns.forEach(function (b) {
      var on = Number(b.getAttribute("data-fig")) === i;
      b.classList.toggle("is-active", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }

  function render(key) {
    var v = key === "cve" ? CVE : WHT;
    panel.classList.toggle("is-data", key === "cve");
    if (figRail) figRail.hidden = key === "cve";
    if (key === "wht") setFig(curFig);
    else { chip.textContent = "DATA CARD — NO FIGURE IN ARTICLE"; if (dim) dim.textContent = "VERIFIED CLAIMS ONLY"; }
    label.textContent = v.label;
    cta.textContent = v.cta;
    cta.setAttribute("href", v.href);
    rows.innerHTML = v.rows.map(function (r, i) { return rowHtml(r[0], r[1], key === "cve" && i === 2); }).join("");
    foot.textContent = v.foot;
    tech.innerHTML = '<span class="board-label">' + v.techLabel + "</span>" +
      v.tech.map(function (t) { return rowHtml(t[0], t[1], false); }).join("");
    entries.forEach(function (e) {
      var on = e.getAttribute("data-entry") === key;
      e.classList.toggle("is-active", on);
      e.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }

  entries.forEach(function (e) {
    var key = e.getAttribute("data-entry");
    e.addEventListener("click", function () { render(key); });
    e.addEventListener("mouseenter", function () { render(key); });
    e.addEventListener("focus", function () { render(key); });
  });
  figBtns.forEach(function (b) {
    b.addEventListener("click", function () { setFig(Number(b.getAttribute("data-fig"))); });
  });

  render("wht");
})();
