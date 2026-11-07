/* Research contextual preview — hover a research index entry; the featured
   visual re-renders to match the hovered publication. Pure content swap, no
   animation dependency. */
(function () {
  "use strict";
  var feats = document.querySelector(".featured");
  if (!feats) return;
  var vis = feats.querySelector(".feat-visual");
  if (!vis) return;
  var body = vis.querySelector(".fv-body");
  var photo = vis.querySelector(".fv-photo");
  var chip = vis.querySelector(".fv-chip");
  if (!body || !photo || !chip) return;

  var variants = {
    cve: {
      label: "Admission path",
      rows: [
        ["01", "Unauth request"],
        ["02", "Management API · role check missing"],
        ["03", "Elevated command execution"],
      ],
      acidRow: "03",
      foot: "Evidence-led · Detection rules inside",
      techLabel: "Technical thread",
      tech: [["CWE", "862 · Missing Authorization"]],
      img: "assets/img/research/pcb-circuit.webp",
      chip: "Fig. 01 · evidence surface", 
    },
    wht: {
      label: "Mechanism",
      rows: [
        ["01", "Input · shellcode bytes"],
        ["02", "Transform · Walsh-Hadamard"],
        ["03", "Permute · spectral key"],
        ["04", "Output · permuted bytes"],
      ],
      acidRow: null,
      foot: "Full technique note ↗",
      techLabel: "Implementation",
      tech: [["Integer-only", "Butterfly · no S-boxes, no crypto constants, no math library"]],
      img: "assets/img/research/mesh-industrial.webp",
      chip: "Fig. 02 · mechanism surface", 
    },
  };

  function rowHtml(idx, text, acid) {
    var acidCls = acid ? ' fv-acid' : '';
    return '<div class="fv-row' + acidCls + '"><span>' + idx + '</span><b>' + text + '</b></div>';
  }

  function render(key) {
    var v = variants[key] || variants.cve;
    var html = '<div class="fv-label">' + v.label + "</div>";
    v.rows.forEach(function (r) {
      html += rowHtml(r[0], r[1], v.acidRow === r[0]);
    });
    html += '<div class="fv-foot">' + v.foot + "</div>";
    html += '<div class="fv-tech">';
    html += '  <div class="fv-label">' + v.techLabel + "</div>";
    v.tech.forEach(function (t) {
      html += rowHtml(t[0], t[1], false);
    });
    html += "</div>";
    body.innerHTML = html;
    photo.src = v.img;
    chip.textContent = v.chip;
  }

  function keyFor(target) {
    var a = target && target.closest ? target.closest('a[href*="posts/"]') : null;
    if (!a) return "cve";
    if (String(a.getAttribute("href") || "").indexOf("wht-shellcode") !== -1) return "wht";
    return "cve";
  }

  function attach(card) {
    card.addEventListener("mouseenter", function () { render(keyFor(card)); });
    card.addEventListener("mouseleave", function () { render("cve"); });
    card.addEventListener("focusin", function () { render(keyFor(card)); });
    card.addEventListener("focusout", function () { render("cve"); });
  }

  document.querySelectorAll(".post-card").forEach(attach);
})();
