// Renders results/compat.json (the compat binary's output — see
// README.md in this directory for the schema and semantics) as the
// MDN-style support matrix: one table per WIT group, one column per
// target, aspect subrows where targets diverge, and a notes section the
// subrows and feature-gated cells anchor into — divergence notes with
// authoritative sources, and gate-rationale notes per feature. Static
// and dependency-free, like the WPT parity page; served over the
// repository root locally (`just conformance-ct::web`) and on the Pages
// site with the latest main CI run's data.

const status = document.getElementById("status");
const matrix = document.getElementById("matrix");
const notes = document.getElementById("notes");
const provenance = document.getElementById("provenance");

const SYMBOLS = {
  // Row support values.
  yes: { text: "✓", cls: "yes", label: "supported" },
  partial: { text: "◐", cls: "partial", label: "partial — a subrow diverges" },
  no: { text: "✗", cls: "no", label: "not supported" },
  // Feature-gated absences (row and aspect cells alike): the target
  // declares the tagged feature missing — a recorded posture or
  // capability gap, not a divergence from the contract. The feature
  // names beneath the glyph anchor to the gate-rationale notes.
  unsupported: { text: "⊘", cls: "gated", label: "not served — feature gated" },
  absent: { text: "—", cls: "absent", label: "not part of this target's world" },
  "no-data": { text: "·", cls: "nodata", label: "no data in this run" },
};

const noteAnchor = (rowId, aspectId) => `note-${rowId}-${aspectId}`;
const gateAnchor = (feature) => `gate-${feature}`;

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") node.textContent = v;
    else if (v !== undefined) node.setAttribute(k, v);
  }
  for (const child of children) node.append(child);
  return node;
}

function cellNode(cell, column) {
  const state = cell.support ?? cell.state;
  const sym = SYMBOLS[state] ?? { text: state, cls: "nodata", label: state };
  const bits = [el("span", { class: sym.cls, text: sym.text })];
  const titleParts = [`${column.label}: ${sym.label}`];
  if (cell.note) titleParts.push(cell.note);
  if (cell.features?.length) {
    bits.push(
      el(
        "span",
        { class: "feat" },
        cell.features.flatMap((f, i) => [
          i ? " " : "",
          el("a", { href: `#${gateAnchor(f)}`, text: f, title: "why this gate exists" }),
        ]),
      ),
    );
  }
  const td = el("td", { class: column.kind === "implementation" ? "impl" : "" }, bits);
  td.title = titleParts.join("\n");
  return td;
}

function render(data) {
  const columns = data.columns;
  for (const group of data.groups) {
    const section = el("section", {}, [
      el("h2", {}, [el("code", { text: group.id }), ` — ${group.label}`]),
    ]);
    const thead = el("thead", {}, [
      el("tr", {}, [
        el("th", { class: "rowhead", text: "Algorithm" }),
        ...columns.map((c) =>
          el("th", { class: c.kind === "implementation" ? "impl" : "", text: c.label }),
        ),
      ]),
    ]);
    const tbody = el("tbody");
    for (const row of group.rows) {
      const head = el("td", { class: "rowhead" }, [
        `${row.label} `,
        el("code", { text: row.wit.join(", ") }),
      ]);
      tbody.append(
        el("tr", {}, [head, ...columns.map((c) => cellNode(row.cells[c.target] ?? { support: "no-data" }, c))]),
      );
      for (const aspect of row.aspects ?? []) {
        const label = el("a", {
          href: `#${noteAnchor(row.id, aspect.id)}`,
          text: aspect.label,
          title: "what diverges, and the sources",
        });
        tbody.append(
          el("tr", { class: "aspect" }, [
            el("td", { class: "rowhead" }, [label]),
            ...columns.map((c) => cellNode(aspect.cells[c.target] ?? { state: "no-data" }, c)),
          ]),
        );
      }
    }
    section.append(el("table", {}, [thead, tbody]));
    matrix.append(section);
  }

  // The notes the matrix anchors into: divergences first (in matrix
  // order), then the feature gates.
  const divergences = data.groups.flatMap((g) =>
    g.rows.flatMap((row) =>
      (row.aspects ?? []).map((aspect) =>
        el("section", { class: "note", id: noteAnchor(row.id, aspect.id) }, [
          el("h3", {}, [`${row.label} — ${aspect.label}`]),
          el("p", { text: aspect.note }),
          el("ul", {}, aspect.links.map((l) => el("li", {}, [el("a", { href: l.url, text: l.label })]))),
        ]),
      ),
    ),
  );
  if (divergences.length) {
    notes.append(el("h2", { text: "Divergence notes" }), ...divergences);
  }
  if (data.features?.length) {
    notes.append(
      el("h2", { text: "Feature gates" }),
      ...data.features.map((f) =>
        el("section", { class: "note", id: gateAnchor(f.id) }, [
          el("h3", {}, [el("code", { text: f.id })]),
          el("p", { text: f.note }),
          el("ul", {}, f.links.map((l) => el("li", {}, [el("a", { href: l.url, text: l.label })]))),
        ]),
      ),
    );
  }

  const versions = columns
    .filter((c) => c.meta?.version)
    .map((c) => `${c.label}: ${c.meta.version}`);
  provenance.append(
    el("div", {}, [
      "Generated ",
      el("span", { text: data.provenance.generated }),
      data.provenance.commit
        ? el("span", {}, [
            " from ",
            el("a", {
              href: `https://github.com/polymorph-components/polymorph-webcrypto/commit/${data.provenance.commit}`,
              text: data.provenance.commit.slice(0, 12),
            }),
          ])
        : "",
      versions.length ? el("ul", {}, versions.map((v) => el("li", { text: v }))) : "",
      el("div", {
        text:
          "Engine versions are the run's, recorded by each leg; the Rust " +
          "implementations are this repository's at the commit above.",
      }),
    ]),
  );
  provenance.hidden = false;
}

try {
  const res = await fetch("../results/compat.json");
  if (!res.ok) throw new Error(`${res.status}`);
  render(await res.json());
  status.remove();
} catch {
  status.innerHTML =
    "No <code>results/compat.json</code> found. Run " +
    "<code>just conformance-ct::all</code> (any subset of targets) to " +
    "generate one from local results; the published page carries the " +
    "latest main CI run's.";
}
