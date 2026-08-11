// Renders results/compat.json (the compat binary's output — see
// README.md in this directory for the schema and semantics) as the
// MDN-style support matrix: one table per WIT group, one column per
// target, aspect subrows where targets diverge. Static and
// dependency-free, like the WPT parity page; served over the repository
// root locally (`just conformance-ct::web`) and on the Pages site with
// the latest main CI run's data.

const status = document.getElementById("status");
const matrix = document.getElementById("matrix");
const provenance = document.getElementById("provenance");

const SYMBOLS = {
  // Row support values.
  yes: { text: "✓", cls: "yes", label: "supported" },
  partial: { text: "◐", cls: "partial", label: "partial — a subrow diverges" },
  no: { text: "✗", cls: "no", label: "not supported" },
  absent: { text: "—", cls: "absent", label: "not part of this target's world" },
  "no-data": { text: "·", cls: "nodata", label: "no data in this run" },
  // Aspect cell states.
  unsupported: { text: "✗", cls: "no", label: "not supported" },
};

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
  const bits = [];
  const titleParts = [`${column.label}: ${sym.label}`];
  if (cell.features?.length) titleParts.push(`feature: ${cell.features.join(", ")}`);
  if (cell.note) titleParts.push(cell.note);
  let symbol = el("span", { class: sym.cls, text: sym.text });
  if (cell.tracking?.length) {
    titleParts.push(cell.tracking.join("\n"));
    symbol = el("a", { href: cell.tracking[0], title: "" }, [symbol]);
  }
  bits.push(symbol);
  if (cell.features?.length) {
    bits.push(el("span", { class: "feat", text: cell.features.join(" ") }));
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
        const label = aspect.tracking
          ? el("a", { href: aspect.tracking, text: aspect.label })
          : aspect.label;
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
