// Renders ```mermaid blocks with a pinned Mermaid version. Rendering runs on
// Material's document$ event, so it also covers instant navigation, and again
// when the reader switches light/dark mode.
import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.esm.min.mjs";

let count = 0;

async function render() {
  const blocks = [...document.querySelectorAll(".diagram")];
  if (!blocks.length) return;
  const dark = document.body.getAttribute("data-md-color-scheme") === "slate";
  mermaid.initialize({
    startOnLoad: false,
    theme: dark ? "dark" : "default",
    fontFamily: "Roboto, Helvetica, Arial, sans-serif",
    sequence: { mirrorActors: false, actorMargin: 60, messageMargin: 34, boxMargin: 8, noteMargin: 10, useMaxWidth: true },
  });
  for (const block of blocks) {
    if (!block.dataset.source) block.dataset.source = block.textContent;
    const { svg } = await mermaid.render(`diagram-${count++}`, block.dataset.source);
    block.innerHTML = svg;
  }
}

if (window.document$) window.document$.subscribe(() => render());
else render();
new MutationObserver(render).observe(document.body, { attributes: true, attributeFilter: ["data-md-color-scheme"] });
