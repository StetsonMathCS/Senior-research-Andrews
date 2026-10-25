// Runs on Claude, Chat GPT, Grok, Gemini. Uses scan() from rules.js, which loads first


// While typing, sensitive text is highlighted and a small badge shows a count
// Clicking the badge opens a list of what was found

const BOX_SELECTOR = '#prompt-textarea, .ProseMirror[contenteditable="true"], .ql-editor[contenteditable="true"]';

let found = [];        // what the last scan found
let lastText = null;   // skip rescanning when nothing changed
let disabled = [];     // rule types turned off in the popup

// ---------- Page elements ----------

const highlights = {
  1: new Highlight(),
  2: new Highlight(),
  3: new Highlight(),
};
CSS.highlights.set("sic-p1", highlights[1]);
CSS.highlights.set("sic-p2", highlights[2]);
CSS.highlights.set("sic-p3", highlights[3]);


const badge = document.createElement("button");
badge.className = "sic-badge";
badge.hidden = true;
badge.addEventListener("click", () => {
  panel.hidden = !panel.hidden;
  fillPanel();
});

const panel = document.createElement("div");
panel.className = "sic-panel";
panel.hidden = true;
panel.innerHTML = `
  <strong>Sensitive info in your message</strong>
  <ul class="sic-list"></ul>`;

document.body.append(badge, panel);

// ---------- Scanning ----------

// Scans each text node in the chat box once. That single pass gives both the list of findings and the exact ranges to highlight
// Known limit that a match split across two text nodes
function check() {
  const box = document.querySelector(BOX_SELECTOR);
  const text = box ? box.innerText : "";
  if (text === lastText) return;
  lastText = text;

  highlights[1].clear();
  highlights[2].clear();
  highlights[3].clear();
  found = [];
  if (box) {
    const walker = document.createTreeWalker(box, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      for (const item of scan(node.textContent, disabled)) {
        const range = new Range();
        range.setStart(node, item.start);
        range.setEnd(node, item.end);
        highlights[item.priority].add(range);
        found.push(item);
      }
    }
  }

  badge.hidden = found.length === 0;
  badge.textContent = `⚠ ${found.length} sensitive item${found.length === 1 ? "" : "s"}`;
  if (found.length === 0) panel.hidden = true;
  fillPanel();
}

// ---------- List of findings ----------

// Shows only the last 4 characters of values in card numbers and SSNs for example
function display(item) {
  if (!item.mask) return item.value;
  return "•••• " + item.value.slice(-4);
}

function fillPanel() {
  const list = panel.querySelector(".sic-list");
  list.textContent = "";
  for (const item of found) {
    const li = document.createElement("li");
    li.textContent = `${item.label}: ${display(item)}`;
    list.append(li);
  }
}

// ---------- Keeping the scan current ----------

document.addEventListener("input", check, true);
// Catches changes that don't fire "input", like a paste from clipboard
setInterval(check, 1000);

chrome.storage.sync.get({ disabled: [] }, (saved) => {
  disabled = saved.disabled;
  check();
});
chrome.storage.onChanged.addListener((changes) => {
  if (!changes.disabled) return;
  disabled = changes.disabled.newValue || [];
  lastText = null;
  check();
});
