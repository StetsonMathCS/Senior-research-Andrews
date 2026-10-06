const labels = { email: "Email address" };

const warning = document.createElement("div");
warning.style.position = "fixed";
warning.style.bottom = "120px";
warning.style.right = "20px";
warning.style.maxWidth = "320px";
warning.style.padding = "12px 16px";
warning.style.background = "#fff3cd";
warning.style.color = "#664d03";
warning.style.border = "1px solid #ffda6a";
warning.style.borderRadius = "8px";
warning.style.fontSize = "14px";
warning.style.zIndex = "999999";
warning.style.display = "none";
document.body.appendChild(warning);

const highlight = new Highlight();
CSS.highlights.set("sensitive-info", highlight);

const highlightStyle = document.createElement("style");
highlightStyle.textContent = "::highlight(sensitive-info) { background-color: #ffda6a; color: black; }";
document.head.appendChild(highlightStyle);

function check() {
  const box = document.querySelector(".ProseMirror");
  highlight.clear();

  if (!box) {
    warning.style.display = "none";
    return;
  }

  const found = scan(box.innerText);
  if (found.length === 0) {
    warning.style.display = "none";
    return;
  }

  // Rebuild the warning box: a heading, then one line per detection.
  warning.textContent = "";
  const heading = document.createElement("strong");
  heading.textContent = "Sensitive info detected. Are you sure you want to share this with an AI chatbot?";
  warning.appendChild(heading);

  const list = document.createElement("ul");
  list.style.margin = "8px 0 0";
  list.style.paddingLeft = "20px";
  for (const item of found) {
    const line = document.createElement("li");
    line.textContent = (labels[item.type] || item.type) + ": " + item.value;
    list.appendChild(line);
  }
  warning.appendChild(list);
  warning.style.display = "block";

  // Highlight matches inside the chat box without changing its contents.
  const walker = document.createTreeWalker(box, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    for (const item of scan(node.textContent)) {
      const range = new Range();
      range.setStart(node, item.start);
      range.setEnd(node, item.start + item.value.length);
      highlight.add(range);
    }
  }
}

document.addEventListener("input", check);
setInterval(check, 500);
