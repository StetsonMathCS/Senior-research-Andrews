

// Lists what the extension checks from from rules.js, so the popup stays correct as rules are added
const list = document.getElementById("rule-list");
for (const rule of rules) {
  const li = document.createElement("li");
  li.textContent = rule.label;
  list.append(li);
}
