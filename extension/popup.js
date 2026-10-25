

// Lists what the extension checks from from rules.js, so the popup stays correct as rules are added
// Each rule gets a checkbox. Unchecked rules are saved as "disabled" and content.js skips them
const list = document.getElementById("rule-list");

chrome.storage.sync.get({ disabled: [] }, ({ disabled }) => {
  for (const rule of rules) {
    const li = document.createElement("li");
    const label = document.createElement("label");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = !disabled.includes(rule.type);
    box.addEventListener("change", saveChoices);
    box.dataset.type = rule.type;
    label.append(box, " " + rule.label);
    li.append(label);
    list.append(li);
  }
});

function saveChoices() {
  const disabled = [...list.querySelectorAll("input")]
    .filter((box) => !box.checked)
    .map((box) => box.dataset.type);
  chrome.storage.sync.set({ disabled });
}
