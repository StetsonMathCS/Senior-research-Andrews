
// Detection rules shared by the extension and the evaluation scripts
// No DOM code in this file, so it also runs in Node


// Each rule is one kind of sensitive info:
//   type    short id used in results and evaluation
//   label   readable name shown to the user
//   pattern regex with the /g flag
//   mask    true if the warning should hide most of the value on screen


// (?<!\d) and (?!\d) mean "no digit right before / right after", so a
// pattern can't match a slice out of the middle of a longer number

const rules = [
  {
    type: "card",
    label: "Credit card number",
    priority: 1,
    pattern: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
    check: passesLuhn,
    mask: true,
  },
  {
    type: "ssn",
    label: "Social Security number",
    priority: 1,
    pattern: /(?<!\d)(?!000|666|9\d\d)\d{3}([- ])(?!00)\d{2}\1(?!0000)\d{4}(?!\d)/g,
    mask: true,
  },
  {
    type: "apikey",
    label: "API key or token",
    priority: 1,
    pattern: /\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,})/g,
    mask: true,
  },
  {
    type: "email",
    label: "Email address",
    priority: 3,
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  },
  {
    type: "phone",
    label: "Phone number",
    priority: 2,
    pattern: /(?<![\d+])(?:\+?1[-. ]?)?(?:\(\d{3}\)|\d{3})[-. ]?\d{3}[-. ]?\d{4}(?!\d)/g,
  },
  {
    type: "ip",
    label: "IP Address",
    priority: 2,
    pattern: /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)/g,
    check: validIP,
  

  },
  {
    type: "mac",
    label: "MAC address",
    priority: 2,
    pattern: /(?<![0-9a-f:-])[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}(?![:-]?[0-9a-f])/gi,
  },

];

// Function to check for valid IP addresses
function validIP(value){
  const parts = value.split(".");
  for (const part of parts) {
    if (part.length > 1 && part[0] === "0") return false;
    if (Number(part) > 255) return false;
  }
  return true;
}
// Luhn checksum for verifying cards
function passesLuhn(value) {
  const digits = value.replace(/\D/g, "");
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

// Runs every rule over the text and returns what was found, in text order
function scan(text) {
  const all = [];
  for (const rule of rules) {
    for (const match of text.matchAll(rule.pattern)) {
      if (rule.check && !rule.check(match[0])) continue;
      all.push({
        type: rule.type,
        label: rule.label,
        priority: rule.priority,
        mask: Boolean(rule.mask),
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }

  all.sort((a, b) => a.start - b.start || b.end - a.end);
  const found = [];
  for (const item of all) {
    const last = found[found.length - 1];
    if (!last || item.start >= last.end) found.push(item);
  }
  return found;
}

// Lets the evaluation scripts load this file in Node
if (typeof module !== "undefined") {
  module.exports = { rules, scan, passesLuhn };
}
