
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
  
  // On hold: research better way to detect 6 digit codes without sending false positives
  // {
  //   type: "code",
  //   label: "6 digit code",
  //   priority: 2,
  //   pattern: /(?<!\d)(?:\d{6,}|\d{3}[ -]\d{3})(?!\d)/g,
  // },
  // Kept last so the more specific rules above win when they match the same text

  {
    type: "password",
    label: "Possible password",
    priority: 1,
    pattern: /(?<!\S)\S{7,63}[^\s.,;](?=[.,;]*(?!\S))/g,
    check: looksLikePassword,
    mask: true,
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

// Words that mean a password is probably coming up
const passwordWords = [
  // full words
  "passwords?", "passcodes?", "passphrases?",          
  // short forms
  "passwd", "passwrd", "pword", "pswd", "psw", "pwd", "pw", 
].join("|");
const passwordKeyword = new RegExp(`^(?:${passwordWords})\\W*$`, "i");
const joinedPassword = new RegExp(`^(?:${passwordWords})[:=](.+)`, "i");

//Counts types of characers (uppercase, lower, num) Returns 0-4
function charKinds(value) {
  let kinds = 0;
  if (/[A-Z]/.test(value)) kinds++;
  if (/[a-z]/.test(value)) kinds++;
  if (/\d/.test(value)) kinds++;
  if (/[^A-Za-z0-9]/.test(value)) kinds++;
  return kinds;
}


// With a keyword in the 3 words before a suspected passsword, only two conditions need to be met
// With no keyword it needs all 4 conditions
function looksLikePassword(value, text, start) {
  if (/@.+\.[A-Za-z]{2,}$/.test(value) || /^(?:https?:\/\/|www\.)/i.test(value)) return false;

  const joined = value.match(joinedPassword);
  if (joined) return charKinds(joined[1]) >= 2;

  const before = text.slice(Math.max(0, start - 80), start).split(/\s+/).filter((word) => /[A-Za-z0-9]/.test(word)).slice(-3);
  const hasKeyword = before.some((word) => passwordKeyword.test(word));
  return charKinds(value) >= (hasKeyword ? 2 : 4);
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
// disabled is a list of rule types to skip, such as ssn or mac
function scan(text, disabled = []) {
  const all = [];
  for (const rule of rules) {
    if (disabled.includes(rule.type)) continue;
    for (const match of text.matchAll(rule.pattern)) {
      if (rule.check && !rule.check(match[0], text, match.index)) continue;
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
