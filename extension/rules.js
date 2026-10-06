const emailPattern = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

function scan(text) {
    const found = [];
    for (const match of text.matchAll(emailPattern)) {
        found.push({ type: "email", value: match[0], start: match.index });
    }
    return found;
}
