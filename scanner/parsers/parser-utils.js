function asArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function cleanText(value, fallback = "") {
  return String(value || fallback || "").replace(/\s+/g, " ").trim();
}

function normalizeSeverity(value) {
  const raw = String(value || "").toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].includes(raw)) {
    return raw;
  }
  if (["ERROR", "SEVERE"].includes(raw)) return "HIGH";
  if (["WARNING", "WARN", "MODERATE"].includes(raw)) return "MEDIUM";
  if (["NOTE", "INFORMATIONAL", "NEGLIGIBLE"].includes(raw)) return "INFO";
  if (raw === "NONE") return "INFO";
  return "UNKNOWN";
}

function firstLine(value) {
  if (Array.isArray(value)) return Number(value[0]) || 1;
  return Number(value) || 1;
}

module.exports = {
  asArray,
  cleanText,
  firstLine,
  normalizeSeverity
};
