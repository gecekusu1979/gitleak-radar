export interface IgnoreDirective {
  all: boolean;
  rules: string[];
}

export function parseIgnoreDirective(
  line: string,
  directiveType: "ignore" | "ignore-next-line"
): IgnoreDirective | null {
  // Desteklenen yorum işaretleri: //, #, --, /*, <!--
  const regex = new RegExp(
    `(?:\\/\\/|#|--|\\/\\*|<!--)\\s*gitleak-radar:${directiveType}(?:\\s+(.*?))?(?:-->|\\*\\/|$|#|\\/\\/)`,
    "i"
  );
  const match = regex.exec(line);
  if (!match) return null;

  const rest = match[1]?.trim();
  if (!rest) {
    return { all: true, rules: [] };
  }

  // Köşeli parantez varsa temizle: [rule1, rule2] -> rule1, rule2
  const cleaned = rest.replace(/^\[/, "").replace(/\]$/, "").trim();
  if (!cleaned) {
    return { all: true, rules: [] };
  }

  const rules = cleaned
    .split(/[\s,]+/)
    .map((r) => r.trim())
    .filter(Boolean);

  return {
    all: rules.length === 0,
    rules
  };
}

export function isLineIgnoredByDirective(
  currentLine: string,
  previousLine?: string,
  ruleId?: string
): boolean {
  // 1. Aynı satırdaki ignore kontrolü
  const inlineDirective = parseIgnoreDirective(currentLine, "ignore");
  if (inlineDirective) {
    if (inlineDirective.all) return true;
    if (ruleId && inlineDirective.rules.includes(ruleId)) return true;
  }

  // 2. Bir önceki satırdaki ignore-next-line kontrolü
  if (previousLine) {
    const nextLineDirective = parseIgnoreDirective(previousLine, "ignore-next-line");
    if (nextLineDirective) {
      if (nextLineDirective.all) return true;
      if (ruleId && nextLineDirective.rules.includes(ruleId)) return true;
    }
  }

  return false;
}
