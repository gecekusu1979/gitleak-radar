import { Finding, ScoreReport, ScoreTier, Severity } from "../types/index.js";

const PENALTIES: Record<Severity, number> = {
  critical: 35,
  high: 20,
  medium: 10,
  low: 5
};

export function calculateSecurityScore(findings: Finding[]): ScoreReport {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  let totalPenalty = 0;
  const uniquePenaltyKeys = new Set<string>();

  for (const finding of findings) {
    counts[finding.severity]++;

    const key = `${finding.ruleId}::${finding.file}`;
    if (!uniquePenaltyKeys.has(key)) {
      uniquePenaltyKeys.add(key);
      totalPenalty += PENALTIES[finding.severity];
    }
  }

  const score = Math.max(0, 100 - totalPenalty);
  let tier: ScoreTier = "Critical";

  if (score >= 90) {
    tier = "Excellent";
  } else if (score >= 75) {
    tier = "Good";
  } else if (score >= 50) {
    tier = "Warning";
  }

  return {
    score,
    tier,
    counts
  };
}
