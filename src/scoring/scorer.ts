import { Finding, ScoreReport, ScoreTier, Severity, SeverityOrder } from "../types/index.js";

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

  // 1. İçerik bazlı deduplikasyon: Birebir aynı secret 
  // birden fazla konumda veya kuralda tespit edilirse birleştir (tekil risk havuzu)
  const locationMap = new Map<string, Finding>();
  for (const finding of findings) {
    const dedupKey = finding.secretHash || finding.maskedValue;
    const existing = locationMap.get(dedupKey);
    if (!existing) {
      locationMap.set(dedupKey, finding);
    } else {
      const existingWeight = SeverityOrder[existing.severity] ?? 0;
      const currentWeight = SeverityOrder[finding.severity] ?? 0;
      if (currentWeight > existingWeight) {
        locationMap.set(dedupKey, finding);
      }
    }
  }

  const deduplicatedFindings = Array.from(locationMap.values());

  // 2. Birbirinden farklı (rule + hash olarak) her sızıntı kendi cezasını öder.
  let totalPenalty = 0;

  for (const finding of deduplicatedFindings) {
    counts[finding.severity]++;
    totalPenalty += PENALTIES[finding.severity];
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
