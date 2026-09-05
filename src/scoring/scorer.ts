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

  // 1. Konum bazlı deduplikasyon: Aynı dosya, satır, sütun ve committe
  // birden fazla kural tetiklenirse en yüksek ciddiyeti (severity) seç
  const locationMap = new Map<string, Finding>();
  for (const finding of findings) {
    const locKey = `${finding.file}:${finding.line}:${finding.column}:${finding.commit ?? ""}`;
    const existing = locationMap.get(locKey);
    if (!existing) {
      locationMap.set(locKey, finding);
    } else {
      const existingWeight = SeverityOrder[existing.severity] ?? 0;
      const currentWeight = SeverityOrder[finding.severity] ?? 0;
      if (currentWeight > existingWeight) {
        locationMap.set(locKey, finding);
      }
    }
  }

  const deduplicatedFindings = Array.from(locationMap.values());

  // 2. Fiziksel olarak farklı konumdaki her gerçek sızıntı kendi cezasını öder.
  // ruleId::file tavanı kaldırıldı; farklı satırlardaki sızıntılar skoru düşürür.
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
