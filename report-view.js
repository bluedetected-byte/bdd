'use strict';

function text(value, fallback = 'Unknown') {
  if (value === null || value === undefined || value === '') return fallback;
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function summarizeReport(report) {
  const source = report && typeof report === 'object' && !Array.isArray(report) ? report : {};
  const stats = source.stats && typeof source.stats === 'object' ? source.stats : {};
  const coverage = source.fileScanCoverage && typeof source.fileScanCoverage === 'object'
    ? source.fileScanCoverage : {};
  const defender = source.defenderScan && typeof source.defenderScan === 'object' ? source.defenderScan : {};
  const protection = source.protectionStatus && typeof source.protectionStatus === 'object'
    ? source.protectionStatus : {};
  const findings = Array.isArray(source.findings) ? source.findings : [];

  return {
    assessment: text(source.assessment),
    hostname: text(source.hostname),
    operatingSystem: text(source.os),
    scannedAt: text(source.scannedAt),
    defenderStatus: text(defender.status),
    defenderDetections: text(defender.detections, '0'),
    signatureAgeDays: text(protection.signatureAgeDays),
    realTimeProtection: text(protection.realTimeProtectionEnabled),
    tamperProtection: text(protection.tamperProtectionEnabled),
    fileScanComplete: text(coverage.complete),
    filesVisited: text(coverage.filesVisited, text(stats.files, '0')),
    directoriesVisited: text(coverage.directoriesVisited, '0'),
    readErrors: text(coverage.readErrors, '0'),
    skippedDirectories: text(coverage.directoriesSkipped, '0'),
    findings: findings.map((finding) => ({
      severity: text(finding && finding.severity),
      category: text(finding && finding.category),
      reason: text(finding && finding.reason),
      detail: text(finding && finding.detail)
    }))
  };
}

module.exports = { summarizeReport };
