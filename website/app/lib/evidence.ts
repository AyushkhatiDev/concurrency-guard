export type NumericClaim = {
  label: string;
  value: string;
  source: "recorded" | "simulation";
  command?: string;
  capturedAt: string;
};

export const recordedWalletScan = {
  packageVersion: "2.1.0",
  command: "cguard scan examples/vulnerable_wallet.py --format json",
  capturedAt: "2026-11-03",
  scannedFiles: 1,
  elapsedMs: "7.83",
  findingsCount: 2,
  findings: [
    { ruleId: "CG-001", line: 51, functionName: "withdraw" },
    { ruleId: "CG-002", line: 46, functionName: "withdraw" },
  ],
} as const;

export const numericClaims: NumericClaim[] = [
  { label: "Documented rules", value: "16", source: "recorded", capturedAt: "2026-11-03" },
  { label: "Network calls required", value: "0", source: "recorded", capturedAt: "2026-11-03" },
  { label: "Files scanned", value: "1", source: "recorded", command: recordedWalletScan.command, capturedAt: recordedWalletScan.capturedAt },
  { label: "Findings", value: "2", source: "recorded", command: recordedWalletScan.command, capturedAt: recordedWalletScan.capturedAt },
  { label: "Scan elapsed", value: "7.83 ms", source: "recorded", command: recordedWalletScan.command, capturedAt: recordedWalletScan.capturedAt },
  { label: "Timeline state", value: "illustrative", source: "simulation", capturedAt: "2026-11-03" },
];
