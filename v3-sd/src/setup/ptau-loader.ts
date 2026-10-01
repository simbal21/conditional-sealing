export interface PtauSelection {
  readonly fileName: string;
  readonly source: "pinned-hermez" | "local-dev-generated";
  readonly sha256: string;
  readonly path: string;
  readonly verifiedAt: string;
  readonly warning?: string;
}
