import {
  SUB_CLASS_METADATA,
  type GovernanceMetadata,
} from "../types/governance-metadata.js";
import type { SubClass } from "../types/categories.js";

export interface GovernanceMetadataEvent {
  readonly sub_class: 1 | 2 | 3 | 4 | 5;
  readonly metadata: GovernanceMetadata;
  readonly surface: string;
  readonly operation: string;
}

export function emitGovernanceMetadata(
  sub_class: SubClass,
  surface: string,
  operation: string,
): GovernanceMetadataEvent {
  if (typeof sub_class !== "number") {
    throw new Error(
      `emitGovernanceMetadata: composite or N/A sub-class ${String(sub_class)} cannot emit a single §6.8 row`,
    );
  }
  const metadata = SUB_CLASS_METADATA.get(sub_class);
  if (metadata === undefined) {
    throw new Error(
      `emitGovernanceMetadata: missing §6.8 metadata for sub-class ${String(sub_class)}`,
    );
  }
  return { sub_class, metadata, surface, operation };
}

export function emitAllGovernanceMetadata(): readonly GovernanceMetadataEvent[] {
  return ([1, 2, 3, 4, 5] as const).map((sub_class) =>
    emitGovernanceMetadata(
      sub_class,
      `sub_class_${String(sub_class)}`,
      "metadata_interface",
    ),
  );
}
