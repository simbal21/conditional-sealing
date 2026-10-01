import { CI_BY_ID } from "../../types/ci-codes.js";
import type { DualFormValidationFailure } from "../../errors/index.js";
import { deepStringIncludes, makeCiFailure, recordValue } from "./ci-01.js";
import type { SubmittedPda } from "./dispatcher.js";

const DESCRIPTOR = CI_BY_ID.get("CI-08")!; // verbatim spec anchor

export function checkCi08(pda: SubmittedPda): DualFormValidationFailure | null {
  const sdPlan = recordValue(pda["sd_plan"]);
  const crossesPipelines =
    (sdPlan !== null && sdPlan["failure_blocks_escrow"] === true) ||
    deepStringIncludes(sdPlan, [/custody[_ -]?sigma/i, /reveal[_ -]?time[_ -]?plaintext/i]);
  if (!crossesPipelines) return null;
  return makeCiFailure({
    descriptor: DESCRIPTOR,
    surface_name: "sd_failure_does_not_block_escrow",
    code: "SD_ESCROW_PIPELINE_CROSSED",
    source_field_path: "sd_plan",
    failed_predicate: "SD plan neither reads custody sigma nor blocks escrow sealing",
    sanitized_value_class: "sd_pipeline_crossing",
    cross_references: "S2-7 §12 SD isolation; S2-4 §4.3 CI-08",
    why_failed:
      "This SD plan crosses into the escrow pipeline; Cealis requires SD failure and escrow sealing to stay isolated.",
    partner_action_text: "Keep SD outputs parallel to escrow and remove reveal-time plaintext or custody-sigma dependencies.",
  });
}
