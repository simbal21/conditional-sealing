import type {
  RecipientPolicyReplayInput,
  SimulationSubStepResult,
} from "./types.js";

export function runRecipientPolicyReplay(
  input: RecipientPolicyReplayInput,
): SimulationSubStepResult {
  const thresholdOk =
    input.threshold.k >= 1 && input.threshold.k <= input.threshold.n;
  const modesOk = input.recipients.every(
    (recipient) => recipient.delivery_mode.length > 0,
  );
  return {
    step: "recipient-policy",
    ok: thresholdOk && modesOk,
    details:
      thresholdOk && modesOk
        ? "Conditional-recipient threshold and per-recipient delivery modes replay."
        : "Conditional-recipient threshold or delivery-mode replay failed.",
  };
}
