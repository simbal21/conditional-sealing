import { CF_BY_ID } from "../../types/cf-codes.js";
import { createCfFailure } from "./failure.js";
import {
  archetypeFloor,
  eligibleChallengersContainSubject,
  hasTierBorCRelevantReveal,
  minimumShredLatency,
  requiredCfDescriptor,
  revealChallengeWindow,
} from "./helpers.js";
import type { CrossFieldValidationContext } from "./types.js";

const CF_01 = CF_BY_ID.get("CF-01");

export function validateCf01(context: CrossFieldValidationContext) {
  const descriptor = requiredCfDescriptor(CF_01, "CF-01");
  const { pda } = context;
  if (pda.legal_effect_expected !== true) return [];

  const failures = [];
  const revealWindow = revealChallengeWindow(pda);
  const floor = archetypeFloor(pda);
  const tierBorC = hasTierBorCRelevantReveal(pda);

  if (tierBorC && revealWindow < floor) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "reveal_challenge_window",
        code: "ART22_CHALLENGE_WINDOW_BELOW_FLOOR",
        failed_predicate: "reveal_challenge_window >= archetype_floor",
        source_field_path: "reveal_challenge_window_seconds",
        sanitized_value_class: "duration_below_archetype_floor",
        partner_friendly_field_label: "Reveal challenge window",
        why_failed:
          "This deployment uses a third-party oracle, so it needs a challenge window at or above the archetype floor.",
        partner_action_text:
          "Raise the reveal challenge window to the archetype floor.",
      }),
    );
  }

  if (!tierBorC && revealWindow !== 0n) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "reveal_challenge_window",
        code: "TIER_A_CHALLENGE_WINDOW_NONZERO",
        failed_predicate:
          "Tier A legal-effect PDA has reveal_challenge_window == 0",
        source_field_path: "reveal_challenge_window_seconds",
        sanitized_value_class: "duration_nonzero",
        partner_friendly_field_label: "Reveal challenge window",
        why_failed:
          "This chain-native legal-effect deployment relies on deterministic pre-commit consent, so the reveal challenge window must be zero.",
        partner_action_text: "Set the Tier A reveal challenge window to zero.",
      }),
    );
  }

  if (
    tierBorC &&
    !["human_endpoint", "judicial_address"].includes(
      pda.ceremony_resolver?.type ?? "",
    )
  ) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "ceremony_resolver",
        code: "ART22_RESOLVER_NOT_HUMAN_OR_JUDICIAL",
        failed_predicate:
          "ceremony_resolver.type in {human_endpoint, judicial_address}",
        source_field_path: "ceremony_resolver.type",
        sanitized_value_class: "resolver_type_not_art22_allowed",
        partner_friendly_field_label: "Ceremony resolver",
        why_failed:
          "This legal-effect deployment needs a human or judicial resolver on the reveal side.",
        partner_action_text:
          "Choose a human endpoint or judicial address resolver.",
      }),
    );
  }

  if (tierBorC && !eligibleChallengersContainSubject(pda)) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "eligible_challengers_reveal",
        code: "ART22_SUBJECT_NOT_ELIGIBLE_CHALLENGER",
        failed_predicate: "subject is in eligible_challengers_reveal",
        source_field_path: "eligible_challengers_reveal",
        sanitized_value_class: "subject_role_missing",
        partner_friendly_field_label: "Reveal challenger set",
        why_failed:
          "This legal-effect deployment must let the subject challenge the reveal path.",
        partner_action_text: "Add the subject to the reveal challenger set.",
      }),
    );
  }

  if (tierBorC && minimumShredLatency(pda) < floor) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "minimum_shred_latency",
        code: "ART22_MINIMUM_SHRED_LATENCY_BELOW_FLOOR",
        failed_predicate: "minimum_shred_latency >= archetype_floor",
        source_field_path: "minimum_shred_latency_seconds",
        sanitized_value_class: "duration_below_archetype_floor",
        partner_friendly_field_label: "Minimum shred latency",
        why_failed:
          "This legal-effect deployment needs enough shred latency for the challenge path to remain meaningful.",
        partner_action_text:
          "Raise minimum shred latency to the archetype floor.",
      }),
    );
  }

  if (tierBorC && pda.cealis_class_wide_halt_opt_out === true) {
    failures.push(
      createCfFailure({
        descriptor,
        surface_name: "cealis_class_wide_halt_opt_out",
        code: "ART22_HALT_OPT_OUT_TRUE",
        failed_predicate: "cealis_class_wide_halt_opt_out = false",
        source_field_path: "cealis_class_wide_halt_opt_out",
        sanitized_value_class: "boolean_true",
        partner_friendly_field_label: "Cealis halt opt-out",
        why_failed:
          "This legal-effect deployment cannot opt out of Cealis's class-wide halt safety path.",
        partner_action_text: "Set class-wide halt opt-out to false.",
      }),
    );
  }

  return failures;
}
