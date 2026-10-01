import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  combineByteLane,
  combineDek,
  gfInv,
  gfMul,
  Shamir,
  type AccessStructureProfile,
  type ShamirErrorCode,
} from "../../src/crypto/shamir.js";
import {
  SHARE_DOMAIN_RECIPIENT_BRANCH,
  SHARE_DOMAIN_TOP_LEVEL,
  SHARE_ROLE_CONDITIONAL_RECIPIENT,
  SHARE_ROLE_G3,
  SHARE_ROLE_G4,
  SHARE_ROLE_LIT,
  SHARE_ROLE_RECIPIENT_AGGREGATE,
  type ShareRecord,
  type ShareRole,
} from "../../src/codecs/share-record.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const positivePath = join(__dirname, "..", "fixtures", "shamir-positive.golden.json");
const negativePath = join(__dirname, "..", "fixtures", "shamir-negative.golden.json");
const shareRecordPath = join(__dirname, "..", "fixtures", "share-record.golden.json");

interface JsonShareRecord {
  share_domain: number;
  share_role: number;
  logical_index: number;
  x: number;
  value: string;
}

type ProfileName = "FIXED_ONLY" | "RECIPIENT_1_OF_1" | "RECIPIENT_K_OF_N";

interface RandomizedCase {
  profile: ProfileName;
  seed: number;
  n_conditional?: number;
  k_conditional?: number;
}

interface PositiveGolden {
  _meta: { comment: string };
  normative_top_level: {
    name: string;
    expected_dek: string;
    records: JsonShareRecord[];
  };
  normative_nested_recipient: {
    name: string;
    expected_aggregate: string;
    records: JsonShareRecord[];
  };
  derived_recipient_top_level: {
    name: string;
    expected_dek: string;
    records: JsonShareRecord[];
  };
  randomized_cases: RandomizedCase[];
}

interface NegativeGolden {
  _meta: { comment: string };
  cases: Array<{
    profile: ProfileName;
    case: "duplicate_x" | "x_zero" | "below_threshold" | "cross_domain_substitution" | "missing_mandatory_top_level";
    expected_error: ShamirErrorCode;
    n_conditional?: number;
    k_conditional?: number;
  }>;
}

interface ShareRecordGolden {
  vectors: Array<{ name: string; record: JsonShareRecord }>;
}

const positive = JSON.parse(readFileSync(positivePath, "utf-8")) as PositiveGolden;
const negative = JSON.parse(readFileSync(negativePath, "utf-8")) as NegativeGolden;
const shareRecordGolden = JSON.parse(readFileSync(shareRecordPath, "utf-8")) as ShareRecordGolden;

function hexBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

function must<T>(value: T | undefined, label: string): T {
  if (value === undefined) throw new Error(`missing ${label}`);
  return value;
}

function recordFromJson(record: JsonShareRecord): ShareRecord {
  return {
    share_domain: record.share_domain as ShareRecord["share_domain"],
    share_role: record.share_role as ShareRecord["share_role"],
    logical_index: record.logical_index,
    x: record.x,
    value: hexBytes(record.value),
  };
}

function cloneRecord(record: ShareRecord): ShareRecord {
  return {
    share_domain: record.share_domain,
    share_role: record.share_role,
    logical_index: record.logical_index,
    x: record.x,
    value: record.value.slice(),
  };
}

function cloneRecords(records: ShareRecord[]): ShareRecord[] {
  return records.map(cloneRecord);
}

function randomSecret(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, lane) => (seed * 17 + lane * 29 + ((seed ^ lane) * 3)) & 0xff);
}

function coefficient(seed: number, lane: number, degree: number): number {
  return (seed * 73 + lane * 41 + degree * 97 + (lane + degree) * (seed | 1)) & 0xff;
}

function splitSecret(secret: Uint8Array, k: number, n: number, seed: number): Uint8Array[] {
  const shares = Array.from({ length: n }, () => new Uint8Array(32));
  for (let lane = 0; lane < 32; lane++) {
    const coeffs = Array.from({ length: k - 1 }, (_, degree) => coefficient(seed, lane, degree + 1));
    for (let x = 1; x <= n; x++) {
      let y = secret[lane] ?? 0;
      let xPower = 1;
      for (const coeff of coeffs) {
        xPower = gfMul(xPower, x);
        y ^= gfMul(coeff, xPower);
      }
      must(shares[x - 1], `share ${x}`)[lane] = y;
    }
  }
  return shares;
}

function topRecord(role: ShareRole, logicalIndex: number, value: Uint8Array): ShareRecord {
  return {
    share_domain: SHARE_DOMAIN_TOP_LEVEL,
    share_role: role,
    logical_index: logicalIndex,
    x: logicalIndex + 1,
    value,
  };
}

function recipientRecord(logicalIndex: number, value: Uint8Array): ShareRecord {
  return {
    share_domain: SHARE_DOMAIN_RECIPIENT_BRANCH,
    share_role: SHARE_ROLE_CONDITIONAL_RECIPIENT,
    logical_index: logicalIndex,
    x: logicalIndex + 1,
    value,
  };
}

function profileFromName(name: ProfileName, n = 3, k = 2): AccessStructureProfile {
  if (name === "FIXED_ONLY") return { kind: "FIXED_ONLY" };
  if (name === "RECIPIENT_1_OF_1") return { kind: "RECIPIENT_1_OF_1" };
  return { kind: "RECIPIENT_K_OF_N", n_conditional: n, k_conditional: k };
}

function materialForProfile(profile: AccessStructureProfile, seed: number): { secret: Uint8Array; records: ShareRecord[] } {
  const secret = randomSecret(seed);
  if (profile.kind === "FIXED_ONLY") {
    const shares = splitSecret(secret, 3, 3, seed);
    return {
      secret,
      records: [
        topRecord(SHARE_ROLE_LIT, 0, must(shares[0], "fixed lit")),
        topRecord(SHARE_ROLE_G3, 1, must(shares[1], "fixed g3")),
        topRecord(SHARE_ROLE_G4, 2, must(shares[2], "fixed g4")),
      ],
    };
  }

  const topShares = splitSecret(secret, 4, 4, seed);
  if (profile.kind === "RECIPIENT_1_OF_1") {
    return {
      secret,
      records: [
        topRecord(SHARE_ROLE_LIT, 0, must(topShares[0], "recipient lit")),
        topRecord(SHARE_ROLE_G3, 1, must(topShares[1], "recipient g3")),
        topRecord(SHARE_ROLE_G4, 2, must(topShares[2], "recipient g4")),
        topRecord(SHARE_ROLE_RECIPIENT_AGGREGATE, 3, must(topShares[3], "recipient aggregate")),
      ],
    };
  }

  const aggregate = must(topShares[3], "nested aggregate");
  const recipientShares = splitSecret(aggregate, profile.k_conditional, profile.n_conditional, seed + 100);
  return {
    secret,
    records: [
      topRecord(SHARE_ROLE_LIT, 0, must(topShares[0], "nested lit")),
      topRecord(SHARE_ROLE_G3, 1, must(topShares[1], "nested g3")),
      topRecord(SHARE_ROLE_G4, 2, must(topShares[2], "nested g4")),
      ...recipientShares.map((value, index) => recipientRecord(index, value)),
    ],
  };
}

function profileKey(profile: AccessStructureProfile): ProfileName {
  return profile.kind;
}

function expectCombineOk(records: ShareRecord[], profile: AccessStructureProfile, expectedHex: string): void {
  const result = combineDek(records, profile);
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error(`expected ok, got ${result.error}`);
  expect(bytesToHex(result.dek)).toBe(expectedHex);
  expect(bytesToHex(Shamir.combine(records, profile))).toBe(expectedHex);
}

function malformedCrossDomainRecord(): ShareRecord {
  return {
    share_domain: SHARE_DOMAIN_TOP_LEVEL,
    share_role: SHARE_ROLE_CONDITIONAL_RECIPIENT,
    logical_index: 0,
    x: 1,
    value: new Uint8Array(32),
  } as ShareRecord;
}

function negativeRecordsFor(
  profile: AccessStructureProfile,
  caseName: NegativeGolden["cases"][number]["case"],
): ShareRecord[] {
  const base = materialForProfile(profile, 77);
  const records = cloneRecords(base.records);

  switch (caseName) {
    case "duplicate_x":
      return [cloneRecord(must(records[0], "duplicate base")), cloneRecord(must(records[0], "duplicate copy")), ...records.slice(1)];
    case "x_zero": {
      const bad = cloneRecords(records);
      must(bad[0], "x zero target").x = 0;
      return bad;
    }
    case "below_threshold":
      if (profile.kind === "FIXED_ONLY") return records.slice(0, 2);
      if (profile.kind === "RECIPIENT_1_OF_1") return records.slice(0, 3);
      return records
        .filter((record) => record.share_domain === SHARE_DOMAIN_TOP_LEVEL)
        .concat(records.filter((record) => record.share_domain === SHARE_DOMAIN_RECIPIENT_BRANCH).slice(0, profile.k_conditional - 1));
    case "cross_domain_substitution":
      return [malformedCrossDomainRecord()];
    case "missing_mandatory_top_level":
      if (profile.kind === "RECIPIENT_K_OF_N") {
        return records.filter((record) => !(record.share_domain === SHARE_DOMAIN_TOP_LEVEL && record.share_role === SHARE_ROLE_G4));
      }
      return materialForProfile({ kind: "RECIPIENT_1_OF_1" }, 78).records.filter(
        (record) => record.share_role !== SHARE_ROLE_LIT,
      );
  }
}

describe("Shamir GF(2^8) field ops — §6.3.3", () => {
  it("uses the AES 0x11b field multiplication identity vector", () => {
    expect(gfMul(0x57, 0x83)).toBe(0xc1);
  });

  it("inverts non-zero bytes in GF(2^8)", () => {
    for (const value of [1, 2, 3, 4, 0x53, 0xca, 0xff]) {
      expect(gfMul(value, gfInv(value))).toBe(1);
    }
  });
});

describe("Shamir positive vectors — typed access structures", () => {
  it("goldens are marked as locked Phase D seeds", () => {
    expect(positive._meta.comment).toContain("LOCKED — Phase D seed");
  });

  it("Phase D TOP_LEVEL and RECIPIENT_BRANCH values match Phase A share-record goldens byte-for-byte", () => {
    const byName = new Map(shareRecordGolden.vectors.map((vector) => [vector.name, vector.record.value]));
    expect(positive.normative_top_level.records[0]?.value).toBe(byName.get("top_level_lit"));
    expect(positive.normative_top_level.records[1]?.value).toBe(byName.get("top_level_g3"));
    expect(positive.normative_top_level.records[2]?.value).toBe(byName.get("top_level_g4"));
    expect(positive.normative_nested_recipient.records[0]?.value).toBe(byName.get("recipient_branch_first"));
    expect(positive.normative_nested_recipient.records[1]?.value).toBe(byName.get("recipient_branch_second"));
  });

  it("§6.3.4 top-level k=3 vector reconstructs the DEK", () => {
    expectCombineOk(
      positive.normative_top_level.records.map(recordFromJson),
      { kind: "FIXED_ONLY" },
      positive.normative_top_level.expected_dek,
    );
  });

  it("§6.3.4 nested-recipient k=2 vector reconstructs the recipient aggregate", () => {
    const records = positive.normative_nested_recipient.records.slice(0, 2).map(recordFromJson);
    const out = new Uint8Array(32);
    for (let lane = 0; lane < 32; lane++) {
      out[lane] = combineByteLane(records.map((record) => ({ x: record.x, y: record.value[lane] ?? 0 })));
    }
    expect(bytesToHex(out)).toBe(positive.normative_nested_recipient.expected_aggregate);
  });

  it("runs exactly 5 positive combine vectors per profile", () => {
    const derivedTop = positive.derived_recipient_top_level.records.map(recordFromJson);
    const derivedK = [
      ...positive.derived_recipient_top_level.records.slice(0, 3).map(recordFromJson),
      ...positive.normative_nested_recipient.records.map(recordFromJson),
    ];
    const cases: Array<{ name: string; profile: AccessStructureProfile; records: ShareRecord[]; expected: string }> = [
      {
        name: positive.normative_top_level.name,
        profile: { kind: "FIXED_ONLY" },
        records: positive.normative_top_level.records.map(recordFromJson),
        expected: positive.normative_top_level.expected_dek,
      },
      {
        name: `${positive.derived_recipient_top_level.name}_1_of_1`,
        profile: { kind: "RECIPIENT_1_OF_1" },
        records: derivedTop,
        expected: positive.derived_recipient_top_level.expected_dek,
      },
      {
        name: `${positive.normative_nested_recipient.name}_full_profile`,
        profile: { kind: "RECIPIENT_K_OF_N", n_conditional: 3, k_conditional: 2 },
        records: derivedK,
        expected: positive.derived_recipient_top_level.expected_dek,
      },
      ...positive.randomized_cases.map((testCase) => {
        const profile = profileFromName(testCase.profile, testCase.n_conditional, testCase.k_conditional);
        const material = materialForProfile(profile, testCase.seed);
        return {
          name: `${testCase.profile}_${testCase.seed}`,
          profile,
          records: material.records,
          expected: bytesToHex(material.secret),
        };
      }),
    ];

    const profileCounts = new Map<ProfileName, number>();
    for (const testCase of cases) {
      expectCombineOk(testCase.records, testCase.profile, testCase.expected);
      profileCounts.set(profileKey(testCase.profile), (profileCounts.get(profileKey(testCase.profile)) ?? 0) + 1);
    }
    expect(Object.fromEntries(profileCounts)).toEqual({
      FIXED_ONLY: 5,
      RECIPIENT_1_OF_1: 5,
      RECIPIENT_K_OF_N: 5,
    });
  });
});

describe("Shamir negative vectors — IB-2 mandatory-branch enforcement", () => {
  it("goldens are marked as locked Phase D seeds", () => {
    expect(negative._meta.comment).toContain("LOCKED — Phase D seed");
  });

  it("runs exactly 5 negative cases per profile with typed errors", () => {
    const profileCounts = new Map<ProfileName, number>();
    for (const testCase of negative.cases) {
      const profile = profileFromName(testCase.profile, testCase.n_conditional, testCase.k_conditional);
      const result = combineDek(negativeRecordsFor(profile, testCase.case), profile);
      expect(result).toEqual({ ok: false, error: testCase.expected_error });
      profileCounts.set(testCase.profile, (profileCounts.get(testCase.profile) ?? 0) + 1);
    }
    expect(Object.fromEntries(profileCounts)).toEqual({
      FIXED_ONLY: 5,
      RECIPIENT_1_OF_1: 5,
      RECIPIENT_K_OF_N: 5,
    });
  });

  it("rejects surplus recipient shares substituting for missing G4 in RECIPIENT_K_OF_N", () => {
    const profile: AccessStructureProfile = { kind: "RECIPIENT_K_OF_N", n_conditional: 5, k_conditional: 3 };
    const records = materialForProfile(profile, 88).records.filter(
      (record) => !(record.share_domain === SHARE_DOMAIN_TOP_LEVEL && record.share_role === SHARE_ROLE_G4),
    );
    expect(combineDek(records, profile)).toEqual({
      ok: false,
      error: "ERR_TOP_LEVEL_MANDATORY_BRANCH_ABSENT",
    });
  });

  it("documents the bit-flip boundary: tampered shares combine to a different key; AEAD detects it later", () => {
    const profile: AccessStructureProfile = { kind: "FIXED_ONLY" };
    const material = materialForProfile(profile, 99);
    const tampered = cloneRecords(material.records);
    must(tampered[0], "tampered share").value[0]! ^= 0x01;

    const result = combineDek(tampered, profile);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error(`expected ok, got ${result.error}`);
    expect(bytesToHex(result.dek)).not.toBe(bytesToHex(material.secret));
  });
});
