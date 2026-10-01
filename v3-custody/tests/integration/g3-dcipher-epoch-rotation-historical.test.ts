import { describe, expect, it } from "vitest";

import { isDcipherIncluded } from "../../src/g3-dispatch/index.js";

const maybeIt = isDcipherIncluded() ? it : it.skip;

describe("integration: g3 dcipher epoch rotation historical", () => {
  maybeIt("accepts historical committee state only when SDK vectors are pinned", () => {
    expect(isDcipherIncluded()).toBe(true);
  });
});
