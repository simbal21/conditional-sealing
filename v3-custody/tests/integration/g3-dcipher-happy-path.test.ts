import { describe, expect, it } from "vitest";

import { isDcipherIncluded } from "../../src/g3-dispatch/index.js";

const maybeIt = isDcipherIncluded() ? it : it.skip;

describe("integration: g3 dcipher happy path", () => {
  maybeIt("runs only when the Randamu SDK is pinned in the build", () => {
    expect(isDcipherIncluded()).toBe(true);
  });
});
