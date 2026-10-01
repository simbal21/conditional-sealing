import { describe, expect, it } from "vitest";
import {
  areSignalHandlersInstalled,
  combineAndDecrypt,
  setNetworkEgressForTest,
} from "../../src/combiner/index.js";
import { CUSTODY_ERROR_CODES } from "../../src/index.js";
import { makeFixture } from "./combiner-testkit.js";

describe("combiner runtime hardening", () => {
  it("disables crash dump directory and installs signal handlers before sigma work", () => {
    const result = combineAndDecrypt(makeFixture());
    expect(result.ok).toBe(true);
    expect(process.report?.directory ?? "").toBe("");
    expect(areSignalHandlersInstalled()).toBe(true);
  });

  it("fails closed when debug, egress, or IPC hooks are active", () => {
    const priorDebug = process.env.CEALIS_COMBINER_DEBUG;
    process.env.CEALIS_COMBINER_DEBUG = "1";
    try {
      const result = combineAndDecrypt(makeFixture());
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SIGMA_REDACTION_BREACH);
    } finally {
      if (priorDebug === undefined) delete process.env.CEALIS_COMBINER_DEBUG;
      else process.env.CEALIS_COMBINER_DEBUG = priorDebug;
    }

    setNetworkEgressForTest(true);
    try {
      const result = combineAndDecrypt(makeFixture());
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SIGMA_REDACTION_BREACH);
    } finally {
      setNetworkEgressForTest(false);
    }

    const priorIpc = process.env.CEALIS_COMBINER_IPC_ACTIVE;
    process.env.CEALIS_COMBINER_IPC_ACTIVE = "1";
    try {
      const result = combineAndDecrypt(makeFixture());
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe(CUSTODY_ERROR_CODES.CUSTODY_ERR_SIGMA_REDACTION_BREACH);
    } finally {
      if (priorIpc === undefined) delete process.env.CEALIS_COMBINER_IPC_ACTIVE;
      else process.env.CEALIS_COMBINER_IPC_ACTIVE = priorIpc;
    }
  });
});
