import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { getMode, getTimelockDelay, getChainConfig, DEMO_MODES } from "../../src/setup.js";
import { DemoError, DEMO_ERR_CODES, isDemoError } from "../../src/errors/index.js";

describe("setup mode-switch", () => {
  let priorMode: string | undefined;
  let priorRpc: string | undefined;

  beforeEach(() => {
    priorMode = process.env.DEMO_MODE;
    priorRpc = process.env.BASE_SEPOLIA_RPC_URL;
    delete process.env.DEMO_MODE;
    delete process.env.BASE_SEPOLIA_RPC_URL;
  });

  afterEach(() => {
    if (priorMode !== undefined) process.env.DEMO_MODE = priorMode;
    else delete process.env.DEMO_MODE;
    if (priorRpc !== undefined) process.env.BASE_SEPOLIA_RPC_URL = priorRpc;
    else delete process.env.BASE_SEPOLIA_RPC_URL;
  });

  it("DEMO_MODES enumerates exactly ['ci-anvil', 'live-base-sepolia']", () => {
    expect(DEMO_MODES).toEqual(["ci-anvil", "live-base-sepolia"]);
  });

  it("getMode() throws DemoError when DEMO_MODE unset", () => {
    let caught: unknown = null;
    try {
      getMode();
    } catch (err) {
      caught = err;
    }
    expect(isDemoError(caught)).toBe(true);
    expect((caught as DemoError).code).toBe(DEMO_ERR_CODES.DEMO_ERR_INFRA_DOWN);
    expect((caught as DemoError).safeRefs.envVar).toBe("DEMO_MODE");
  });

  it("getMode() returns 'ci-anvil' when DEMO_MODE=ci-anvil", () => {
    process.env.DEMO_MODE = "ci-anvil";
    expect(getMode()).toBe("ci-anvil");
  });

  it("getMode() returns 'live-base-sepolia' when DEMO_MODE=live-base-sepolia", () => {
    process.env.DEMO_MODE = "live-base-sepolia";
    expect(getMode()).toBe("live-base-sepolia");
  });

  it("getMode() throws when DEMO_MODE invalid", () => {
    process.env.DEMO_MODE = "production-mainnet";
    let caught: unknown = null;
    try {
      getMode();
    } catch (err) {
      caught = err;
    }
    expect(isDemoError(caught)).toBe(true);
  });

  it("getTimelockDelay('ci-anvil') = 86400 seconds (simulated 24h)", () => {
    expect(getTimelockDelay("ci-anvil")).toBe(86400);
  });

  it("getTimelockDelay('live-base-sepolia') = 300 seconds (5 min wall)", () => {
    expect(getTimelockDelay("live-base-sepolia")).toBe(300);
  });

  it("getChainConfig('ci-anvil') defaults to anvil RPC + chainId 31337", () => {
    const config = getChainConfig("ci-anvil");
    expect(config.mode).toBe("ci-anvil");
    expect(config.chainId).toBe(31337);
    expect(config.rpcUrl).toContain("8545");
  });

  it("getChainConfig('live-base-sepolia') throws when BASE_SEPOLIA_RPC_URL unset", () => {
    let caught: unknown = null;
    try {
      getChainConfig("live-base-sepolia");
    } catch (err) {
      caught = err;
    }
    expect(isDemoError(caught)).toBe(true);
    expect((caught as DemoError).safeRefs.envVar).toBe("BASE_SEPOLIA_RPC_URL");
  });
});
