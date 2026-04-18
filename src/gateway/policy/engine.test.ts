import { describe, expect, it } from "vitest";
import { BULK_SAFETY_THRESHOLD, evaluate } from "./engine.js";
import { ASK_BEFORE_MUTATING, POWER_USER, READ_ONLY } from "./profiles.js";
import type { PolicyInput } from "./types.js";

function makeInput(overrides: Partial<PolicyInput> & { profile: PolicyInput["profile"] }): PolicyInput {
  return {
    userId: "user-1",
    surface: "node",
    command: "system.run",
    capabilityMeta: {
      sensitivity: "low",
      mutatesState: false,
      approvalHint: "never",
      idempotent: true,
    },
    context: { originatingKind: "chat" },
    ...overrides,
  };
}

const readCap = { sensitivity: "low" as const, mutatesState: false, approvalHint: "never" as const, idempotent: true };
const mutateCap = { sensitivity: "medium" as const, mutatesState: true, approvalHint: "sometimes" as const, idempotent: false };
const criticalCap = { sensitivity: "critical" as const, mutatesState: true, approvalHint: "always" as const, idempotent: false };
const deniedCap = { sensitivity: "high" as const, mutatesState: true, approvalHint: "always" as const, idempotent: false };

describe("evaluate() — READ_ONLY profile", () => {
  it("allows read-only capability", () => {
    const result = evaluate(makeInput({ profile: READ_ONLY, capabilityMeta: readCap }));
    expect(result.decision).toBe("allow");
  });

  it("denies mutating capability", () => {
    const result = evaluate(makeInput({ profile: READ_ONLY, capabilityMeta: mutateCap }));
    expect(result.decision).toBe("deny");
  });

  it("denies bulk mutating capability", () => {
    const result = evaluate(makeInput({
      profile: READ_ONLY,
      capabilityMeta: mutateCap,
      context: { originatingKind: "chat", targetCount: BULK_SAFETY_THRESHOLD + 1 },
    }));
    expect(result.decision).toBe("deny");
  });

  it("denies critical capability", () => {
    const result = evaluate(makeInput({ profile: READ_ONLY, capabilityMeta: criticalCap }));
    expect(result.decision).toBe("deny");
  });
});

describe("evaluate() — ASK_BEFORE_MUTATING profile", () => {
  it("allows read-only capability", () => {
    const result = evaluate(makeInput({ profile: ASK_BEFORE_MUTATING, capabilityMeta: readCap }));
    expect(result.decision).toBe("allow");
  });

  it("requires approval for mutating capability", () => {
    const result = evaluate(makeInput({ profile: ASK_BEFORE_MUTATING, capabilityMeta: mutateCap }));
    expect(result.decision).toBe("require_approval");
  });

  it("requires approval for bulk mutating capability (from rule, before bulk safety)", () => {
    const result = evaluate(makeInput({
      profile: ASK_BEFORE_MUTATING,
      capabilityMeta: mutateCap,
      context: { originatingKind: "chat", targetCount: BULK_SAFETY_THRESHOLD + 1 },
    }));
    expect(result.decision).toBe("require_approval");
  });

  it("requires approval for critical capability", () => {
    const result = evaluate(makeInput({ profile: ASK_BEFORE_MUTATING, capabilityMeta: criticalCap }));
    expect(result.decision).toBe("require_approval");
  });
});

describe("evaluate() — POWER_USER profile", () => {
  it("allows read-only capability", () => {
    const result = evaluate(makeInput({ profile: POWER_USER, capabilityMeta: readCap }));
    expect(result.decision).toBe("allow");
  });

  it("allows mutating (non-critical) capability", () => {
    const result = evaluate(makeInput({ profile: POWER_USER, capabilityMeta: mutateCap }));
    expect(result.decision).toBe("allow");
  });

  it("requires approval for bulk mutating capability (bulk safety kicks in)", () => {
    const result = evaluate(makeInput({
      profile: POWER_USER,
      capabilityMeta: mutateCap,
      context: { originatingKind: "chat", targetCount: BULK_SAFETY_THRESHOLD + 1 },
    }));
    expect(result.decision).toBe("require_approval");
    expect(result.rule).toBe("system.bulk_safety");
    expect(result.approvalTemplate).toBe("bulk");
  });

  it("requires approval for critical capability", () => {
    const result = evaluate(makeInput({ profile: POWER_USER, capabilityMeta: criticalCap }));
    expect(result.decision).toBe("require_approval");
    expect(result.rule).toBe("pu.require_critical");
  });
});

describe("evaluate() — system rules", () => {
  it("bulk safety fires when no profile rule matches and targetCount > threshold", () => {
    const emptyProfile = { id: "test.empty", name: "Empty", kind: "builtin" as const, rules: [] };
    const result = evaluate(makeInput({
      profile: emptyProfile,
      capabilityMeta: mutateCap,
      context: { originatingKind: "chat", targetCount: BULK_SAFETY_THRESHOLD + 1 },
    }));
    expect(result.decision).toBe("require_approval");
    expect(result.rule).toBe("system.bulk_safety");
  });

  it("read-only short-circuit fires when no profile rule matches and cap is read-only", () => {
    const emptyProfile = { id: "test.empty", name: "Empty", kind: "builtin" as const, rules: [] };
    const result = evaluate(makeInput({
      profile: emptyProfile,
      capabilityMeta: readCap,
    }));
    expect(result.decision).toBe("allow");
    expect(result.rule).toBe("system.read_only");
  });

  it("default require_approval fires when no rule matches and cap mutates", () => {
    const emptyProfile = { id: "test.empty", name: "Empty", kind: "builtin" as const, rules: [] };
    const result = evaluate(makeInput({
      profile: emptyProfile,
      capabilityMeta: deniedCap,
      context: { originatingKind: "chat", targetCount: 1 },
    }));
    expect(result.decision).toBe("require_approval");
    expect(result.rule).toBe("system.default");
  });
});
