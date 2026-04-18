import { beforeEach, describe, expect, it, vi } from "vitest";
import { createBroker } from "./broker.js";
import { ASK_BEFORE_MUTATING, POWER_USER, READ_ONLY } from "./profiles.js";
import type { ActionRequest, ActionResult, PolicyDecision, PolicyProfile } from "./types.js";
import type { BrokerPorts } from "./broker.js";

function makeReq(overrides?: Partial<ActionRequest>): ActionRequest {
  return {
    idempotencyKey: "idem-1",
    userId: "user-1",
    surface: "node",
    nodeId: "node-1",
    command: "camera.list",
    input: {},
    correlationId: "corr-1",
    ...overrides,
  };
}

function makePorts(profileOverride: PolicyProfile = ASK_BEFORE_MUTATING): BrokerPorts {
  return {
    policy: {
      forUser: vi.fn().mockResolvedValue(profileOverride),
    },
    approvals: {
      create: vi.fn().mockResolvedValue({ id: "approval-1", subject: "node-broker" }),
      requireApproved: vi.fn().mockResolvedValue(true),
    },
    execution: {
      invoke: vi.fn().mockResolvedValue({ ok: true, output: { result: "done" } } satisfies ActionResult),
    },
    events: {
      emit: vi.fn().mockResolvedValue(undefined),
    },
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  };
}

describe("broker.submit()", () => {
  it("allow — read-only command with POWER_USER profile returns allowed outcome", async () => {
    const ports = makePorts(POWER_USER);
    const broker = createBroker(ports);

    const outcome = await broker.submit(makeReq({ command: "camera.list" }));

    expect(outcome.kind).toBe("allowed");
    if (outcome.kind === "allowed") {
      expect(outcome.result.ok).toBe(true);
    }
    expect(ports.execution.invoke).toHaveBeenCalledOnce();
  });

  it("deny — READ_ONLY profile denies mutating command", async () => {
    const ports = makePorts(READ_ONLY);
    const broker = createBroker(ports);

    const outcome = await broker.submit(makeReq({ command: "camera.snap" }));

    expect(outcome.kind).toBe("denied");
    if (outcome.kind === "denied") {
      expect(outcome.reason).toBeTruthy();
    }
    expect(ports.execution.invoke).not.toHaveBeenCalled();
    expect(ports.approvals.create).not.toHaveBeenCalled();
  });

  it("require_approval — ASK_BEFORE_MUTATING profile requires approval for mutating command", async () => {
    const ports = makePorts(ASK_BEFORE_MUTATING);
    const broker = createBroker(ports);

    const outcome = await broker.submit(makeReq({ command: "camera.snap" }));

    expect(outcome.kind).toBe("approval_required");
    if (outcome.kind === "approval_required") {
      expect(outcome.approvalId).toBe("approval-1");
    }
    expect(ports.approvals.create).toHaveBeenCalledOnce();
    expect(ports.execution.invoke).not.toHaveBeenCalled();
  });

  it("failed — execution.invoke throws returns failed outcome", async () => {
    const ports = makePorts(POWER_USER);
    (ports.execution.invoke as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("node timed out"),
    );
    const broker = createBroker(ports);

    const outcome = await broker.submit(makeReq({ command: "camera.list" }));

    expect(outcome.kind).toBe("failed");
    if (outcome.kind === "failed") {
      expect(outcome.errorMessage).toContain("node timed out");
    }
    expect(ports.logger.error).toHaveBeenCalled();
  });

  it("failed — execution.invoke returns ok=false returns failed outcome", async () => {
    const ports = makePorts(POWER_USER);
    (ports.execution.invoke as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
      output: undefined,
      errorMessage: "permission denied by node",
    } satisfies ActionResult);
    const broker = createBroker(ports);

    const outcome = await broker.submit(makeReq({ command: "camera.list" }));

    expect(outcome.kind).toBe("failed");
    if (outcome.kind === "failed") {
      expect(outcome.errorMessage).toContain("permission denied by node");
    }
    expect(ports.logger.error).toHaveBeenCalled();
  });

  it("system.run skipApprovalCheck=true — when policy allows system.run, execution.invoke receives skipApprovalCheck=true", async () => {
    const ports = makePorts(POWER_USER);
    const broker = createBroker(ports);

    await broker.submit(makeReq({ command: "system.run" }));

    expect(ports.execution.invoke).toHaveBeenCalledOnce();
    const [, opts] = (ports.execution.invoke as ReturnType<typeof vi.fn>).mock.calls[0] as [
      ActionRequest,
      { skipApprovalCheck: boolean },
    ];
    expect(opts.skipApprovalCheck).toBe(true);
  });

  it("non-system.run skipApprovalCheck=false — regular allowed command gets skipApprovalCheck=false", async () => {
    const ports = makePorts(POWER_USER);
    const broker = createBroker(ports);

    await broker.submit(makeReq({ command: "camera.list" }));

    const [, opts] = (ports.execution.invoke as ReturnType<typeof vi.fn>).mock.calls[0] as [
      ActionRequest,
      { skipApprovalCheck: boolean },
    ];
    expect(opts.skipApprovalCheck).toBe(false);
  });

  it("emits policy.decision event for every submit", async () => {
    const ports = makePorts(POWER_USER);
    const broker = createBroker(ports);

    await broker.submit(makeReq({ command: "camera.list" }));

    const emittedTypes = (ports.events.emit as ReturnType<typeof vi.fn>).mock.calls.map(
      ([ev]: [{ type: string }]) => ev.type,
    );
    expect(emittedTypes).toContain("policy.decision");
  });
});

describe("broker.resumeAfterApproval()", () => {
  it("approved=true — calls execution.invoke and returns allowed", async () => {
    const ports = makePorts(ASK_BEFORE_MUTATING);
    const broker = createBroker(ports);
    const req = makeReq({ command: "camera.snap" });

    const outcome = await broker.resumeAfterApproval("approval-1", req);

    expect(ports.approvals.requireApproved).toHaveBeenCalledWith("approval-1");
    expect(outcome.kind).toBe("allowed");
  });

  it("approved=false — returns denied without calling execution.invoke", async () => {
    const ports = makePorts(ASK_BEFORE_MUTATING);
    (ports.approvals.requireApproved as ReturnType<typeof vi.fn>).mockResolvedValueOnce(false);
    const broker = createBroker(ports);
    const req = makeReq({ command: "camera.snap" });

    const outcome = await broker.resumeAfterApproval("approval-1", req);

    expect(outcome.kind).toBe("denied");
    expect(ports.execution.invoke).not.toHaveBeenCalled();
  });
});
