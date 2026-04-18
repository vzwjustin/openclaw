import { loadConfig } from "../config/config.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { createExecApprovalForwarder } from "../infra/exec-approval-forwarder.js";
import { type PluginApprovalRequestPayload } from "../infra/plugin-approvals.js";
import {
  resolveCommandSecretsFromActiveRuntimeSnapshot,
  type CommandSecretAssignment,
} from "../secrets/runtime-command-secrets.js";
import { getActiveSecretsRuntimeSnapshot } from "../secrets/runtime.js";
import { createExecApprovalIosPushDelivery } from "./exec-approval-ios-push.js";
import { ExecApprovalManager } from "./exec-approval-manager.js";
import { sanitizeNodeInvokeParamsForForwarding } from "./node-invoke-sanitize.js";
import {
  isNodeCommandAllowed,
  resolveNodeCommandAllowlist,
} from "./node-command-policy.js";
import { createBroker } from "./policy/broker.js";
import { DEFAULT_PROFILE_ID, getBuiltinProfile } from "./policy/profiles.js";
import type { NodeRegistry } from "./node-registry.js";
import { createExecApprovalHandlers } from "./server-methods/exec-approval.js";
import { createPluginApprovalHandlers } from "./server-methods/plugin-approval.js";
import { createSecretsHandlers } from "./server-methods/secrets.js";
import {
  disconnectStaleSharedGatewayAuthClients,
  setCurrentSharedGatewaySessionGeneration,
  type SharedGatewayAuthClient,
  type SharedGatewaySessionGenerationState,
} from "./server-shared-auth-generation.js";
import type { ActivateRuntimeSecrets } from "./server-startup-config.js";

type GatewayAuxHandlerLogger = {
  warn?: (message: string) => void;
  error?: (message: string) => void;
  debug?: (message: string) => void;
};

export function createGatewayAuxHandlers(params: {
  log: GatewayAuxHandlerLogger;
  activateRuntimeSecrets: ActivateRuntimeSecrets;
  sharedGatewaySessionGenerationState: SharedGatewaySessionGenerationState;
  resolveSharedGatewaySessionGenerationForConfig: (config: OpenClawConfig) => string | undefined;
  clients: Iterable<SharedGatewayAuthClient>;
  nodeRegistry: NodeRegistry;
}) {
  const execApprovalManager = new ExecApprovalManager();
  const execApprovalForwarder = createExecApprovalForwarder();
  const execApprovalIosPushDelivery = createExecApprovalIosPushDelivery({ log: params.log });
  const execApprovalHandlers = createExecApprovalHandlers(execApprovalManager, {
    forwarder: execApprovalForwarder,
    iosPushDelivery: execApprovalIosPushDelivery,
  });
  const pluginApprovalManager = new ExecApprovalManager<PluginApprovalRequestPayload>();
  const pluginApprovalHandlers = createPluginApprovalHandlers(pluginApprovalManager, {
    forwarder: execApprovalForwarder,
  });
  const secretsHandlers = createSecretsHandlers({
    reloadSecrets: async () => {
      const active = getActiveSecretsRuntimeSnapshot();
      if (!active) {
        throw new Error("Secrets runtime snapshot is not active.");
      }
      const previousSharedGatewaySessionGeneration =
        params.sharedGatewaySessionGenerationState.current;
      const prepared = await params.activateRuntimeSecrets(active.sourceConfig, {
        reason: "reload",
        activate: true,
      });
      const nextSharedGatewaySessionGeneration =
        params.resolveSharedGatewaySessionGenerationForConfig(prepared.config);
      setCurrentSharedGatewaySessionGeneration(
        params.sharedGatewaySessionGenerationState,
        nextSharedGatewaySessionGeneration,
      );
      if (previousSharedGatewaySessionGeneration !== nextSharedGatewaySessionGeneration) {
        disconnectStaleSharedGatewayAuthClients({
          clients: params.clients,
          expectedGeneration: nextSharedGatewaySessionGeneration,
        });
      }
      return { warningCount: prepared.warnings.length };
    },
    resolveSecrets: async ({ commandName, targetIds }) => {
      const { assignments, diagnostics, inactiveRefPaths } =
        resolveCommandSecretsFromActiveRuntimeSnapshot({
          commandName,
          targetIds: new Set(targetIds),
        });
      if (assignments.length === 0) {
        return { assignments: [] as CommandSecretAssignment[], diagnostics, inactiveRefPaths };
      }
      return { assignments, diagnostics, inactiveRefPaths };
    },
  });

  const nodeCommandBroker = createBroker({
    policy: {
      forUser: async (userId: string) => {
        const cfg = loadConfig();
        const profileId = cfg.gateway?.nodes?.policyProfileId ?? DEFAULT_PROFILE_ID;
        return getBuiltinProfile(profileId) ?? getBuiltinProfile(DEFAULT_PROFILE_ID)!;
      },
    },
    approvals: {
      create: async (req, decision) => {
        const record = execApprovalManager.create(
          {
            command: req.command,
            nodeId: req.nodeId,
            host: "node",
            security: null,
            ask: null,
            allowedDecisions: ["allow-once"],
            agentId: null,
            resolvedPath: null,
            sessionKey: null,
            turnSourceChannel: null,
            turnSourceTo: null,
            turnSourceAccountId: null,
            turnSourceThreadId: null,
            systemRunBinding: null,
            systemRunPlan: null,
            cwd: null,
            envKeys: undefined,
            commandArgv: undefined,
            commandPreview: undefined,
          },
          60_000,
        );
        (record as Record<string, unknown>)["_brokerActionRequest"] = req;
        execApprovalManager.register(record, 60_000);
        return { id: record.id, subject: "node-broker" };
      },
      requireApproved: async (approvalId: string) => {
        const snapshot = execApprovalManager.getSnapshot(approvalId);
        return snapshot?.decision === "allow-once" || snapshot?.decision === "allow-always";
      },
    },
    execution: {
      invoke: async (req, opts) => {
        const cfg = loadConfig();
        const nodeSession = params.nodeRegistry.get(req.nodeId);
        if (!nodeSession) {
          return { ok: false, output: undefined, errorMessage: "node not connected" };
        }
        const allowlist = resolveNodeCommandAllowlist(cfg, nodeSession);
        const allowed = isNodeCommandAllowed({
          command: req.command,
          declaredCommands: nodeSession.commands,
          allowlist,
        });
        if (!allowed.ok) {
          return { ok: false, output: undefined, errorMessage: allowed.reason };
        }
        const sanitized = sanitizeNodeInvokeParamsForForwarding({
          nodeId: req.nodeId,
          command: req.command,
          rawParams: req.input,
          client: null,
          execApprovalManager,
          skipApprovalCheck: opts.skipApprovalCheck,
        });
        if (!sanitized.ok) {
          return { ok: false, output: undefined, errorMessage: sanitized.message };
        }
        const res = await params.nodeRegistry.invoke({
          nodeId: req.nodeId,
          command: req.command,
          params: sanitized.params,
          idempotencyKey: req.idempotencyKey,
        });
        if (!res.ok) {
          return { ok: false, output: undefined, errorMessage: res.error?.message ?? "node invoke failed" };
        }
        const output = res.payloadJSON ?? res.payload ?? undefined;
        return { ok: true, output };
      },
    },
    events: {
      emit: async (event) => {
        params.log.debug?.(`[policy] ${event.type}`);
      },
    },
    logger: {
      info: (msg, data) => params.log.debug?.(`[policy] ${msg}`),
      warn: (msg, data) => params.log.warn?.(`[policy] ${msg}`),
      error: (msg, data) => params.log.error?.(`[policy] ${msg}`),
    },
  });

  return {
    execApprovalManager,
    pluginApprovalManager,
    nodeCommandBroker,
    extraHandlers: {
      ...execApprovalHandlers,
      ...pluginApprovalHandlers,
      ...secretsHandlers,
    },
  };
}
