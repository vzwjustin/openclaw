import type { PolicyProfile } from "./types.js";

export const READ_ONLY: PolicyProfile = {
  id: "builtin.read_only",
  name: "Read Only",
  kind: "builtin",
  rules: [
    { id: "read_only.allow_reads", decision: "allow", reason: "Read access", when: { mutatesState: false } },
    { id: "read_only.deny_mutations", decision: "deny", reason: "Read Only profile forbids mutations", when: { mutatesState: true } },
  ],
};

export const ASK_BEFORE_MUTATING: PolicyProfile = {
  id: "builtin.ask_before_mutating",
  name: "Ask Before Mutating",
  kind: "builtin",
  rules: [
    { id: "abm.allow_reads", decision: "allow", reason: "Read access", when: { mutatesState: false } },
    { id: "abm.require_mutations", decision: "require_approval", reason: "All mutations need approval", when: { mutatesState: true } },
  ],
};

export const POWER_USER: PolicyProfile = {
  id: "builtin.power_user",
  name: "Power User",
  kind: "builtin",
  rules: [
    { id: "pu.require_critical", decision: "require_approval", when: { sensitivityAtLeast: "critical" }, reason: "Critical actions still need confirmation" },
    { id: "pu.allow_most", decision: "allow", reason: "Trusted profile" },
  ],
};

export const BUILTIN_PROFILES: PolicyProfile[] = [READ_ONLY, ASK_BEFORE_MUTATING, POWER_USER];

export function getBuiltinProfile(id: string): PolicyProfile | undefined {
  return BUILTIN_PROFILES.find((p) => p.id === id);
}

export const DEFAULT_PROFILE_ID = "builtin.ask_before_mutating";
