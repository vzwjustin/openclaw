import type { NodeCapability } from "./types.js";

const HIGH_MUTATING: Omit<NodeCapability, "surface" | "id"> = {
  mutatesState: true,
  sensitivity: "high",
  idempotent: false,
  approvalHint: "always",
};

const LOW_READONLY: Omit<NodeCapability, "surface" | "id"> = {
  mutatesState: false,
  sensitivity: "low",
  idempotent: true,
  approvalHint: "never",
};

const MEDIUM_MUTATING: Omit<NodeCapability, "surface" | "id"> = {
  mutatesState: true,
  sensitivity: "medium",
  idempotent: false,
  approvalHint: "sometimes",
};

// Commands explicitly classified as high-sensitivity mutating
const HIGH_COMMANDS = new Set([
  "system.run",
  "system.write",
  // camera dangerous
  "camera.snap",
  "camera.clip",
  // screen dangerous
  "screen.record",
  // contacts dangerous
  "contacts.add",
  // calendar dangerous
  "calendar.add",
  // reminders dangerous
  "reminders.add",
  // sms dangerous
  "sms.send",
  "sms.search",
]);

const READ_SUFFIXES = [".read", ".list", ".get", ".search", ".events", ".latest"];

function classifyCommand(command: string): Omit<NodeCapability, "surface" | "id"> {
  if (HIGH_COMMANDS.has(command)) {
    return HIGH_MUTATING;
  }
  if (command.includes("delete") || command.includes(".rm") || command.includes(".remove")) {
    return HIGH_MUTATING;
  }
  for (const suffix of READ_SUFFIXES) {
    if (command.endsWith(suffix)) {
      return LOW_READONLY;
    }
  }
  // camera.snap is high (covered above); camera.list is read-only
  if (command === "camera.list" || command === "location.get" || command === "device.info" ||
      command === "device.status" || command === "photos.latest" || command === "motion.activity" ||
      command === "motion.pedometer" || command === "screen.snapshot") {
    return LOW_READONLY;
  }
  // Conservative fallback for unknown commands
  return MEDIUM_MUTATING;
}

export function getNodeCapability(command: string): NodeCapability {
  const meta = classifyCommand(command);
  return { surface: "node", id: command, ...meta };
}
