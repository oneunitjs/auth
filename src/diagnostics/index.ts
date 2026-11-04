export {
  emitDiagnostic,
  getDiagnosticsObserver,
  getDiagnosticsOverflowPolicy,
  getDiagnosticsStats,
  resetDiagnostics,
  setDiagnosticsErrorCallback,
  setDiagnosticsOverflowPolicy,
  setDiagnosticsObserver,
} from "./emitter.js";

export type {
  AuthDiagnosticEvent,
  DiagnosticFailureCategory,
  DiagnosticsErrorCallback,
  DiagnosticsObserver,
  DiagnosticsOverflowPolicy,
  DiagnosticsStats,
} from "./types.js";
