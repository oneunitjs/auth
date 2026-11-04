/**
 * Optional, structurally typed logger interface. Applications can inject any
 * compatible logger directly—no library-specific adapter is required provided
 * the methods satisfy this shape.
 *
 * All methods are optional. The library does not depend on a specific logging
 * implementation and never writes to console when no logger is configured.
 */
export type Logger = {
  debug?(payload: unknown, message?: string): void;
  info?(payload: unknown, message?: string): void;
  warn?(payload: unknown, message?: string): void;
  error?(payload: unknown, message?: string): void;
};
