declare module "opentelemetry" {
  export const trace: {
    getTracer: (name: string) => {
      startSpan: (
        name: string,
        attrs?: Record<string, unknown>,
      ) => { end: () => void };
    };
  };
}
