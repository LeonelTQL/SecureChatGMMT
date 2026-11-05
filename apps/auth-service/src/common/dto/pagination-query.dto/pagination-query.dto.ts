export const offsetPage = (value?: string) =>
  Math.min(1000000, Math.max(0, Number.isSafeInteger(Number(value)) ? Number(value) : 0));
