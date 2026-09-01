import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    clearMocks: true,
    coverage: {
      provider: 'v8',
      include: ['src/guardrails/**/*.ts', 'src/audit/**/*.ts'],
      thresholds: { lines: 90 },
    },
  },
});
