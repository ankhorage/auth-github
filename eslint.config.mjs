import { createConfig } from '@ankhorage/devtools/eslint';
export default createConfig({
  files: ['src/**/*.{ts,tsx}'],
  project: ['./tsconfig.eslint.json'],
  tsconfigRootDir: import.meta.dirname,
});
