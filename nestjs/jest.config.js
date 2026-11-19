// ESM project: run through `pnpm test`, which starts node with --experimental-vm-modules.
export default {
  testEnvironment: 'node',
  setupFiles: ['reflect-metadata'],
  rootDir: 'src',
  testRegex: '.*\\.spec\\.ts$',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: { '^(\\.{1,2}/.*)\\.js$': '$1' },
  transform: { '^.+\\.ts$': ['ts-jest', { useESM: true, tsconfig: '<rootDir>/../tsconfig.json' }] },
};
