import { fixupConfigRules } from '@eslint/compat';
import { FlatCompat } from '@eslint/eslintrc';
import js from '@eslint/js';
import importPlugin from 'eslint-plugin-import';
import prettier from 'eslint-plugin-prettier';
import { defineConfig } from 'eslint/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
});

export default defineConfig([
  importPlugin.flatConfigs.recommended,
  importPlugin.flatConfigs.typescript,
  importPlugin.flatConfigs['react-native'],
  {
    extends: fixupConfigRules(compat.extends('@react-native', 'prettier')),
    settings: {
      'import/core-modules': ['react-native', 'react-native-dpop', 'react-native/Libraries/Types/CodegenTypes'],
      'import/extensions': ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json'],
      'import/ignore': ['node_modules/react-native/', 'react-native(/.*)?$'],
      'import/resolver': {
        node: {
          extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json'],
        },
      },
    },
    plugins: { prettier },
    rules: {
      'import/order': [
        'error',
        {
          groups: [['builtin', 'external'], 'internal', ['parent', 'sibling', 'index'], 'object'],
          pathGroups: [
            {
              pattern: '@/**',
              group: 'internal',
              position: 'before',
            },
          ],
          pathGroupsExcludedImportTypes: ['builtin'],
          'newlines-between': 'always',
          alphabetize: {
            order: 'asc',
            caseInsensitive: true,
          },
        },
      ],
      'react/react-in-jsx-scope': 'off',
      'prettier/prettier': 'error',
    },
  },
  {
    files: ['**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/consistent-type-imports': [
        'error',
        {
          fixStyle: 'inline-type-imports',
          prefer: 'type-imports',
        },
      ],
      '@typescript-eslint/explicit-function-return-type': 'error',
      '@typescript-eslint/explicit-member-accessibility': [
        'error',
        {
          accessibility: 'explicit',
        },
      ],
      '@typescript-eslint/member-ordering': [
        'error',
        {
          default: {
            order: 'alphabetically',
          },
        },
      ],
    },
  },
  {
    ignores: ['node_modules/', '**/node_modules/**', 'lib/'],
  },
]);
