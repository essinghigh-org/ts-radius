import path from "node:path";
import { fileURLToPath } from "node:url";

import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default tseslint.config(
    {
        ignores: ["node_modules/**", "dist/**", "coverage/**"],
    },
    {
        files: ["**/*.ts"],
        extends: [js.configs.recommended, ...tseslint.configs.strictTypeChecked],
        languageOptions: {
            globals: {
                ...globals.node,
                ...globals.bun,
            },
            parserOptions: {
                projectService: true,
                tsconfigRootDir: __dirname,
            },
        },
        rules: {
            "@typescript-eslint/consistent-type-imports": [
                "error",
                {
                    prefer: "type-imports",
                    fixStyle: "inline-type-imports",
                },
            ],
            "@typescript-eslint/no-explicit-any": "error",
        },
    },
    {
        files: ["tests/**/*.ts"],
        rules: {
            "@typescript-eslint/require-await": "off",
        },
    },
);