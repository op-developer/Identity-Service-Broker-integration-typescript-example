import tseslint from "typescript-eslint";
import functional from "eslint-plugin-functional";
import globals from "globals";
import tsParser from "@typescript-eslint/parser";
import eslint from "@eslint/js";

export default tseslint.config(
    eslint.configs.recommended,
    ...tseslint.configs.recommended,
    {
        plugins: {
            "@typescript-eslint": tseslint.plugin,
            functional,
        },

        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node,
                Atomics: "readonly",
                SharedArrayBuffer: "readonly",
            },

            parser: tsParser,
            ecmaVersion: 2018,
            sourceType: "module",

            parserOptions: {
                project: "./tsconfig.json",
            },
        },

        rules: {
            "functional/no-let": ["off"],
            "@typescript-eslint/no-explicit-any": ["off"],
            "@typescript-eslint/explicit-function-return-type": ["off"],
            "functional/immutable-data": ["off"],
            "functional/type-declaration-immutability": ["off"],
            "functional/prefer-immutable-types": ["off"],
            "@typescript-eslint/no-unused-vars": ["off"],
            "@typescript-eslint/no-inferrable-types": ["off"],
            "@typescript-eslint/camelcase": ["off"],
            "@typescript-eslint/ban-types": ["off"],
            "@typescript-eslint/consistent-type-assertions": ["off"],
            "@typescript-eslint/interface-name-prefix": ["off"],
            "@typescript-eslint/triple-slash-reference": ["off"],
            "@typescript-eslint/no-unsafe-member-access": ["off"],
            "@typescript-eslint/no-unsafe-assignment": ["off"],
            "@typescript-eslint/no-unsafe-call": ["off"],
            "@typescript-eslint/no-unsafe-return": ["off"],
            "functional/no-return-void": "error",
            "functional/no-loop-statements": "error",
            eqeqeq: "error",
            quotes: ["error", "double"],
            semi: ["error", "always"],
            "linebreak-style": ["error", "unix"],

            "max-len": ["error", {
                code: 120,
            }],
        },
    }
);