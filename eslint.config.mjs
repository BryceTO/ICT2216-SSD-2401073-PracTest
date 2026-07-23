import pluginSecurity from "eslint-plugin-security";

export default [
  {
    files: ["static/**/*.js"],
    plugins: {
      security: pluginSecurity,
    },
    rules: {
      ...pluginSecurity.configs.recommended.rules,
    },
    languageOptions: {
      sourceType: "script",
      globals: {
        document: "readonly",
        alert: "readonly",
      },
    },
  },
];
