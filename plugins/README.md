# AetherFlow Plugin SDK

Community plugins live under `plugins/` and are scaffolded from `plugins/sdk-template`.

Use the scaffold helper:

```bash
bash scripts/create-plugin-sdk.sh my-plugin "My Plugin" plugins/my-plugin
```

The generated plugin includes:

- `plugin.manifest.json` for identity, permissions, and entrypoints
- `backend/` Go boilerplate with an AetherFlow API client
- `frontend/` React/TypeScript boilerplate for a Next.js-compatible panel
- `.env.example` for local development defaults
