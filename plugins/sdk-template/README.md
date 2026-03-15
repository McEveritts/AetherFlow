# {{PLUGIN_NAME}}

Standard AetherFlow plugin scaffold.

## Layout

- `plugin.manifest.json`: plugin metadata consumed by loaders/tooling
- `backend/`: Go service or webhook worker that talks to the AetherFlow API
- `frontend/`: React panel exported for the Next.js shell
- `.env.example`: local environment variables

## Development flow

1. Copy the template with `bash scripts/create-plugin-sdk.sh`.
2. Fill in `plugin.manifest.json`.
3. Add backend routes or event workers in `backend/main.go`.
4. Replace the demo panel in `frontend/src/PluginPanel.tsx`.
5. Request only the permissions your plugin actually needs.
