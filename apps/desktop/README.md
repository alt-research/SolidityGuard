# SolidityGuard Desktop

Tauri v2 desktop application wrapping the SolidityGuard React frontend with native capabilities.

## Prerequisites

- **Rust** (1.70+) and Cargo
- **Node.js** (18+) and npm
- The web frontend built at `../web/frontend/dist`

### System Dependencies (Linux)

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
```

## Development

```bash
# Install JS dependencies
npm install

# Start the web frontend dev server first
cd ../web/frontend && npm run dev

# Then start Tauri dev (in another terminal)
npm run tauri:dev
```

## Build

```bash
# Build the web frontend first
cd ../web/frontend && npm run build

# Build the desktop app
npm run tauri:build
```

The built application will be in `src-tauri/target/release/bundle/`.

## Tauri Commands

| Command | Description |
|---------|-------------|
| `select_contracts_dir` | Opens a native directory picker dialog |
| `check_tools` | Checks if slither, aderyn, mythril, forge are in PATH |
| `greet` | Test command to verify Tauri bridge |

## Architecture

The desktop app reuses the React frontend from `apps/web/frontend/`:

- **Development**: `devUrl` points to `http://localhost:5173` (Vite dev server)
- **Production**: `frontendDist` points to `../../web/frontend/dist` (built assets)

Native functionality is exposed via Tauri commands (Rust) callable from the frontend via `@tauri-apps/api`.
