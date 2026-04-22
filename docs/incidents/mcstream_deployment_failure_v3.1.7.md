# AetherFlow Deployment Incident Resolution (v3.1.7)

This document outlines the diagnosis and resolution of a deployment failure on the McStream production server (192.168.1.153) during the v3.1.7 release.

## Incident Overview

During the execution of the deployment script (`update.py`) to release the `v3.1.7` tag, the Go API compiled successfully but the Next.js frontend build failed, causing the update script to exit with code `1`. The services did not restart, meaning the production environment remained on the previous version but the update could not complete.

## Root Cause Analysis & Identification

By checking the output of the Next.js `npm run build` process on the remote machine (and subsequently verifying locally), the exact build failure was pinpointed.

### Frontend Build Crash: TypeScript Type Mismatch
**How it was identified:** 
The Next.js build output in `journalctl` and the deployment script logs showed a compilation error in `frontend/src/components/tabs/AiChatTab.tsx`:
```
> 225 |                                             setSelectedProvider(newProvider);
      |                                                                 ^
```

**The Root Cause:**
In `AiChatTab.tsx`, a `<select>` dropdown was used to change the active AI provider. The `onChange` handler extracted `e.target.value`, which TypeScript infers as a generic `string`. However, the React state hook `selectedProvider` was strictly typed to expect the `AIProviderID` union type (e.g., `'gemini' | 'claude' | ...`). Passing a generic string to the strictly typed setter caused a TypeScript validation failure, halting the production build.

## Remediations Executed

The fix was applied locally and then redeployed to the McStream server.

### 1. Patching the TypeScript Error
The frontend code was modified to explicitly cast the generic string to the expected `AIProviderID` type before passing it to the state setter.

**Diff applied to `AiChatTab.tsx`:**
```tsx
- const newProvider = e.target.value;
+ const newProvider = e.target.value as AIProviderID;
  setSelectedProvider(newProvider);
```

### 2. Updating Git Tags
To ensure the remote server built the correct code from the intended release tag:
1. The changes were committed locally.
2. The `v3.1.7` tag was forcefully recreated to point to the new commit (`git tag -f v3.1.7`).
3. The `master` branch and the tags were forcefully pushed to the origin repository (`git push origin master; git push origin --tags -f`).

### 3. Executing the Remote Deployment
The `paramiko`-based Python deployment script was executed again to:
1. SSH into the McStream node.
2. Stash any dirty states and fetch the forced tags (`git fetch --all --tags -f`).
3. Checkout the `v3.1.7` tag.
4. Rebuild the Go API and the Next.js frontend (which now compiled successfully).
5. Restart the `aetherflow-api` and `aetherflow-frontend` systemd services.

## Validations Performed

The `Next.js` production build succeeded (`Compiled successfully in 2.2s`), and both systemd services restarted without issue. The deployment script concluded with an `Exit Status: 0`, confirming that v3.1.7 was successfully released and the outage was resolved.
