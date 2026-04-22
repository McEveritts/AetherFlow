import { NextResponse } from 'next/server';
import fs from 'fs/promises';
import path from 'path';

// IMPORTANT: Define the absolute paths you want to allow AetherMarketplace to see.
// For example, if you only want to mount media or app configs:
const ALLOWED_ROOTS = [
  '/mnt/media',
  '/opt/aetherflow/config',
  '/home/user/app/data'
];

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const dirPath = searchParams.get('path');

  if (!dirPath) {
    return NextResponse.json({ error: 'Path is required' }, { status: 400 });
  }

  try {
    // Resolve the path safely
    const resolvedPath = path.resolve(dirPath);
    
    // SECURITY CHECK: Ensure the resolved path starts with one of our allowed roots
    const isSafe = ALLOWED_ROOTS.some(root => resolvedPath.startsWith(root));
    
    if (!isSafe) {
      // Return a 403 Forbidden if they try to access /etc, /root, etc.
      console.warn(`Blocked directory traversal attempt: ${resolvedPath}`);
      return NextResponse.json({ error: 'Access Denied: Path outside allowed sandbox' }, { status: 403 });
    }
    
    const entries = await fs.readdir(resolvedPath, { withFileTypes: true });
    
    const directories = entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
      .sort((a, b) => a.localeCompare(b));

    return NextResponse.json({ directories });
  } catch (error) {
    console.error('Error reading directory:', error);
    return NextResponse.json({ error: 'Failed to read directory' }, { status: 500 });
  }
}
