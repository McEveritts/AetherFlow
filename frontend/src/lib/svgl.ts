/**
 * frontend/src/lib/svgl.ts
 * * Handles client-side fetching and caching of the SVGL network catalog.
 * Provides fuzzy-matching utilities to map local app profiles to remote SVGL assets.
 */

export interface SVGLRoute {
  light: string;
  dark: string;
}

export interface SVGLItem {
  id: string;
  title: string;
  category: string | string[];
  route: string | SVGLRoute;
  wordmark?: string | SVGLRoute;
  url?: string;
  brandUrl?: string;
}

// In-memory cache for the client session to ensure snappy page transitions
let svglCache: SVGLItem[] | null = null;
let svglPromise: Promise<SVGLItem[]> | null = null;

/**
 * Fetches the global network catalog from SVGL and pushes it into the memory cache.
 */
export async function getSVGLCatalog(): Promise<SVGLItem[]> {
  // Return the cached catalog if it exists
  if (svglCache) {
    return svglCache;
  }

  if (!svglPromise) {
    svglPromise = fetch('https://svgl.app/api/svgs', {
      // Next.js caching options to keep the fetch optimal
      next: { revalidate: 3600 } 
    }).then(async (response) => {
        if (!response.ok) {
            throw new Error(`Failed to fetch SVGL catalog: ${response.statusText}`);
        }
        const data: SVGLItem[] = await response.json();
        svglCache = data;
        return data;
    }).catch(error => {
        console.error('SVGL Integration Error:', error);
        // Return an empty array on failure so the app degrades gracefully to local PNGs
        return []; 
    }).finally(() => {
        svglPromise = null;
    });
  }
  
  return svglPromise;
}

/**
 * Uses a fuzzy-mapping loop to search arbitrary application names against 
 * the official repository title structures.
 * 
 * @param catalog - The full array of SVGL items
 * @param appId - The local application's ID
 * @param appName - The local application's display name
 * @returns The URL string to the matched SVG, or null if no match is found
 */
export function matchSVGLLogo(
  catalog: SVGLItem[],
  appId: string,
  appName: string
): string | null {
  if (!catalog || catalog.length === 0) return null;

  // Normalize local inputs for comparison
  const normalizedId = appId.toLowerCase().replace(/[^a-z0-9]/g, '');
  const normalizedName = appName.toLowerCase().replace(/[^a-z0-9]/g, '');

  // Regex fuzzy search loop
  const match = catalog.find((item) => {
    // Normalize the remote item title
    const itemTitle = item.title.toLowerCase().replace(/[^a-z0-9]/g, '');
    
    // Check for exact matches first, then fuzzy inclusions
    const isExactMatch = itemTitle === normalizedId || itemTitle === normalizedName;
    const isFuzzyMatch = itemTitle.includes(normalizedName) || normalizedName.includes(itemTitle);
    
    return isExactMatch || isFuzzyMatch;
  });

  if (match) {
    // Prioritize dark variant if the route is an object containing 'dark' and 'light'
    if (typeof match.route === 'object' && match.route !== null) {
      // AetherFlow operates primarily as a dark-mode app
      return match.route.dark || match.route.light;
    }
    
    // Otherwise, return the standard string route
    return match.route as string;
  }

  return null;
}
