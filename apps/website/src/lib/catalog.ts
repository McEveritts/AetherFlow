import fs from 'node:fs';
import path from 'node:path';

export interface CatalogApp {
  name: string;
  label: string;
  description: string;
  category: string;
  service_name: string;
  default_port: number;
  web_path?: string;
  status?: string;
}

export interface CatalogCategorySummary {
  name: string;
  count: number;
}

export interface CatalogData {
  apps: CatalogApp[];
  categories: CatalogCategorySummary[];
  totalCount: number;
}

const CATEGORY_ORDER = [
  'Media',
  'Downloaders',
  'Cloud',
  'Network',
  'Utilities',
  'Monitoring',
  'Security',
  'Automation',
  'DevOps',
];

export function loadCatalogData(): CatalogData {
  const candidates = [
    path.resolve(process.cwd(), '../../config/packages.json'),
    path.resolve(process.cwd(), 'config/packages.json'),
  ];

  const filePath = candidates.find((candidate) => fs.existsSync(candidate));
  if (!filePath) {
    throw new Error(
      `Unable to locate config/packages.json (checked: ${candidates.join(', ')})`
    );
  }

  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8')) as CatalogApp[];

  const apps: CatalogApp[] = raw.map((entry) => ({
    name: entry.name,
    label: entry.label,
    description: entry.description,
    category: entry.category,
    service_name: entry.service_name,
    default_port: entry.default_port ?? 0,
    ...(entry.web_path ? { web_path: entry.web_path } : {}),
    ...(entry.status ? { status: entry.status } : {}),
  }));

  const counts = new Map<string, number>();
  for (const app of apps) {
    counts.set(app.category, (counts.get(app.category) ?? 0) + 1);
  }

  const categories: CatalogCategorySummary[] = Array.from(counts.entries())
    .sort((a, b) => {
      const idxA = CATEGORY_ORDER.indexOf(a[0]);
      const idxB = CATEGORY_ORDER.indexOf(b[0]);
      if (idxA !== -1 && idxB !== -1) return idxA - idxB;
      if (idxA !== -1) return -1;
      if (idxB !== -1) return 1;
      return b[1] - a[1] || a[0].localeCompare(b[0]);
    })
    .map(([name, count]) => ({ name, count }));

  return {
    apps,
    categories,
    totalCount: apps.length,
  };
}
