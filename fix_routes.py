import os
import re

FRONTEND_DIR = r"C:\Users\armyw\OneDrive\Documents\Antigravity\Projects\AetherFlow\frontend\src"

public_routes = [
    '/auth/setup/check', '/auth/setup', '/auth/login', '/auth/google/login',
    '/auth/google/callback', '/marketplace', '/billing/webhooks'
]

auth_routes = [
    '/ws', '/auth/session', '/auth/logout', '/auth/profile', '/user/quota',
    '/settings', '/fileshare', '/services', '/packages', '/system/update/check',
    '/system/hardware', '/notifications'
]

admin_routes = [
    '/backup', '/users', '/quotas', '/system/update/run', '/fileshare/upload',
    '/cluster', '/oidc', '/ai', '/logs', '/network', '/system/metrics'
]

def map_route(route):
    # remove trailing slash if any on match
    if '/auth/session' in route:
        return route.replace('/api/auth/session', '/api/v1/auth/session')
    if '/auth/logout' in route:
        return route.replace('/api/auth/logout', '/api/v1/auth/logout')
    if '/auth/profile' in route:
        return route.replace('/api/auth/profile', '/api/v1/auth/profile')

    for p in public_routes:
        if route.startswith(f"/api{p}"):
            return route.replace('/api/', '/api/v1/public/')
    for p in auth_routes:
        if route.startswith(f"/api{p}"):
            return route.replace('/api/', '/api/v1/auth/')
    for p in admin_routes:
        if route.startswith(f"/api{p}"):
            return route.replace('/api/', '/api/v1/admin/')
            
    # Default fallback if it doesn't match specific ones
    return route

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find all fetch or useSWR API calls pointing to /api/...
    new_content = content
    matches = set(re.findall(r"['\"]/api/(.*?)['\"\?]", content))
    for m in matches:
        original = f"/api/{m}"
        mapped = map_route(original)
        if original != mapped:
            # We replace in quotes or backticks
            new_content = new_content.replace(f"'{original}'", f"'{mapped}'")
            new_content = new_content.replace(f"\"{original}\"", f"\"{mapped}\"")
            new_content = new_content.replace(f"`{original}", f"`{mapped}")
            
    if new_content != content:
        print(f"Updated {filepath}")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)

for root, _, files in os.walk(FRONTEND_DIR):
    for f in files:
        if f.endswith('.ts') or f.endswith('.tsx'):
            process_file(os.path.join(root, f))
