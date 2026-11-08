"""Catalog/installer messaging contracts, not live upstream compatibility tests."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LegacyNoticesTests(unittest.TestCase):
    def test_legacy_notices_preserve_catalog_identity_and_lifecycle_access(self):
        packages = json.loads((ROOT / 'config/packages.json').read_text())
        self.assertEqual(len(packages), 77)
        for name, notice in [('readarr', 'retired'), ('overseerr', 'superseded'), ('autoscan', 'feature frozen')]:
            with self.subTest(package=name):
                package, = [package for package in packages if package['name'] == name]
                self.assertIn(notice, package['description'])
                self.assertEqual(package['lock_file'], f'/install/.{name}.lock')
                installer = (ROOT / f'packages/package/install/installpackage-{name}').read_text()
                self.assertIn(f'print_warn "', installer)
                self.assertIn(notice, installer)
                self.assertLess(installer.index('print_warn "'), installer.index('apt-get update'))
                self.assertTrue((ROOT / f'packages/package/remove/removepackage-{name}').is_file())


if __name__ == '__main__':
    unittest.main()
