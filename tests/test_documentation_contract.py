"""Prevent documentation counts drifting from the current source catalog."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'monitoring'))
from catalog import DEFINITIONS, RATES


class DocumentationContractTests(unittest.TestCase):
    def test_catalog_is_unique_and_rate_masters_exist(self):
        keys = [row[1] for row in DEFINITIONS]
        names = [row[0] for row in DEFINITIONS]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(set(RATES).issubset(set(names)))

    def test_documented_catalog_matches_source(self):
        text = (ROOT / 'docs/metrics-catalog.md').read_text()
        for _, key, _, _, _ in DEFINITIONS:
            self.assertIn(f'`{key}`', text)
        for name in RATES:
            key = next(row[1] for row in DEFINITIONS if row[0] == name)
            self.assertIn(f'`{key}.rate`', text)
        self.assertIn(f'**{len(DEFINITIONS)} исходных элемента', text)
        self.assertIn(f'{len(RATES)} зависимых скоростей', text)

    def test_teacher_key_separate_from_student_manual(self):
        export = (ROOT / 'tools/export-pdf-gost.py').read_text()
        manual = export.split("'manual':", 1)[1].split("'engineering':", 1)[0]
        self.assertNotIn('teacher-key.md', manual)


if __name__ == '__main__':
    unittest.main()
