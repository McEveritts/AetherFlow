"""
Tier 2 Boundary & Corner Cases Aggregator
Exports all 185 adversarial/edge test cases covering B01 through B37 (5 tests per feature).
"""

from .test_boundaries_api import get_tests as get_b01_to_b06_tests
from .test_boundaries_backend_core import get_tests as get_b07_to_b12_tests
from .test_boundaries_obsidian import get_tests as get_b13_to_b18_tests
from .test_boundaries_components import get_tests as get_b19_to_b23_tests
from .test_boundaries_operator_panels import get_tests as get_b24_to_b27_tests
from .test_boundaries_debian import get_tests as get_b28_to_b31_tests
from .test_boundaries_pipeline import get_tests as get_b32_to_b37_tests

def get_tier2_tests():
    all_tests = []
    all_tests.extend(get_b01_to_b06_tests())
    all_tests.extend(get_b07_to_b12_tests())
    all_tests.extend(get_b13_to_b18_tests())
    all_tests.extend(get_b19_to_b23_tests())
    all_tests.extend(get_b24_to_b27_tests())
    all_tests.extend(get_b28_to_b31_tests())
    all_tests.extend(get_b32_to_b37_tests())
    return all_tests
