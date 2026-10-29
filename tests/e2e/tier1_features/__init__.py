"""
Tier 1 Feature Coverage Aggregator
Exports all 185 test cases covering F01 through F37 (5 tests per feature).
"""

from .test_f01_to_f06_backend_api import get_tests as get_f01_to_f06_tests
from .test_f07_to_f12_backend_core import get_tests as get_f07_to_f12_tests
from .test_f13_to_f18_obsidian_design import get_tests as get_f13_to_f18_tests
from .test_f19_to_f23_component_mounting import get_tests as get_f19_to_f23_tests
from .test_f24_to_f27_operator_panels import get_tests as get_f24_to_f27_tests
from .test_f28_to_f31_debian_packaging import get_tests as get_f28_to_f31_tests
from .test_f32_to_f37_system_pipeline import get_tests as get_f32_to_f37_tests

def get_tier1_tests():
    all_tests = []
    all_tests.extend(get_f01_to_f06_tests())
    all_tests.extend(get_f07_to_f12_tests())
    all_tests.extend(get_f13_to_f18_tests())
    all_tests.extend(get_f19_to_f23_tests())
    all_tests.extend(get_f24_to_f27_tests())
    all_tests.extend(get_f28_to_f31_tests())
    all_tests.extend(get_f32_to_f37_tests())
    return all_tests
