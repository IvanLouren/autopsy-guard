"""Cross-platform helpers for Autopsy paths and process identification."""

from autopsyguard.platform_utils.process import (
    is_windows,
    get_autopsy_process_names,
    get_java_process_names,
)
from autopsyguard.platform_utils.paths import (
    get_autopsy_user_dir,
    get_autopsy_log_dir,
    get_case_log_dir,
    get_case_lock_file,
    get_global_lock_file,
    get_case_log_file,
    get_hs_err_search_dirs,
    get_autopsyguard_state_dir,
)
from autopsyguard.platform_utils.validation import validate_case_dir

__all__ = [
    "is_windows",
    "get_autopsy_process_names",
    "get_java_process_names",
    "get_autopsy_user_dir",
    "get_autopsy_log_dir",
    "get_case_log_dir",
    "get_case_lock_file",
    "get_global_lock_file",
    "get_case_log_file",
    "get_hs_err_search_dirs",
    "get_autopsyguard_state_dir",
    "validate_case_dir",
]
