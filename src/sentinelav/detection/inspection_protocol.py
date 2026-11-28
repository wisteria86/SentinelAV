# Purpose: Share transport byte limits between scanner parent and worker.
# Works with: sibling modules in detection
# Used by: detection.inspection, detection.inspection_worker

"""Shared byte limits for the parent scanner and isolated worker."""

MAX_LINE = 32 * 1024 * 1024
MAX_REQUEST = 2 * 1024 * 1024
