# Purpose: Command-line entry point for the application hash archive importer.
# Works with: updates.hash_archive
# Used by: the Python module loader or CLI entry point

"""Command-line entry point for the application hash archive importer."""
from sentinelav.updates.hash_archive import *
from sentinelav.updates.hash_archive import main

if __name__ == "__main__":
    main()
