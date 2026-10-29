"""Versions of the public contracts.

`SDK_VERSION` is what a defense manifest's `sdk_version_range` is checked
against at startup. `CONTRACT_VERSION` is stamped on every `Event`, so a
defense can tell which event shape it received.
"""

SDK_VERSION = "1.0.0"
CONTRACT_VERSION = "1"
