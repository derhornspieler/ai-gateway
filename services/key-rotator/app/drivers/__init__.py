"""Pluggable vendor rotation drivers.

Design ref: docs/solution-map.md §9.4 — "per-vendor driver plugin interface
in the key-rotator ... future custom vendors = new driver + config, no core
change." Each driver subclasses `app.drivers.base.BaseDriver` and is wired
into the vendor->driver map in `app.main`.
"""
