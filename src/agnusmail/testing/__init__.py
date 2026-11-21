"""Test helpers for Agnusmail and its extensions. Never imported by the services.

- ``fakes``: settings, an in-memory database and Redis, and ``make_app``;
- ``auth``: SIWE messages and logins with throwaway wallets;
- ``openpgp`` and ``devices``: device keys generated in the test, as a client would;
- ``people``: logged-in users with a bound device, and E2EE messages between them.

They need the test dependencies (``pip install agnusmail[testing]``).
"""
