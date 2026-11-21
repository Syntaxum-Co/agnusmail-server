"""Application constants."""

# Envelope size limits (bytes). Content is always ciphertext for the backend.
MAX_MESSAGE_CIPHERTEXT_SIZE = 2 * 1024 * 1024  # 2 MiB
MAX_ATTACHMENT_CIPHERTEXT_SIZE = 50 * 1024 * 1024  # 50 MiB

# Pagination limits.
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 25

# Redis key namespaces. No plaintext message content may ever be stored under them.
RATE_LIMIT_KEY_PREFIX = "agnusmail:rl:"
CACHE_KEY_PREFIX = "agnusmail:cache:"
NONCE_KEY_PREFIX = "agnusmail:nonce:"
SESSION_KEY_PREFIX = "agnusmail:session:"
