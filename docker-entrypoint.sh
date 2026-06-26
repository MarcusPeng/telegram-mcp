#!/bin/sh
# Runs as root (the container's default user) so it can fix ownership of
# /app/data before dropping privileges. /app/data only exists when something
# is bind-mounted there (HTTP multi-user mode's SQLite DB volume); when the
# host directory didn't pre-exist, Docker creates it owned by root, which
# appuser then can't write to -- hence fixing it here on every start,
# idempotently, before exec'ing the real command as appuser.
set -e

if [ -d /app/data ]; then
    chown -R appuser:appuser /app/data
fi

exec su-exec appuser "$@"
