# SPDX-License-Identifier: MIT
# Single-mode Puma (workers 0) to stay comfortably inside the 512 MB mem_limit.
# No pidfile / state file: the root filesystem is read-only.
max_threads = Integer(ENV.fetch("RAILS_MAX_THREADS", 8))
min_threads = Integer(ENV.fetch("RAILS_MIN_THREADS", 2))
threads min_threads, max_threads

workers 0

bind "tcp://0.0.0.0:8080"
environment ENV.fetch("RAILS_ENV", "production")

# Do not daemonize; log to stdout/stderr (inherited).
