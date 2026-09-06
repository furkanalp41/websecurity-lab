# SPDX-License-Identifier: MIT
# Holds the single per-container secret (master_key). It is seeded at startup and
# never rendered by any endpoint; it can only be *inferred* through the ORDER BY
# side channel, and it is verified (not echoed) by POST /solve.
class Secret < ApplicationRecord
end
