# SPDX-License-Identifier: MIT
#
# Incident-report listing API.
#
#   GET /reports?filter[status]=open&sort=<expr>
#
# The `filter` hash is run through strong parameters and reaches ActiveRecord as
# a *hash condition*, so those values are bound as query parameters -> safe.
#
# The `sort` field is the vulnerability. The developer wanted "flexible sorting"
# (sort by any column, expression, direction). Rails 6.1+ refuses to put an
# unrecognised raw string into ORDER BY (it raises
# ActiveRecord::UnknownAttributeReference) precisely to stop SQL injection here.
# Instead of building an allowlist, the developer reached for `Arel.sql(...)`,
# the escape hatch that tells ActiveRecord "trust me, this string is safe SQL".
# It is NOT safe: `params[:sort]` is attacker-controlled and is now interpolated
# verbatim into ORDER BY (CWE-89, ActiveRecord order() injection).
class ReportsController < ApplicationController
  def index
    reports = Report
              .where(filter_params)
              .order(sort_clause)
              .limit(50)

    render json: reports.as_json(only: %i[id title status])
  rescue ActiveRecord::ActiveRecordError
    # Stay a black box: a malformed injected expression must not leak a stack
    # trace or SQL error. The learner only ever sees row ordering.
    render json: { error: "query failed" }, status: :ok
  end

  private

  # Strong parameters DO protect the filter surface: only :status and :category
  # are permitted, and hash conditions are always bound by the adapter.
  def filter_params
    raw = params[:filter]
    return {} unless raw.respond_to?(:permit)

    raw.permit(:status, :category).to_h
  end

  # VULNERABILITY (CWE-89): raw, attacker-controlled ORDER BY. Wrapping the param
  # in Arel.sql disables Rails' raw-SQL ORDER BY protection. Never do this with
  # untrusted input; an allowlist of {column => direction} is the correct fix.
  def sort_clause
    raw = params[:sort].presence || "id asc"
    Arel.sql(raw)
  end
end
