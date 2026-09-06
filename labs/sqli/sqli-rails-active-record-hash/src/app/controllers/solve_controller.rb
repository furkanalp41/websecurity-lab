# SPDX-License-Identifier: MIT
#
#   POST /solve   {"key": "<16 lowercase hex chars>"}
#
# Verifies the submitted value against the per-container secrets.master_key. On a
# match it reads the flag FILE directly in Ruby (File.read) and returns it. It
# never shell-execs to fetch the flag: opening the file in-process avoids handing
# an attacker a command-execution primitive, which is the safer established
# pattern for this platform (the catalog's "give-flag.sh" hint notwithstanding).
class SolveController < ApplicationController
  FLAG_PATH = ENV.fetch("FLAG_PATH", "/var/lib/lab/flag.txt")

  def create
    submitted = params[:key].to_s
    secret = Secret.order(:id).first

    if secret &&
       !submitted.empty? &&
       ActiveSupport::SecurityUtils.secure_compare(submitted, secret.master_key.to_s)
      render json: { flag: read_flag }
    else
      render json: { ok: false }
    end
  end

  private

  def read_flag
    File.read(FLAG_PATH).strip
  rescue SystemCallError
    "(flag unavailable)"
  end
end
