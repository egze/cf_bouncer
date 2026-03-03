defmodule Mix.Tasks.CfBouncer.Sync do
  @shortdoc "Sync WAF allowlist to Cloudflare from Phoenix routes"
  @moduledoc """
  Generates a WAF block rule from the Phoenix router, endpoint sockets,
  and static paths, then pushes it to Cloudflare.

      mix cf_bouncer.sync           # sync to Cloudflare
      mix cf_bouncer.sync --dry-run # preview expression without pushing
      mix cf_bouncer.sync --force   # push even if unchanged

  The rule is only updated if the expression has changed.

  ## Required configuration

  See `CfBouncer` module docs.
  """

  use Mix.Task

  @requirements ["app.start"]

  @impl true
  def run(args) do
    cond do
      "--dry-run" in args ->
        expression = CfBouncer.build_expression()
        Mix.shell().info("Generated WAF expression:\n\n#{expression}\n")

      true ->
        opts = if "--force" in args, do: [force: true], else: []

        case CfBouncer.sync(opts) do
          :created -> Mix.shell().info("WAF rule created.")
          :updated -> Mix.shell().info("WAF rule updated.")
          :up_to_date -> Mix.shell().info("WAF rule already up to date.")
        end
    end
  end
end
