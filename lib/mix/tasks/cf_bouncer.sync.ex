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
    opts = config()

    cond do
      "--dry-run" in args ->
        expression = CfBouncer.build_expression(opts)
        Mix.shell().info("Generated WAF expression:\n\n#{expression}\n")

      true ->
        opts = if "--force" in args, do: Keyword.put(opts, :force, true), else: opts

        case CfBouncer.sync(opts) do
          :created -> Mix.shell().info("WAF rule created.")
          :updated -> Mix.shell().info("WAF rule updated.")
          :up_to_date -> Mix.shell().info("WAF rule already up to date.")
        end
    end
  end

  defp config do
    [
      router: Application.fetch_env!(:cf_bouncer, :router),
      endpoint: Application.fetch_env!(:cf_bouncer, :endpoint),
      static_module: Application.fetch_env!(:cf_bouncer, :static_module),
      rule_description: Application.fetch_env!(:cf_bouncer, :rule_description),
      extra_paths: Application.get_env(:cf_bouncer, :extra_paths, []),
      zone_id: Application.fetch_env!(:cf_bouncer, :zone_id),
      api_token: Application.fetch_env!(:cf_bouncer, :api_token)
    ]
  end
end
