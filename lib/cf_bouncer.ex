defmodule CfBouncer do
  @moduledoc """
  Generates a Cloudflare WAF block rule from your Phoenix router, endpoint
  sockets, and static paths, then syncs it via the Rulesets API.

  ## Configuration

      # config/config.exs
      config :cf_bouncer,
        router: MyAppWeb.Router,
        endpoint: MyAppWeb.Endpoint,
        static_module: MyAppWeb,
        rule_description: "[CfBouncer] Block non-allowlisted paths",
        extra_paths: ["/cf-fonts/"]

      # config/runtime.exs
      config :cf_bouncer,
        zone_id: System.get_env("CLOUDFLARE_ZONE_ID"),
        api_token: System.get_env("CLOUDFLARE_API_TOKEN")

  ## Usage

  All public functions accept a keyword list of options instead of reading
  application config directly, making this library usable without being a
  supervised OTP app.

      opts = [
        router: MyAppWeb.Router,
        endpoint: MyAppWeb.Endpoint,
        static_module: MyAppWeb,
        extra_paths: ["/cf-fonts/"],
        zone_id: "your-zone-id",
        api_token: "your-api-token",
        rule_description: "[CfBouncer] Block non-allowlisted paths"
      ]

      CfBouncer.build_expression(opts)
      CfBouncer.sync(opts)
  """

  @base_url "https://api.cloudflare.com/client/v4"

  @doc """
  Builds the WAF expression string from configured routes, sockets, and static paths.

  ## Options

    * `:router` — Phoenix router module (required)
    * `:endpoint` — Phoenix endpoint module (required)
    * `:static_module` — module with `static_paths/0` (required)
    * `:extra_paths` — additional path prefixes to allow (default: `[]`)
  """
  def build_expression(opts) do
    route_conditions = route_conditions(opts)
    static_conditions = static_conditions(opts)
    extra_conditions = extra_conditions(opts)

    all_conditions =
      (route_conditions ++ static_conditions ++ extra_conditions)
      |> Enum.uniq()
      |> Enum.sort()

    EEx.eval_string(
      """
      not (
        <%= Enum.join(conditions, "\\n  or ") %>
      )\
      """,
      conditions: all_conditions
    )
  end

  @doc """
  Syncs the WAF rule to Cloudflare. Creates the rule if it doesn't exist,
  updates it if the expression changed, or skips if already up to date.

  Accepts all options from `build_expression/1` plus:

    * `:zone_id` — Cloudflare zone ID (required)
    * `:api_token` — Cloudflare API token (required)
    * `:rule_description` — description for the WAF rule (required)
    * `:force` — push even if unchanged (default: `false`)

  Returns `:created`, `:updated`, or `:up_to_date`.
  """
  def sync(opts) do
    force = Keyword.get(opts, :force, false)
    expression = build_expression(opts)
    zone_id = Keyword.fetch!(opts, :zone_id)
    rule_description = Keyword.fetch!(opts, :rule_description)

    ruleset_id = find_ruleset!(zone_id, opts)
    rule = find_rule(zone_id, ruleset_id, rule_description, opts)

    body = %{
      action: "block",
      expression: expression,
      description: rule_description
    }

    case rule do
      nil ->
        create_rule!(zone_id, ruleset_id, body, opts)
        :created

      %{"expression" => ^expression} when not force ->
        :up_to_date

      %{"id" => rule_id} ->
        update_rule!(zone_id, ruleset_id, rule_id, body, opts)
        :updated
    end
  end

  # Expression building

  defp route_conditions(opts) do
    router = Keyword.fetch!(opts, :router)

    router.__routes__()
    |> Enum.map(& &1.path)
    |> Enum.uniq()
    |> Enum.map(fn "/" <> rest ->
      case String.split(rest, "/") do
        [""] -> "/"
        [first | _] -> "/#{first}"
      end
    end)
    |> Enum.concat(socket_prefixes(opts))
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.map(fn
      "/" -> ~s[http.request.uri.path eq "/"]
      prefix -> ~s[starts_with(http.request.uri.path, "#{prefix}")]
    end)
  end

  defp socket_prefixes(opts) do
    endpoint = Keyword.fetch!(opts, :endpoint)

    endpoint.__sockets__()
    |> Enum.map(fn {path, _module, _opts} -> path end)
    |> Enum.reject(&String.contains?(&1, "live_reload"))
  end

  defp static_conditions(opts) do
    static_module = Keyword.fetch!(opts, :static_module)

    static_module.static_paths()
    |> Enum.map(fn path ->
      if String.contains?(path, ".") do
        ~s[starts_with(http.request.uri.path, "/#{path}")]
      else
        ~s[starts_with(http.request.uri.path, "/#{path}/")]
      end
    end)
  end

  defp extra_conditions(opts) do
    case Keyword.get(opts, :extra_paths, []) do
      [] -> []
      paths -> Enum.map(paths, &~s[starts_with(http.request.uri.path, "#{&1}")])
    end
  end

  # Cloudflare API

  defp find_ruleset!(zone_id, opts) do
    case cf_request(:get, "/zones/#{zone_id}/rulesets", opts) do
      %{"success" => true, "result" => rulesets} ->
        case Enum.find(rulesets, &(&1["phase"] == "http_request_firewall_custom")) do
          %{"id" => id} -> id
          nil -> Mix.raise("No http_request_firewall_custom ruleset found")
        end

      body ->
        Mix.raise("Failed to list rulesets: #{inspect(body)}")
    end
  end

  defp find_rule(zone_id, ruleset_id, rule_description, opts) do
    case cf_request(:get, "/zones/#{zone_id}/rulesets/#{ruleset_id}", opts) do
      %{"success" => true, "result" => %{"rules" => rules}} ->
        Enum.find(rules, &(&1["description"] == rule_description))

      body ->
        Mix.raise("Failed to list rules: #{inspect(body)}")
    end
  end

  defp create_rule!(zone_id, ruleset_id, body, opts) do
    case cf_request(:post, "/zones/#{zone_id}/rulesets/#{ruleset_id}/rules", opts, body) do
      %{"success" => true} ->
        :ok

      resp ->
        Mix.raise("Failed to create rule: #{inspect(resp)}")
    end
  end

  defp update_rule!(zone_id, ruleset_id, rule_id, body, opts) do
    case cf_request(
           :patch,
           "/zones/#{zone_id}/rulesets/#{ruleset_id}/rules/#{rule_id}",
           opts,
           body
         ) do
      %{"success" => true} ->
        :ok

      resp ->
        Mix.raise("Failed to update rule: #{inspect(resp)}")
    end
  end

  defp cf_request(method, path, opts, body \\ nil) do
    api_token = Keyword.fetch!(opts, :api_token)
    url = @base_url <> path
    headers = [{~c"Authorization", ~c"Bearer #{api_token}"}]

    ssl_opts = [
      ssl: [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        depth: 3
      ]
    ]

    request =
      case {method, body} do
        {:get, _} ->
          :httpc.request(:get, {url, headers}, ssl_opts, [])

        {m, body} when m in [:post, :patch] ->
          json_body = Jason.encode!(body)
          content_type = ~c"application/json"
          :httpc.request(m, {url, headers, content_type, json_body}, ssl_opts, [])
      end

    case request do
      {:ok, {{_, _status, _}, _resp_headers, resp_body}} ->
        Jason.decode!(to_string(resp_body))

      {:error, reason} ->
        Mix.raise("HTTP request failed: #{inspect(reason)}")
    end
  end
end
