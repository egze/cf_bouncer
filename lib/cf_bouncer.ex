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
  """

  @doc """
  Builds the WAF expression string from configured routes, sockets, and static paths.
  """
  def build_expression do
    route_conditions = route_conditions()
    static_conditions = static_conditions()
    extra_conditions = extra_conditions()

    all_conditions =
      (route_conditions ++ static_conditions ++ extra_conditions)
      |> Enum.uniq()
      |> Enum.sort()

    "not (\n  " <> Enum.join(all_conditions, "\n  or ") <> "\n)"
  end

  @doc """
  Syncs the WAF rule to Cloudflare. Creates the rule if it doesn't exist,
  updates it if the expression changed, or skips if already up to date.

  Returns `:created`, `:updated`, or `:up_to_date`.
  """
  def sync(opts \\ []) do
    force = Keyword.get(opts, :force, false)
    expression = build_expression()
    zone_id = config!(:zone_id)
    rule_description = config!(:rule_description)

    ruleset_id = find_ruleset!(zone_id)
    rule = find_rule(zone_id, ruleset_id, rule_description)

    body = %{
      action: "block",
      expression: expression,
      description: rule_description
    }

    case rule do
      nil ->
        create_rule!(zone_id, ruleset_id, body)
        :created

      %{"expression" => ^expression} when not force ->
        :up_to_date

      %{"id" => rule_id} ->
        update_rule!(zone_id, ruleset_id, rule_id, body)
        :updated
    end
  end

  # Expression building

  defp route_conditions do
    config!(:router).__routes__()
    |> Enum.map(& &1.path)
    |> Enum.uniq()
    |> Enum.map(fn "/" <> rest ->
      case String.split(rest, "/") do
        [""] -> "/"
        [first | _] -> "/#{first}"
      end
    end)
    |> Enum.concat(socket_prefixes())
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.map(fn
      "/" -> ~s[http.request.uri.path eq "/"]
      prefix -> ~s[starts_with(http.request.uri.path, "#{prefix}")]
    end)
  end

  defp socket_prefixes do
    config!(:endpoint).__sockets__()
    |> Enum.map(fn {path, _module, _opts} -> path end)
    |> Enum.reject(&String.contains?(&1, "live_reload"))
  end

  defp static_conditions do
    config!(:static_module).static_paths()
    |> Enum.map(fn path ->
      if String.contains?(path, ".") do
        ~s[starts_with(http.request.uri.path, "/#{path}")]
      else
        ~s[starts_with(http.request.uri.path, "/#{path}/")]
      end
    end)
  end

  defp extra_conditions do
    case Application.get_env(:cf_bouncer, :extra_paths, []) do
      [] -> []
      paths -> Enum.map(paths, &~s[starts_with(http.request.uri.path, "#{&1}")])
    end
  end

  # Cloudflare API

  defp req do
    opts = [
      base_url: "https://api.cloudflare.com/client/v4",
      headers: [{"Authorization", "Bearer #{config!(:api_token)}"}]
    ]

    opts =
      case Application.get_env(:cf_bouncer, :plug) do
        nil -> opts
        plug -> Keyword.put(opts, :plug, plug)
      end

    Req.new(opts)
  end

  defp find_ruleset!(zone_id) do
    case cf_get("/zones/#{zone_id}/rulesets") do
      %{"success" => true, "result" => rulesets} ->
        case Enum.find(rulesets, &(&1["phase"] == "http_request_firewall_custom")) do
          %{"id" => id} -> id
          nil -> Mix.raise("No http_request_firewall_custom ruleset found")
        end

      body ->
        Mix.raise("Failed to list rulesets: #{inspect(body)}")
    end
  end

  defp find_rule(zone_id, ruleset_id, rule_description) do
    case cf_get("/zones/#{zone_id}/rulesets/#{ruleset_id}") do
      %{"success" => true, "result" => %{"rules" => rules}} ->
        Enum.find(rules, &(&1["description"] == rule_description))

      body ->
        Mix.raise("Failed to list rules: #{inspect(body)}")
    end
  end

  defp create_rule!(zone_id, ruleset_id, body) do
    case Req.post(req(), url: "/zones/#{zone_id}/rulesets/#{ruleset_id}/rules", json: body) do
      {:ok, %{body: %{"success" => true}}} ->
        :ok

      {:ok, %{status: status, body: body}} ->
        Mix.raise("Failed to create rule (#{status}): #{inspect(body)}")

      {:error, reason} ->
        Mix.raise("Request failed: #{inspect(reason)}")
    end
  end

  defp update_rule!(zone_id, ruleset_id, rule_id, body) do
    case Req.patch(req(), url: "/zones/#{zone_id}/rulesets/#{ruleset_id}/rules/#{rule_id}", json: body) do
      {:ok, %{body: %{"success" => true}}} ->
        :ok

      {:ok, %{status: status, body: body}} ->
        Mix.raise("Failed to update rule (#{status}): #{inspect(body)}")

      {:error, reason} ->
        Mix.raise("Request failed: #{inspect(reason)}")
    end
  end

  defp cf_get(path) do
    {:ok, %{body: body}} = Req.get(req(), url: path)
    body
  end

  # Config

  defp config!(key) do
    Application.get_env(:cf_bouncer, key) ||
      Mix.raise("Missing :cf_bouncer config: #{inspect(key)}")
  end
end
