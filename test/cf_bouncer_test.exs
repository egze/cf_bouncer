defmodule CfBouncerTest do
  use ExUnit.Case
  use Mimic

  @zone_id "test-zone-123"
  @ruleset_id "ruleset-456"
  @rule_id "rule-789"
  @rule_description "[CfBouncer] Block non-allowlisted paths"

  @base_opts [
    router: CfBouncer.Test.FakeRouter,
    endpoint: CfBouncer.Test.FakeEndpoint,
    static_module: CfBouncer.Test.FakeStatic,
    rule_description: @rule_description,
    zone_id: @zone_id,
    api_token: "test-token"
  ]

  defp json_response(body) do
    {:ok, {{~c"HTTP/1.1", 200, ~c"OK"}, [], Jason.encode!(body) |> to_charlist()}}
  end

  describe "build_expression/1" do
    test "builds the full expression from routes, sockets, and static paths" do
      expected = """
      not (
        http.request.uri.path eq "/"
        or starts_with(http.request.uri.path, "/assets/")
        or starts_with(http.request.uri.path, "/auth")
        or starts_with(http.request.uri.path, "/fonts/")
        or starts_with(http.request.uri.path, "/images/")
        or starts_with(http.request.uri.path, "/live")
        or starts_with(http.request.uri.path, "/robots.txt")
        or starts_with(http.request.uri.path, "/users")
      )\
      """

      assert CfBouncer.build_expression(@base_opts) == expected
    end

    test "includes extra_paths sorted with the rest" do
      opts = Keyword.put(@base_opts, :extra_paths, ["/cf-fonts/", "/webhooks/"])

      expected = """
      not (
        http.request.uri.path eq "/"
        or starts_with(http.request.uri.path, "/assets/")
        or starts_with(http.request.uri.path, "/auth")
        or starts_with(http.request.uri.path, "/cf-fonts/")
        or starts_with(http.request.uri.path, "/fonts/")
        or starts_with(http.request.uri.path, "/images/")
        or starts_with(http.request.uri.path, "/live")
        or starts_with(http.request.uri.path, "/robots.txt")
        or starts_with(http.request.uri.path, "/users")
        or starts_with(http.request.uri.path, "/webhooks/")
      )\
      """

      assert CfBouncer.build_expression(opts) == expected
    end
  end

  describe "sync/1" do
    test "creates rule when none exists" do
      stub(:httpc, :request, fn
        :get, {url, _headers}, _ssl_opts, _opts ->
          cond do
            String.ends_with?(url, "/rulesets") ->
              json_response(%{
                success: true,
                result: [%{"id" => @ruleset_id, "phase" => "http_request_firewall_custom"}]
              })

            String.ends_with?(url, "/rulesets/#{@ruleset_id}") ->
              json_response(%{success: true, result: %{"rules" => []}})
          end

        :post, {_url, _headers, _content_type, _body}, _ssl_opts, _opts ->
          json_response(%{success: true})
      end)

      assert CfBouncer.sync(@base_opts) == :created
    end

    test "returns up_to_date when expression matches" do
      expression = CfBouncer.build_expression(@base_opts)

      stub(:httpc, :request, fn :get, {url, _headers}, _ssl_opts, _opts ->
        cond do
          String.ends_with?(url, "/rulesets") ->
            json_response(%{
              success: true,
              result: [%{"id" => @ruleset_id, "phase" => "http_request_firewall_custom"}]
            })

          String.ends_with?(url, "/rulesets/#{@ruleset_id}") ->
            json_response(%{
              success: true,
              result: %{
                "rules" => [
                  %{
                    "id" => @rule_id,
                    "description" => @rule_description,
                    "expression" => expression
                  }
                ]
              }
            })
        end
      end)

      assert CfBouncer.sync(@base_opts) == :up_to_date
    end

    test "updates rule when expression differs" do
      stub(:httpc, :request, fn
        :get, {url, _headers}, _ssl_opts, _opts ->
          cond do
            String.ends_with?(url, "/rulesets") ->
              json_response(%{
                success: true,
                result: [%{"id" => @ruleset_id, "phase" => "http_request_firewall_custom"}]
              })

            String.ends_with?(url, "/rulesets/#{@ruleset_id}") ->
              json_response(%{
                success: true,
                result: %{
                  "rules" => [
                    %{
                      "id" => @rule_id,
                      "description" => @rule_description,
                      "expression" => "old expression"
                    }
                  ]
                }
              })
          end

        :patch, {_url, _headers, _content_type, _body}, _ssl_opts, _opts ->
          json_response(%{success: true})
      end)

      assert CfBouncer.sync(@base_opts) == :updated
    end

    test "force pushes even when expression matches" do
      expression = CfBouncer.build_expression(@base_opts)

      stub(:httpc, :request, fn
        :get, {url, _headers}, _ssl_opts, _opts ->
          cond do
            String.ends_with?(url, "/rulesets") ->
              json_response(%{
                success: true,
                result: [%{"id" => @ruleset_id, "phase" => "http_request_firewall_custom"}]
              })

            String.ends_with?(url, "/rulesets/#{@ruleset_id}") ->
              json_response(%{
                success: true,
                result: %{
                  "rules" => [
                    %{
                      "id" => @rule_id,
                      "description" => @rule_description,
                      "expression" => expression
                    }
                  ]
                }
              })
          end

        :patch, {_url, _headers, _content_type, _body}, _ssl_opts, _opts ->
          json_response(%{success: true})
      end)

      assert CfBouncer.sync(Keyword.put(@base_opts, :force, true)) == :updated
    end
  end
end
