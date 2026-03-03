defmodule CfBouncerTest do
  use ExUnit.Case

  @zone_id "test-zone-123"
  @ruleset_id "ruleset-456"
  @rule_id "rule-789"
  @rule_description "[CfBouncer] Block non-allowlisted paths"

  @rulesets_path "/client/v4/zones/#{@zone_id}/rulesets"
  @ruleset_path "/client/v4/zones/#{@zone_id}/rulesets/#{@ruleset_id}"

  setup do
    Application.put_env(:cf_bouncer, :router, CfBouncer.Test.FakeRouter)
    Application.put_env(:cf_bouncer, :endpoint, CfBouncer.Test.FakeEndpoint)
    Application.put_env(:cf_bouncer, :static_module, CfBouncer.Test.FakeStatic)
    Application.put_env(:cf_bouncer, :rule_description, @rule_description)
    Application.put_env(:cf_bouncer, :zone_id, @zone_id)
    Application.put_env(:cf_bouncer, :api_token, "test-token")
    Application.put_env(:cf_bouncer, :plug, {Req.Test, CfBouncer})
    Application.delete_env(:cf_bouncer, :extra_paths)

    :ok
  end

  defp stub_rulesets(conn) do
    Req.Test.json(conn, %{
      success: true,
      result: [%{"id" => @ruleset_id, "phase" => "http_request_firewall_custom"}]
    })
  end

  defp stub_rules(conn, rules) do
    Req.Test.json(conn, %{success: true, result: %{"rules" => rules}})
  end

  describe "build_expression/0" do
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

      assert CfBouncer.build_expression() == expected
    end

    test "includes extra_paths sorted with the rest" do
      Application.put_env(:cf_bouncer, :extra_paths, ["/cf-fonts/", "/webhooks/"])

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

      assert CfBouncer.build_expression() == expected
    end
  end

  describe "sync/0" do
    test "creates rule when none exists" do
      Req.Test.stub(CfBouncer, fn conn ->
        case {conn.method, conn.request_path} do
          {"GET", @rulesets_path} -> stub_rulesets(conn)
          {"GET", @ruleset_path} -> stub_rules(conn, [])
          {"POST", _} -> Req.Test.json(conn, %{success: true})
        end
      end)

      assert CfBouncer.sync() == :created
    end

    test "returns up_to_date when expression matches" do
      expression = CfBouncer.build_expression()

      Req.Test.stub(CfBouncer, fn conn ->
        case {conn.method, conn.request_path} do
          {"GET", @rulesets_path} ->
            stub_rulesets(conn)

          {"GET", @ruleset_path} ->
            stub_rules(conn, [
              %{
                "id" => @rule_id,
                "description" => @rule_description,
                "expression" => expression
              }
            ])
        end
      end)

      assert CfBouncer.sync() == :up_to_date
    end

    test "updates rule when expression differs" do
      Req.Test.stub(CfBouncer, fn conn ->
        case {conn.method, conn.request_path} do
          {"GET", @rulesets_path} ->
            stub_rulesets(conn)

          {"GET", @ruleset_path} ->
            stub_rules(conn, [
              %{
                "id" => @rule_id,
                "description" => @rule_description,
                "expression" => "old expression"
              }
            ])

          {"PATCH", _} ->
            Req.Test.json(conn, %{success: true})
        end
      end)

      assert CfBouncer.sync() == :updated
    end

    test "force pushes even when expression matches" do
      expression = CfBouncer.build_expression()

      Req.Test.stub(CfBouncer, fn conn ->
        case {conn.method, conn.request_path} do
          {"GET", @rulesets_path} ->
            stub_rulesets(conn)

          {"GET", @ruleset_path} ->
            stub_rules(conn, [
              %{
                "id" => @rule_id,
                "description" => @rule_description,
                "expression" => expression
              }
            ])

          {"PATCH", _} ->
            Req.Test.json(conn, %{success: true})
        end
      end)

      assert CfBouncer.sync(force: true) == :updated
    end
  end
end
