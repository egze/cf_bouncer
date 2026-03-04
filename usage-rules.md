# CfBouncer Usage Rules

CfBouncer syncs a Cloudflare WAF block rule from a Phoenix router. It blocks any request to a path not in the router, sockets, or static files.

## Configuration

All config goes under `:cf_bouncer`. Split between `config.exs` (compile-time) and `runtime.exs` (secrets):

```elixir
# config/config.exs
config :cf_bouncer,
  router: MyAppWeb.Router,
  endpoint: MyAppWeb.Endpoint,
  static_module: MyAppWeb,
  rule_description: "[CfBouncer] Block non-allowlisted paths"

# config/runtime.exs
config :cf_bouncer,
  zone_id: System.get_env("CLOUDFLARE_ZONE_ID"),
  api_token: System.get_env("CLOUDFLARE_API_TOKEN")
```

### Required keys

- `router` — Phoenix router module (must respond to `__routes__/0`)
- `endpoint` — Phoenix endpoint module (must respond to `__sockets__/0`)
- `static_module` — module with `static_paths/0` (typically your `MyAppWeb` module)
- `rule_description` — string used to find/create the rule in Cloudflare
- `zone_id` — Cloudflare Zone ID
- `api_token` — Cloudflare API token with Zone WAF + Firewall Services edit permissions

### Optional keys

- `extra_paths` — list of additional path prefixes to allow, e.g. `["/cf-fonts/", "/webhooks/"]`
- `force` — (sync only) push even if unchanged

## Programmatic usage

Pass config as a keyword list directly — useful outside of mix tasks:

```elixir
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
```

## Mix task

The only mix task is `mix cf_bouncer.sync`.

- `mix cf_bouncer.sync` — pushes the rule to Cloudflare (skips if unchanged)
- `mix cf_bouncer.sync --dry-run` — prints the generated expression without pushing
- `mix cf_bouncer.sync --force` — pushes the rule even if unchanged

## How the expression is built

1. Route prefixes are extracted from the router and deduplicated to top-level segments (e.g. `/users/123` becomes `/users`)
2. WebSocket paths from the endpoint (excluding `live_reload`)
3. Static paths from `static_paths/0` — paths with a `.` are treated as files, paths without as directories (trailing `/`)
4. Extra paths from config are added as-is

All conditions are joined with `or` and wrapped in `not (...)`. The expression is rendered via EEx.

## Common patterns

### Adding the task to a deploy script

Run `mix cf_bouncer.sync` locally before deploying, not on the server:

```sh
mix cf_bouncer.sync
# then rsync/deploy...
```

### Adding paths not in the router

Use `extra_paths` for proxied paths or paths served outside Phoenix:

```elixir
config :cf_bouncer,
  extra_paths: ["/cf-fonts/", "/stripe-webhooks/"]
```
