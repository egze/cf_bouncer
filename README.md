# CfBouncer

Automatically syncs a Cloudflare WAF block rule from your Phoenix router. Any request to a path not defined in your routes, sockets, or static files gets blocked.

Keeps your WAF in sync with your code — run it in your deploy script and forget about it.

## How it works

1. Reads all route prefixes from your Phoenix router
2. Reads WebSocket paths from your endpoint
3. Reads static file paths from your web module
4. Builds a Cloudflare WAF expression that blocks everything else
5. Pushes the rule to Cloudflare (only if it changed)

## Installation

Add `cf_bouncer` to your dependencies:

```elixir
def deps do
  [
    {:cf_bouncer, github: "egze/cf_bouncer"}
  ]
end
```

## Configuration

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

### Options

| Key                | Required | Description                                                                 |
|--------------------|----------|-----------------------------------------------------------------------------|
| `router`           | yes      | Your Phoenix router module (e.g. `MyAppWeb.Router`)                         |
| `endpoint`         | yes      | Your Phoenix endpoint module (e.g. `MyAppWeb.Endpoint`)                     |
| `static_module`    | yes      | Module with `static_paths/0` (e.g. `MyAppWeb`)                             |
| `rule_description` | yes      | Description used to identify the rule in Cloudflare                         |
| `zone_id`          | yes      | Cloudflare Zone ID (see below)                                              |
| `api_token`        | yes      | Cloudflare API token with Zone WAF and Firewall Services edit permissions   |
| `extra_paths`      | no       | Additional path prefixes to allow (e.g. `["/cf-fonts/", "/webhooks/"]`)     |

### Cloudflare Zone ID

Found in the Cloudflare dashboard: select your domain, then look in the right sidebar on the **Overview** page under **API** > **Zone ID**.

### Cloudflare API token

Create at https://dash.cloudflare.com/profile/api-tokens. Use the **"Edit zone WAF"** template, or create a custom token with these permissions scoped to your zone:

- Zone > Zone WAF > Edit
- Zone > Firewall Services > Edit

## Usage

Preview the generated WAF expression:

```sh
mix cf_bouncer.sync --dry-run
```

Push to Cloudflare:

```sh
mix cf_bouncer.sync
```

Force push even if unchanged:

```sh
mix cf_bouncer.sync --force
```

The rule is only updated if the expression has changed. Use `--force` to push regardless.

### In a deploy script

```sh
echo "Updating Cloudflare WAF..."
mix cf_bouncer.sync

echo "Syncing files..."
# ... rest of deploy
```

## Generated expression

The generated expression looks like:

```
not (
  http.request.uri.path eq "/"
  or starts_with(http.request.uri.path, "/auth")
  or starts_with(http.request.uri.path, "/users")
  or starts_with(http.request.uri.path, "/live")
  or starts_with(http.request.uri.path, "/assets/")
  or starts_with(http.request.uri.path, "/images/")
  or starts_with(http.request.uri.path, "/robots.txt")
  or starts_with(http.request.uri.path, "/cf-fonts/")
)
```

Static paths containing a `.` (like `robots.txt`) are treated as files. Paths without a `.` (like `assets`) are treated as directories and get a trailing `/`.
