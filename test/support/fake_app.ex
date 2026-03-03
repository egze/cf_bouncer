defmodule CfBouncer.Test.FakeRouter do
  def __routes__ do
    [
      %{path: "/"},
      %{path: "/users"},
      %{path: "/users/:id"},
      %{path: "/auth/login"},
      %{path: "/auth/callback"}
    ]
  end
end

defmodule CfBouncer.Test.FakeEndpoint do
  def __sockets__ do
    [
      {"/live", Phoenix.LiveView.Socket, []},
      {"/phoenix/live_reload/socket", Phoenix.LiveReloader.Socket, []}
    ]
  end
end

defmodule CfBouncer.Test.FakeStatic do
  def static_paths, do: ~w(assets fonts images robots.txt)
end
