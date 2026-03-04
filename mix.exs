defmodule CfBouncer.MixProject do
  use Mix.Project

  @source_url "https://github.com/egze/cf_bouncer"

  def project do
    [
      app: :cf_bouncer,
      version: "0.1.0",
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description: "Sync Cloudflare WAF rules from your Phoenix router",
      source_url: @source_url,
      homepage_url: @source_url,
      docs: [
        main: "readme",
        extras: ["README.md"]
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :inets, :ssl]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md usage-rules.md LICENSE.md)
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:mimic, "~> 1.0", only: :test},
      {:ex_doc, "~> 0.35", only: :dev, runtime: false}
    ]
  end
end
