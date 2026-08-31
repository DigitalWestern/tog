defmodule ExReal.MixProject do
  use Mix.Project
  def project do
    [app: :ex_real, version: "0.1.0", elixir: "~> 1.15",
     deps: [{:jason, "~> 1.4"}, {:telemetry, "~> 1.2"}]]
  end
end
