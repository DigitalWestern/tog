defmodule Forced.MixProject do
  use Mix.Project

  # Project code mix evaluates by design: isolation, not a setting, is the control.
  File.touch!("@HIT@/mix-exs-eval")

  def project do
    [app: :forced, version: "0.1.0", deps: [{:jason, "~> 1.4"}]]
  end
end
