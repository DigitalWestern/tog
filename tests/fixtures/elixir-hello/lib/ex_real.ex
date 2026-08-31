defmodule ExReal do
  def hello do
    :telemetry.execute([:demo], %{v: 1}, %{})
    Jason.encode!(%{beam: "ok"})
  end
end
