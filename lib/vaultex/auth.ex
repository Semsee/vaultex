defmodule Vaultex.Auth do
  @moduledoc """
  Handles initial authentication to the Vault server.

  Uses one of the authN methods to obtain a token and stores that token in
  our GenServer's state for re-use.
  """
  alias Vaultex.RedirectableRequests, as: VaultReq

  def handle(:approle, {role_id, %{wrapped: wrapping_token}}, state) do
    case VaultReq.request(:put, "#{state.url}sys/wrapping/unwrap", nil, [{"x-vault-token", wrapping_token}]) do
      {:ok, %Req.Response{} = resp} ->
        case resp.body do
          %{"data" => %{"secret_id" => secret_id}} ->
            handle(:approle, %{role_id: role_id, secret_id: secret_id}, state)

          %{"errors" => err_list} ->
            reasons = Enum.join(err_list, ", ")

            {:reply, {:error, ["Unexpected response from [#{state.url}]", reasons]}, state}

          _body ->
            reason = "Could not unwrap token - no secret_id in data"

            {:reply, {:error, ["Unexpected response from [#{state.url}]", reason]}, state}
        end

      {:error, %{reason: reason}} ->
        {:reply, {:error, ["Bad unwrap response from vault [#{state.url}]", reason]}, state}

      {:error, exp} ->
        reason = Exception.message(exp)

        {:reply, {:error, ["Bad unwrap response from vault [#{state.url}]", reason]}, state}
    end
  end

  def handle(:approle, {role_id, secret_id}, state) do
    handle(:approle, %{role_id: role_id, secret_id: secret_id}, state)
  end

  def handle(:app_id, {app_id, user_id}, state) do
    handle(:app_id, %{app_id: app_id, user_id: user_id}, state)
  end

  def handle(:aws_iam, {role, server}, state) do
    handle(:aws, Vaultex.Auth.AWSIAM.credentials(role, server), state)
  end

  def handle(:userpass, {username, password}, state) do
    handle(:userpass, %{username: username, password: password}, state)
  end

  def handle(:ldap, {username, password}, state) do
    handle(:ldap, %{username: username, password: password}, state)
  end

  def handle(:github, {token}, state) do
    handle(:github, %{token: token}, state)
  end

  def handle(:token, {token}, state) do
    VaultReq.request(:get, "#{state.url}auth/token/lookup-self", nil, [{"x-vault-token", token}])
    |> handle_response(state)
  end

  # auth method with usernames are expected to call `POST auth/:method/login/:username`
  def handle(method, %{username: username} = credentials, state) do
    VaultReq.request(:post, "#{state.url}auth/#{method}/login/#{username}", credentials, [])
    |> handle_response(state)
  end

  # Generic login behavior for most methods
  def handle(method, credentials, state) when is_map(credentials) do
    VaultReq.request(:post, "#{state.url}auth/#{method}/login", credentials, [])
    |> handle_response(state)
  end

  defp handle_response({:ok, %Req.Response{} = response}, state) do
    case response.body do
      %{"errors" => messages} ->
        {:reply, {:error, messages}, state}

      %{"auth" => nil, "data" => data} ->
        {:reply, {:ok, :authenticated}, Map.merge(state, %{token: data["id"]})}

      %{"auth" => properties} ->
        queue_renewable_token(properties)

        {:reply, {:ok, :authenticated}, Map.merge(state, %{token: properties["client_token"]})}
    end
  end

  defp handle_response({:error, exception}, state) do
    reason =
      case exception do
        %{reason: reason} -> reason
        _ -> Exception.message(exception)
      end

    {:reply, {:error, ["Bad response from vault [#{state.url}]", reason]}, state}
  end

  # Renews our `token` in state via a call to `/auth/token/renew-self`
  def renew_token(%{token: token} = state) do
    headers = [{"x-vault-token", token}]

    case VaultReq.request(:post, "#{state.url}auth/token/renew-self", nil, headers) do
      {:ok, %Req.Response{body: %{"auth" => auth_info}}} ->
        queue_renewable_token(auth_info)

        {:noreply, Map.merge(state, %{token: auth_info["client_token"]})}

      _err ->
        {:noreply, state}
    end
  end

  def renew_token(state) do
    {:noreply, state}
  end

  defp queue_renewable_token(auth_info) do
    if auth_info["renewable"] do
      lease_duration = auth_info["lease_duration"]
      renew_after_secs = max(round(lease_duration * 0.85), 1)

      Process.send_after(self(), :renew_token, renew_after_secs * 1_000)
    end
  end
end
