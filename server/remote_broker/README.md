# Prewise Interactive remote broker

This service converts a one-time Prewise browser handshake into an ephemeral
Apache Guacamole JSON-auth connection. It never stores Windows passwords.

The broker uses AWS Systems Manager Run Command to create a restricted local
RDP user and installs an in-guest scheduled cleanup task before returning the
connection. At the lease boundary the task logs the user off and deletes it;
the broker also performs the same cleanup as a best-effort second path.

Required environment variables:

- `PREWISE_API_URL` (backend origin)
- `SANDBOX_REMOTE_BROKER_SECRET` (same 32+ byte value as the backend)
- `GUACAMOLE_URL` (for example `https://remote.prewise.site/guacamole`)
- `GUACAMOLE_JSON_SECRET_KEY` (16-byte/128-bit key encoded as 32 hex digits and configured
  in Guacamole's JSON authentication extension)
- `AWS_REGION`

The broker instance role needs only `ssm:SendCommand`,
`ssm:GetCommandInvocation`, and `ec2:DescribeInstances` for tagged interactive
workers. Windows AMIs must run SSM Agent and permit RDP only from Guacamole.

Run with access logging disabled so one-time query tokens never enter logs:

```sh
uvicorn server.remote_broker.app:create_app --factory --host 0.0.0.0 --port 8080 --no-access-log
```
