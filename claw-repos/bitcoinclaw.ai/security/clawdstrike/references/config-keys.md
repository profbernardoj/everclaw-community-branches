# Config Keys Map

Use this map to reference configuration in evidence. Follow these steps:
1. Use only keys that appear in `config.summary`.
2. If a key is missing in `config.summary`, treat it as unknown and mark the check unverified when relevant.
3. Do not guess defaults. Use explicit config or built-in audit evidence.

## Gateway and Control UI
- `[REDACTED].bind`
- `[REDACTED].port`
- `[REDACTED].mode` (local/remote)
- `[REDACTED].auth.mode`
- `[REDACTED].auth.token`
- `[REDACTED].auth.password`
- `[REDACTED].auth.allowTailscale`
- `[REDACTED].trustedProxies`
- `[REDACTED].tailscale.mode` (off/serve/funnel)
- `[REDACTED].controlUi.enabled`
- `[REDACTED].controlUi.allowInsecureAuth`
- `[REDACTED].controlUi.dangerouslyDisableDeviceAuth`

## Discovery
- `discovery.mdns.mode`
- `discovery.mdns.interfaces`
- `discovery.wideArea.enabled`

## Canvas Host
- `canvasHost.enabled`
- `canvasHost.port`
- `canvasHost.root`
- `canvasHost.liveReload`

## Tools and Sandbox
- `tools.exec`
- `tools.elevated.enabled`
- `tools.elevated.allowFrom.*`
- `tools.web.search.enabled`
- `tools.web.search.apiKey`
- `tools.web.fetch.enabled`
- `browser.enabled`
- `browser.cdpUrl`
- `agents.defaults.sandbox.mode`
- `agents.defaults.sandbox.workspaceAccess`

## Sessions and Access
- `session.dmScope`
- `commands.native`
- `commands.nativeSkills`
- `commands.useAccessGroups`

## Channels (examples)
- `channels.defaults.groupPolicy`
- `channels.<provider>.dm.policy`
- `channels.<provider>.dm.allowFrom`
- `channels.<provider>.groupPolicy`
- `channels.<provider>.groupAllowFrom`
- `channels.<provider>.accounts.<id>.dm.policy`
- `channels.<provider>.accounts.<id>.dm.allowFrom`
- `channels.<provider>.accounts.<id>.groupPolicy`
- `channels.<provider>.accounts.<id>.groupAllowFrom`

## Skills and Plugins
- `skills.allowBundled`
- `skills.load.extraDirs`
- `skills.entries.<skillKey>.enabled`
- `skills.entries.<skillKey>.env`
- `skills.entries.<skillKey>.apiKey`
- `plugins.allow`
- `plugins.deny`
- `plugins.load.paths`

## Logging
- `logging.redactSensitive`
- `logging.file`
