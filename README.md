# GitHub v3 REST API MCP Server 🔧

![npm version](https://img.shields.io/npm/v/@sargonpiraev/github-mcp-server)
![npm downloads](https://img.shields.io/npm/dw/@sargonpiraev/github-mcp-server)
![license](https://img.shields.io/github/license/sargonpiraev/github-mcp-server)
![pipeline status](https://gitlab.com/sargonpiraev/github-mcp-server/badges/main/pipeline.svg)
![smithery badge](https://smithery.ai/badge/@sargonpiraev/github-mcp-server)
![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-blue)
[![Join Discord](https://img.shields.io/discord/1331631275464671347?color=7289da&label=Discord&logo=discord)](https://discord.gg/ZsWGxRGj)

## Features

- 🔌 **Seamless AI Integration**: Direct GitHub v3 REST API API access from Claude, Cursor, and VS Code
- 🤖 **Automated Workflows**: Automate GitHub v3 REST API operations and data access
- 📊 **Complete API Coverage**: 1039+ tools covering all major GitHub v3 REST API features
- ⚡ **Real-time Access**: Access GitHub v3 REST API data instantly from AI assistants
- 🔧 **Professional Integration**: Error handling, validation, and comprehensive logging

## Get Your Credentials

Before installation, you'll need a GitHub v3 REST API API key:

1. Open GitHub v3 REST API app or web interface
2. Go to **Settings → Account → API Access**
3. Generate new API key or copy existing one
4. Save this key for the installation steps below

## Requirements

- Node.js >= v18.0.0
- GitHub v3 REST API API key
- Cursor, VS Code, Claude Desktop or another MCP Client

## Installation

<details>
<summary><b>Installing via Smithery</b></summary>

To install GitHub v3 REST API MCP Server for any client automatically via [Smithery](https://smithery.ai):

```bash
npx -y @smithery/cli@latest install @sargonpiraev/github-mcp-server --client <CLIENT_NAME>
```

</details>

<details>
<summary><b>Install in Cursor</b></summary>

#### Cursor One-Click Installation

[![Install MCP Server](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/install-mcp?name=@sargonpiraev/github-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBzYXJnb25waXJhZXYvZ2l0aHViLW1jcC1zZXJ2ZXIiXSwiZW52Ijp7IkdJVEhVQl9BUElfS0VZIjoieW91cl9naXRodWJfYXBpX2tleV9oZXJlIn19)

#### Manual Configuration

Add to your Cursor `~/.cursor/mcp.json` file:

```json
{
  "mcpServers": {
    "github-mcp-server": {
      "command": "npx",
      "args": ["-y", "@sargonpiraev/github-mcp-server"],
      "env": {
        "GITHUB_API_KEY": "your-github_api_key"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Install in VS Code</b></summary>

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_MCP-0098FF)](vscode:mcp/install?%7B%22name%22%3A%22github-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22@sargonpiraev/github-mcp-server%22%5D%7D)

Or add manually to your VS Code settings:

```json
"mcp": {
  "servers": {
    "github-mcp-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@sargonpiraev/github-mcp-server"],
      "env": {
        "GITHUB_API_KEY": "your-github_api_key"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Install in Claude Desktop</b></summary>

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "github-mcp-server": {
      "command": "npx",
      "args": ["-y", "@sargonpiraev/github-mcp-server"],
      "env": {
        "GITHUB_API_KEY": "your-github_api_key"
      }
    }
  }
}
```

</details>

## Available Tools

- **`meta/root`**: GitHub API Root
- **`security-advisories/list-global-advisories`**: List global security advisories
- **`security-advisories/get-global-advisory`**: Get a global security advisory
- **`apps/get-authenticated`**: Get the authenticated app
- **`apps/create-from-manifest`**: Create a GitHub App from a manifest
- **`apps/get-webhook-config-for-app`**: Get a webhook configuration for an app
- **`apps/update-webhook-config-for-app`**: Update a webhook configuration for an app
- **`apps/list-webhook-deliveries`**: List deliveries for an app webhook
- **`apps/get-webhook-delivery`**: Get a delivery for an app webhook
- **`apps/redeliver-webhook-delivery`**: Redeliver a delivery for an app webhook
- **`apps/list-installation-requests-for-authenticated-app`**: List installation requests for the authenticated app
- **`apps/list-installations`**: List installations for the authenticated app
- **`apps/get-installation`**: Get an installation for the authenticated app
- **`apps/delete-installation`**: Delete an installation for the authenticated app
- **`apps/create-installation-access-token`**: Create an installation access token for an app
- **`apps/suspend-installation`**: Suspend an app installation
- **`apps/unsuspend-installation`**: Unsuspend an app installation
- **`apps/delete-authorization`**: Delete an app authorization
- **`apps/check-token`**: Check a token
- **`apps/reset-token`**: Reset a token
- **`apps/delete-token`**: Delete an app token
- **`apps/scope-token`**: Create a scoped access token
- **`apps/get-by-slug`**: Get an app
- **`classroom/get-an-assignment`**: Get an assignment
- **`classroom/list-accepted-assignments-for-an-assignment`**: List accepted assignments for an assignment
- **`classroom/get-assignment-grades`**: Get assignment grades
- **`classroom/list-classrooms`**: List classrooms
- **`classroom/get-a-classroom`**: Get a classroom
- **`classroom/list-assignments-for-a-classroom`**: List assignments for a classroom
- **`codes-of-conduct/get-all-codes-of-conduct`**: Get all codes of conduct
- **`codes-of-conduct/get-conduct-code`**: Get a code of conduct
- **`credentials/revoke`**: Revoke a list of credentials
- **`emojis/get`**: Get emojis
- **`code-security/get-configurations-for-enterprise`**: Get code security configurations for an enterprise
- **`code-security/create-configuration-for-enterprise`**: Create a code security configuration for an enterprise
- **`code-security/get-default-configurations-for-enterprise`**: Get default code security configurations for an enterprise
- **`code-security/get-single-configuration-for-enterprise`**: Retrieve a code security configuration of an enterprise
- **`code-security/update-enterprise-configuration`**: Update a custom code security configuration for an enterprise
- **`code-security/delete-configuration-for-enterprise`**: Delete a code security configuration for an enterprise
- **`code-security/attach-enterprise-configuration`**: Attach an enterprise configuration to repositories
- **`code-security/set-configuration-as-default-for-enterprise`**: Set a code security configuration as a default for an enterprise
- **`code-security/get-repositories-for-enterprise-configuration`**: Get repositories associated with an enterprise code security configuration
- **`dependabot/list-alerts-for-enterprise`**: List Dependabot alerts for an enterprise
- **`secret-scanning/list-alerts-for-enterprise`**: List secret scanning alerts for an enterprise
- **`activity/list-public-events`**: List public events
- **`activity/get-feeds`**: Get feeds
- **`gists/list`**: List gists for the authenticated user
- **`gists/create`**: Create a gist
- **`gists/list-public`**: List public gists
- **`gists/list-starred`**: List starred gists
- **`gists/get`**: Get a gist
- **`gists/update`**: Update a gist
- **`gists/delete`**: Delete a gist
- **`gists/list-comments`**: List gist comments
- **`gists/create-comment`**: Create a gist comment
- **`gists/get-comment`**: Get a gist comment
- **`gists/update-comment`**: Update a gist comment
- **`gists/delete-comment`**: Delete a gist comment
- **`gists/list-commits`**: List gist commits
- **`gists/list-forks`**: List gist forks
- **`gists/fork`**: Fork a gist
- **`gists/check-is-starred`**: Check if a gist is starred
- **`gists/star`**: Star a gist
- **`gists/unstar`**: Unstar a gist
- **`gists/get-revision`**: Get a gist revision
- **`gitignore/get-all-templates`**: Get all gitignore templates
- **`gitignore/get-template`**: Get a gitignore template
- **`apps/list-repos-accessible-to-installation`**: List repositories accessible to the app installation
- **`apps/revoke-installation-access-token`**: Revoke an installation access token
- **`issues/list`**: List issues assigned to the authenticated user
- **`licenses/get-all-commonly-used`**: Get all commonly used licenses
- **`licenses/get`**: Get a license
- **`markdown/render`**: Render a Markdown document
- **`markdown/render-raw`**: Render a Markdown document in raw mode
- **`apps/get-subscription-plan-for-account`**: Get a subscription plan for an account
- **`apps/list-plans`**: List plans
- **`apps/list-accounts-for-plan`**: List accounts for a plan
- **`apps/get-subscription-plan-for-account-stubbed`**: Get a subscription plan for an account (stubbed)
- **`apps/list-plans-stubbed`**: List plans (stubbed)
- **`apps/list-accounts-for-plan-stubbed`**: List accounts for a plan (stubbed)
- **`meta/get`**: Get GitHub meta information
- **`activity/list-public-events-for-repo-network`**: List public events for a network of repositories
- **`activity/list-notifications-for-authenticated-user`**: List notifications for the authenticated user
- **`activity/mark-notifications-as-read`**: Mark notifications as read
- **`activity/get-thread`**: Get a thread
- **`activity/mark-thread-as-read`**: Mark a thread as read
- **`activity/mark-thread-as-done`**: Mark a thread as done
- **`activity/get-thread-subscription-for-authenticated-user`**: Get a thread subscription for the authenticated user
- **`activity/set-thread-subscription`**: Set a thread subscription
- **`activity/delete-thread-subscription`**: Delete a thread subscription
- **`meta/get-octocat`**: Get Octocat
- **`orgs/list`**: List organizations
- **`dependabot/repository-access-for-org`**: Lists the repositories Dependabot can access in an organization
- **`dependabot/update-repository-access-for-org`**: Updates Dependabot&#x27;s repository access list for an organization
- **`dependabot/set-repository-access-default-level`**: Set the default repository access level for Dependabot
- **`billing/get-github-billing-usage-report-org`**: Get billing usage report for an organization
- **`orgs/get`**: Get an organization
- **`orgs/update`**: Update an organization
- **`orgs/delete`**: Delete an organization
- **`actions/get-actions-cache-usage-for-org`**: Get GitHub Actions cache usage for an organization
- **`actions/get-actions-cache-usage-by-repo-for-org`**: List repositories with GitHub Actions cache usage for an organization
- **`actions/list-hosted-runners-for-org`**: List GitHub-hosted runners for an organization
- **`actions/create-hosted-runner-for-org`**: Create a GitHub-hosted runner for an organization
- **`actions/get-hosted-runners-github-owned-images-for-org`**: Get GitHub-owned images for GitHub-hosted runners in an organization
- **`actions/get-hosted-runners-partner-images-for-org`**: Get partner images for GitHub-hosted runners in an organization
- **`actions/get-hosted-runners-limits-for-org`**: Get limits on GitHub-hosted runners for an organization
- **`actions/get-hosted-runners-machine-specs-for-org`**: Get GitHub-hosted runners machine specs for an organization
- **`actions/get-hosted-runners-platforms-for-org`**: Get platforms for GitHub-hosted runners in an organization
- **`actions/get-hosted-runner-for-org`**: Get a GitHub-hosted runner for an organization
- **`actions/update-hosted-runner-for-org`**: Update a GitHub-hosted runner for an organization
- **`actions/delete-hosted-runner-for-org`**: Delete a GitHub-hosted runner for an organization
- **`oidc/get-oidc-custom-sub-template-for-org`**: Get the customization template for an OIDC subject claim for an organization
- **`oidc/update-oidc-custom-sub-template-for-org`**: Set the customization template for an OIDC subject claim for an organization
- **`actions/get-github-actions-permissions-organization`**: Get GitHub Actions permissions for an organization
- **`actions/set-github-actions-permissions-organization`**: Set GitHub Actions permissions for an organization
- **`actions/list-selected-repositories-enabled-github-actions-organization`**: List selected repositories enabled for GitHub Actions in an organization
- **`actions/set-selected-repositories-enabled-github-actions-organization`**: Set selected repositories enabled for GitHub Actions in an organization
- **`actions/enable-selected-repository-github-actions-organization`**: Enable a selected repository for GitHub Actions in an organization
- **`actions/disable-selected-repository-github-actions-organization`**: Disable a selected repository for GitHub Actions in an organization
- **`actions/get-allowed-actions-organization`**: Get allowed actions and reusable workflows for an organization
- **`actions/set-allowed-actions-organization`**: Set allowed actions and reusable workflows for an organization
- **`actions/get-github-actions-default-workflow-permissions-organization`**: Get default workflow permissions for an organization
- **`actions/set-github-actions-default-workflow-permissions-organization`**: Set default workflow permissions for an organization
- **`actions/list-self-hosted-runner-groups-for-org`**: List self-hosted runner groups for an organization
- **`actions/create-self-hosted-runner-group-for-org`**: Create a self-hosted runner group for an organization
- **`actions/get-self-hosted-runner-group-for-org`**: Get a self-hosted runner group for an organization
- **`actions/update-self-hosted-runner-group-for-org`**: Update a self-hosted runner group for an organization
- **`actions/delete-self-hosted-runner-group-from-org`**: Delete a self-hosted runner group from an organization
- **`actions/list-github-hosted-runners-in-group-for-org`**: List GitHub-hosted runners in a group for an organization
- **`actions/list-repo-access-to-self-hosted-runner-group-in-org`**: List repository access to a self-hosted runner group in an organization
- **`actions/set-repo-access-to-self-hosted-runner-group-in-org`**: Set repository access for a self-hosted runner group in an organization
- **`actions/add-repo-access-to-self-hosted-runner-group-in-org`**: Add repository access to a self-hosted runner group in an organization
- **`actions/remove-repo-access-to-self-hosted-runner-group-in-org`**: Remove repository access to a self-hosted runner group in an organization
- **`actions/list-self-hosted-runners-in-group-for-org`**: List self-hosted runners in a group for an organization
- **`actions/set-self-hosted-runners-in-group-for-org`**: Set self-hosted runners in a group for an organization
- **`actions/add-self-hosted-runner-to-group-for-org`**: Add a self-hosted runner to a group for an organization
- **`actions/remove-self-hosted-runner-from-group-for-org`**: Remove a self-hosted runner from a group for an organization
- **`actions/list-self-hosted-runners-for-org`**: List self-hosted runners for an organization
- **`actions/list-runner-applications-for-org`**: List runner applications for an organization
- **`actions/generate-runner-jitconfig-for-org`**: Create configuration for a just-in-time runner for an organization
- **`actions/create-registration-token-for-org`**: Create a registration token for an organization
- **`actions/create-remove-token-for-org`**: Create a remove token for an organization
- **`actions/get-self-hosted-runner-for-org`**: Get a self-hosted runner for an organization
- **`actions/delete-self-hosted-runner-from-org`**: Delete a self-hosted runner from an organization
- **`actions/list-labels-for-self-hosted-runner-for-org`**: List labels for a self-hosted runner for an organization
- **`actions/add-custom-labels-to-self-hosted-runner-for-org`**: Add custom labels to a self-hosted runner for an organization
- **`actions/set-custom-labels-for-self-hosted-runner-for-org`**: Set custom labels for a self-hosted runner for an organization
- **`actions/remove-all-custom-labels-from-self-hosted-runner-for-org`**: Remove all custom labels from a self-hosted runner for an organization
- **`actions/remove-custom-label-from-self-hosted-runner-for-org`**: Remove a custom label from a self-hosted runner for an organization
- **`actions/list-org-secrets`**: List organization secrets
- **`actions/get-org-public-key`**: Get an organization public key
- **`actions/get-org-secret`**: Get an organization secret
- **`actions/create-or-update-org-secret`**: Create or update an organization secret
- **`actions/delete-org-secret`**: Delete an organization secret
- **`actions/list-selected-repos-for-org-secret`**: List selected repositories for an organization secret
- **`actions/set-selected-repos-for-org-secret`**: Set selected repositories for an organization secret
- **`actions/add-selected-repo-to-org-secret`**: Add selected repository to an organization secret
- **`actions/remove-selected-repo-from-org-secret`**: Remove selected repository from an organization secret
- **`actions/list-org-variables`**: List organization variables
- **`actions/create-org-variable`**: Create an organization variable
- **`actions/get-org-variable`**: Get an organization variable
- **`actions/update-org-variable`**: Update an organization variable
- **`actions/delete-org-variable`**: Delete an organization variable
- **`actions/list-selected-repos-for-org-variable`**: List selected repositories for an organization variable
- **`actions/set-selected-repos-for-org-variable`**: Set selected repositories for an organization variable
- **`actions/add-selected-repo-to-org-variable`**: Add selected repository to an organization variable
- **`actions/remove-selected-repo-from-org-variable`**: Remove selected repository from an organization variable
- **`orgs/list-attestations-bulk`**: List attestations by bulk subject digests
- **`orgs/delete-attestations-bulk`**: Delete attestations in bulk
- **`orgs/delete-attestations-by-subject-digest`**: Delete attestations by subject digest
- **`orgs/delete-attestations-by-id`**: Delete attestations by ID
- **`orgs/list-attestations`**: List attestations
- **`orgs/list-blocked-users`**: List users blocked by an organization
- **`orgs/check-blocked-user`**: Check if a user is blocked by an organization
- **`orgs/block-user`**: Block a user from an organization
- **`orgs/unblock-user`**: Unblock a user from an organization
- **`campaigns/list-org-campaigns`**: List campaigns for an organization
- **`campaigns/create-campaign`**: Create a campaign for an organization
- **`campaigns/get-campaign-summary`**: Get a campaign for an organization
- **`campaigns/update-campaign`**: Update a campaign
- **`campaigns/delete-campaign`**: Delete a campaign for an organization
- **`code-scanning/list-alerts-for-org`**: List code scanning alerts for an organization
- **`code-security/get-configurations-for-org`**: Get code security configurations for an organization
- **`code-security/create-configuration`**: Create a code security configuration
- **`code-security/get-default-configurations`**: Get default code security configurations
- **`code-security/detach-configuration`**: Detach configurations from repositories
- **`code-security/get-configuration`**: Get a code security configuration
- **`code-security/update-configuration`**: Update a code security configuration
- **`code-security/delete-configuration`**: Delete a code security configuration
- **`code-security/attach-configuration`**: Attach a configuration to repositories
- **`code-security/set-configuration-as-default`**: Set a code security configuration as a default for an organization
- **`code-security/get-repositories-for-configuration`**: Get repositories associated with a code security configuration
- **`codespaces/list-in-organization`**: List codespaces for the organization
- **`codespaces/set-codespaces-access`**: Manage access control for organization codespaces
- **`codespaces/set-codespaces-access-users`**: Add users to Codespaces access for an organization
- **`codespaces/delete-codespaces-access-users`**: Remove users from Codespaces access for an organization
- **`codespaces/list-org-secrets`**: List organization secrets
- **`codespaces/get-org-public-key`**: Get an organization public key
- **`codespaces/get-org-secret`**: Get an organization secret
- **`codespaces/create-or-update-org-secret`**: Create or update an organization secret
- **`codespaces/delete-org-secret`**: Delete an organization secret
- **`codespaces/list-selected-repos-for-org-secret`**: List selected repositories for an organization secret
- **`codespaces/set-selected-repos-for-org-secret`**: Set selected repositories for an organization secret
- **`codespaces/add-selected-repo-to-org-secret`**: Add selected repository to an organization secret
- **`codespaces/remove-selected-repo-from-org-secret`**: Remove selected repository from an organization secret
- **`copilot/get-copilot-organization-details`**: Get Copilot seat information and settings for an organization
- **`copilot/list-copilot-seats`**: List all Copilot seat assignments for an organization
- **`copilot/add-copilot-seats-for-teams`**: Add teams to the Copilot subscription for an organization
- **`copilot/cancel-copilot-seat-assignment-for-teams`**: Remove teams from the Copilot subscription for an organization
- **`copilot/add-copilot-seats-for-users`**: Add users to the Copilot subscription for an organization
- **`copilot/cancel-copilot-seat-assignment-for-users`**: Remove users from the Copilot subscription for an organization
- **`copilot/copilot-metrics-for-organization`**: Get Copilot metrics for an organization
- **`dependabot/list-alerts-for-org`**: List Dependabot alerts for an organization
- **`dependabot/list-org-secrets`**: List organization secrets
- **`dependabot/get-org-public-key`**: Get an organization public key
- **`dependabot/get-org-secret`**: Get an organization secret
- **`dependabot/create-or-update-org-secret`**: Create or update an organization secret
- **`dependabot/delete-org-secret`**: Delete an organization secret
- **`dependabot/list-selected-repos-for-org-secret`**: List selected repositories for an organization secret
- **`dependabot/set-selected-repos-for-org-secret`**: Set selected repositories for an organization secret
- **`dependabot/add-selected-repo-to-org-secret`**: Add selected repository to an organization secret
- **`dependabot/remove-selected-repo-from-org-secret`**: Remove selected repository from an organization secret
- **`packages/list-docker-migration-conflicting-packages-for-organization`**: Get list of conflicting packages during Docker migration for organization
- **`activity/list-public-org-events`**: List public organization events
- **`orgs/list-failed-invitations`**: List failed organization invitations
- **`orgs/list-webhooks`**: List organization webhooks
- **`orgs/create-webhook`**: Create an organization webhook
- **`orgs/get-webhook`**: Get an organization webhook
- **`orgs/update-webhook`**: Update an organization webhook
- **`orgs/delete-webhook`**: Delete an organization webhook
- **`orgs/get-webhook-config-for-org`**: Get a webhook configuration for an organization
- **`orgs/update-webhook-config-for-org`**: Update a webhook configuration for an organization
- **`orgs/list-webhook-deliveries`**: List deliveries for an organization webhook
- **`orgs/get-webhook-delivery`**: Get a webhook delivery for an organization webhook
- **`orgs/redeliver-webhook-delivery`**: Redeliver a delivery for an organization webhook
- **`orgs/ping-webhook`**: Ping an organization webhook
- **`api-insights/get-route-stats-by-actor`**: Get route stats by actor
- **`api-insights/get-subject-stats`**: Get subject stats
- **`api-insights/get-summary-stats`**: Get summary stats
- **`api-insights/get-summary-stats-by-user`**: Get summary stats by user
- **`api-insights/get-summary-stats-by-actor`**: Get summary stats by actor
- **`api-insights/get-time-stats`**: Get time stats
- **`api-insights/get-time-stats-by-user`**: Get time stats by user
- **`api-insights/get-time-stats-by-actor`**: Get time stats by actor
- **`api-insights/get-user-stats`**: Get user stats
- **`apps/get-org-installation`**: Get an organization installation for the authenticated app
- **`orgs/list-app-installations`**: List app installations for an organization
- **`interactions/get-restrictions-for-org`**: Get interaction restrictions for an organization
- **`interactions/set-restrictions-for-org`**: Set interaction restrictions for an organization
- **`interactions/remove-restrictions-for-org`**: Remove interaction restrictions for an organization
- **`orgs/list-pending-invitations`**: List pending organization invitations
- **`orgs/create-invitation`**: Create an organization invitation
- **`orgs/cancel-invitation`**: Cancel an organization invitation
- **`orgs/list-invitation-teams`**: List organization invitation teams
- **`orgs/list-issue-types`**: List issue types for an organization
- **`orgs/create-issue-type`**: Create issue type for an organization
- **`orgs/update-issue-type`**: Update issue type for an organization
- **`orgs/delete-issue-type`**: Delete issue type for an organization
- **`issues/list-for-org`**: List organization issues assigned to the authenticated user
- **`orgs/list-members`**: List organization members
- **`orgs/check-membership-for-user`**: Check organization membership for a user
- **`orgs/remove-member`**: Remove an organization member
- **`codespaces/get-codespaces-for-user-in-org`**: List codespaces for a user in organization
- **`codespaces/delete-from-organization`**: Delete a codespace from the organization
- **`codespaces/stop-in-organization`**: Stop a codespace for an organization user
- **`copilot/get-copilot-seat-details-for-user`**: Get Copilot seat assignment details for a user
- **`orgs/get-membership-for-user`**: Get organization membership for a user
- **`orgs/set-membership-for-user`**: Set organization membership for a user
- **`orgs/remove-membership-for-user`**: Remove organization membership for a user
- **`migrations/list-for-org`**: List organization migrations
- **`migrations/start-for-org`**: Start an organization migration
- **`migrations/get-status-for-org`**: Get an organization migration status
- **`migrations/download-archive-for-org`**: Download an organization migration archive
- **`migrations/delete-archive-for-org`**: Delete an organization migration archive
- **`migrations/unlock-repo-for-org`**: Unlock an organization repository
- **`migrations/list-repos-for-org`**: List repositories in an organization migration
- **`orgs/list-org-roles`**: Get all organization roles for an organization
- **`orgs/revoke-all-org-roles-team`**: Remove all organization roles for a team
- **`orgs/assign-team-to-org-role`**: Assign an organization role to a team
- **`orgs/revoke-org-role-team`**: Remove an organization role from a team
- **`orgs/revoke-all-org-roles-user`**: Remove all organization roles for a user
- **`orgs/assign-user-to-org-role`**: Assign an organization role to a user
- **`orgs/revoke-org-role-user`**: Remove an organization role from a user
- **`orgs/get-org-role`**: Get an organization role
- **`orgs/list-org-role-teams`**: List teams that are assigned to an organization role
- **`orgs/list-org-role-users`**: List users that are assigned to an organization role
- **`orgs/list-outside-collaborators`**: List outside collaborators for an organization
- **`orgs/convert-member-to-outside-collaborator`**: Convert an organization member to outside collaborator
- **`orgs/remove-outside-collaborator`**: Remove outside collaborator from an organization
- **`packages/list-packages-for-organization`**: List packages for an organization
- **`packages/get-package-for-organization`**: Get a package for an organization
- **`packages/delete-package-for-org`**: Delete a package for an organization
- **`packages/restore-package-for-org`**: Restore a package for an organization
- **`packages/get-all-package-versions-for-package-owned-by-org`**: List package versions for a package owned by an organization
- **`packages/get-package-version-for-organization`**: Get a package version for an organization
- **`packages/delete-package-version-for-org`**: Delete package version for an organization
- **`packages/restore-package-version-for-org`**: Restore package version for an organization
- **`orgs/list-pat-grant-requests`**: List requests to access organization resources with fine-grained personal access tokens
- **`orgs/review-pat-grant-requests-in-bulk`**: Review requests to access organization resources with fine-grained personal access tokens
- **`orgs/review-pat-grant-request`**: Review a request to access organization resources with a fine-grained personal access token
- **`orgs/list-pat-grant-request-repositories`**: List repositories requested to be accessed by a fine-grained personal access token
- **`orgs/list-pat-grants`**: List fine-grained personal access tokens with access to organization resources
- **`orgs/update-pat-accesses`**: Update the access to organization resources via fine-grained personal access tokens
- **`orgs/update-pat-access`**: Update the access a fine-grained personal access token has to organization resources
- **`orgs/list-pat-grant-repositories`**: List repositories a fine-grained personal access token has access to
- **`private-registries/list-org-private-registries`**: List private registries for an organization
- **`private-registries/create-org-private-registry`**: Create a private registry for an organization
- **`private-registries/get-org-public-key`**: Get private registries public key for an organization
- **`private-registries/get-org-private-registry`**: Get a private registry for an organization
- **`private-registries/update-org-private-registry`**: Update a private registry for an organization
- **`private-registries/delete-org-private-registry`**: Delete a private registry for an organization
- **`projects-classic/list-for-org`**: List organization projects
- **`projects-classic/create-for-org`**: Create an organization project
- **`orgs/get-all-custom-properties`**: Get all custom properties for an organization
- **`orgs/create-or-update-custom-properties`**: Create or update custom properties for an organization
- **`orgs/get-custom-property`**: Get a custom property for an organization
- **`orgs/create-or-update-custom-property`**: Create or update a custom property for an organization
- **`orgs/remove-custom-property`**: Remove a custom property for an organization
- **`orgs/list-custom-properties-values-for-repos`**: List custom property values for organization repositories
- **`orgs/create-or-update-custom-properties-values-for-repos`**: Create or update custom property values for organization repositories
- **`orgs/list-public-members`**: List public organization members
- **`orgs/check-public-membership-for-user`**: Check public organization membership for a user
- **`orgs/set-public-membership-for-authenticated-user`**: Set public organization membership for the authenticated user
- **`orgs/remove-public-membership-for-authenticated-user`**: Remove public organization membership for the authenticated user
- **`repos/list-for-org`**: List organization repositories
- **`repos/create-in-org`**: Create an organization repository
- **`repos/get-org-rulesets`**: Get all organization repository rulesets
- **`repos/create-org-ruleset`**: Create an organization repository ruleset
- **`repos/get-org-rule-suites`**: List organization rule suites
- **`repos/get-org-rule-suite`**: Get an organization rule suite
- **`repos/get-org-ruleset`**: Get an organization repository ruleset
- **`repos/update-org-ruleset`**: Update an organization repository ruleset
- **`repos/delete-org-ruleset`**: Delete an organization repository ruleset
- **`orgs/get-org-ruleset-history`**: Get organization ruleset history
- **`orgs/get-org-ruleset-version`**: Get organization ruleset version
- **`secret-scanning/list-alerts-for-org`**: List secret scanning alerts for an organization
- **`security-advisories/list-org-repository-advisories`**: List repository security advisories for an organization
- **`orgs/list-security-manager-teams`**: List security manager teams
- **`orgs/add-security-manager-team`**: Add a security manager team
- **`orgs/remove-security-manager-team`**: Remove a security manager team
- **`billing/get-github-actions-billing-org`**: Get GitHub Actions billing for an organization
- **`billing/get-github-packages-billing-org`**: Get GitHub Packages billing for an organization
- **`billing/get-shared-storage-billing-org`**: Get shared storage billing for an organization
- **`hosted-compute/list-network-configurations-for-org`**: List hosted compute network configurations for an organization
- **`hosted-compute/create-network-configuration-for-org`**: Create a hosted compute network configuration for an organization
- **`hosted-compute/get-network-configuration-for-org`**: Get a hosted compute network configuration for an organization
- **`hosted-compute/update-network-configuration-for-org`**: Update a hosted compute network configuration for an organization
- **`hosted-compute/delete-network-configuration-from-org`**: Delete a hosted compute network configuration from an organization
- **`hosted-compute/get-network-settings-for-org`**: Get a hosted compute network settings resource for an organization
- **`copilot/copilot-metrics-for-team`**: Get Copilot metrics for a team
- **`teams/list`**: List teams
- **`teams/create`**: Create a team
- **`teams/get-by-name`**: Get a team by name
- **`teams/update-in-org`**: Update a team
- **`teams/delete-in-org`**: Delete a team
- **`teams/list-discussions-in-org`**: List discussions
- **`teams/create-discussion-in-org`**: Create a discussion
- **`teams/get-discussion-in-org`**: Get a discussion
- **`teams/update-discussion-in-org`**: Update a discussion
- **`teams/delete-discussion-in-org`**: Delete a discussion
- **`teams/list-discussion-comments-in-org`**: List discussion comments
- **`teams/create-discussion-comment-in-org`**: Create a discussion comment
- **`teams/get-discussion-comment-in-org`**: Get a discussion comment
- **`teams/update-discussion-comment-in-org`**: Update a discussion comment
- **`teams/delete-discussion-comment-in-org`**: Delete a discussion comment
- **`reactions/list-for-team-discussion-comment-in-org`**: List reactions for a team discussion comment
- **`reactions/create-for-team-discussion-comment-in-org`**: Create reaction for a team discussion comment
- **`reactions/delete-for-team-discussion-comment`**: Delete team discussion comment reaction
- **`reactions/list-for-team-discussion-in-org`**: List reactions for a team discussion
- **`reactions/create-for-team-discussion-in-org`**: Create reaction for a team discussion
- **`reactions/delete-for-team-discussion`**: Delete team discussion reaction
- **`teams/list-pending-invitations-in-org`**: List pending team invitations
- **`teams/list-members-in-org`**: List team members
- **`teams/get-membership-for-user-in-org`**: Get team membership for a user
- **`teams/add-or-update-membership-for-user-in-org`**: Add or update team membership for a user
- **`teams/remove-membership-for-user-in-org`**: Remove team membership for a user
- **`teams/list-projects-in-org`**: List team projects
- **`teams/check-permissions-for-project-in-org`**: Check team permissions for a project
- **`teams/add-or-update-project-permissions-in-org`**: Add or update team project permissions
- **`teams/remove-project-in-org`**: Remove a project from a team
- **`teams/list-repos-in-org`**: List team repositories
- **`teams/check-permissions-for-repo-in-org`**: Check team permissions for a repository
- **`teams/add-or-update-repo-permissions-in-org`**: Add or update team repository permissions
- **`teams/remove-repo-in-org`**: Remove a repository from a team
- **`teams/list-child-in-org`**: List child teams
- **`orgs/enable-or-disable-security-product-on-all-org-repos`**: Enable or disable a security feature for an organization
- **`projects-classic/get-card`**: Get a project card
- **`projects-classic/update-card`**: Update an existing project card
- **`projects-classic/delete-card`**: Delete a project card
- **`projects-classic/move-card`**: Move a project card
- **`projects-classic/get-column`**: Get a project column
- **`projects-classic/update-column`**: Update an existing project column
- **`projects-classic/delete-column`**: Delete a project column
- **`projects-classic/list-cards`**: List project cards
- **`projects-classic/create-card`**: Create a project card
- **`projects-classic/move-column`**: Move a project column
- **`projects-classic/get`**: Get a project
- **`projects-classic/update`**: Update a project
- **`projects-classic/delete`**: Delete a project
- **`projects-classic/list-collaborators`**: List project collaborators
- **`projects-classic/add-collaborator`**: Add project collaborator
- **`projects-classic/remove-collaborator`**: Remove user as a collaborator
- **`projects-classic/get-permission-for-user`**: Get project permission for a user
- **`projects-classic/list-columns`**: List project columns
- **`projects-classic/create-column`**: Create a project column
- **`rate-limit/get`**: Get rate limit status for the authenticated user
- **`repos/get`**: Get a repository
- **`repos/update`**: Update a repository
- **`repos/delete`**: Delete a repository
- **`actions/list-artifacts-for-repo`**: List artifacts for a repository
- **`actions/get-artifact`**: Get an artifact
- **`actions/delete-artifact`**: Delete an artifact
- **`actions/download-artifact`**: Download an artifact
- **`actions/get-actions-cache-usage`**: Get GitHub Actions cache usage for a repository
- **`actions/get-actions-cache-list`**: List GitHub Actions caches for a repository
- **`actions/delete-actions-cache-by-key`**: Delete GitHub Actions caches for a repository (using a cache key)
- **`actions/delete-actions-cache-by-id`**: Delete a GitHub Actions cache for a repository (using a cache ID)
- **`actions/get-job-for-workflow-run`**: Get a job for a workflow run
- **`actions/download-job-logs-for-workflow-run`**: Download job logs for a workflow run
- **`actions/re-run-job-for-workflow-run`**: Re-run a job from a workflow run
- **`actions/get-custom-oidc-sub-claim-for-repo`**: Get the customization template for an OIDC subject claim for a repository
- **`actions/set-custom-oidc-sub-claim-for-repo`**: Set the customization template for an OIDC subject claim for a repository
- **`actions/list-repo-organization-secrets`**: List repository organization secrets
- **`actions/list-repo-organization-variables`**: List repository organization variables
- **`actions/get-github-actions-permissions-repository`**: Get GitHub Actions permissions for a repository
- **`actions/set-github-actions-permissions-repository`**: Set GitHub Actions permissions for a repository
- **`actions/get-workflow-access-to-repository`**: Get the level of access for workflows outside of the repository
- **`actions/set-workflow-access-to-repository`**: Set the level of access for workflows outside of the repository
- **`actions/get-allowed-actions-repository`**: Get allowed actions and reusable workflows for a repository
- **`actions/set-allowed-actions-repository`**: Set allowed actions and reusable workflows for a repository
- **`actions/get-github-actions-default-workflow-permissions-repository`**: Get default workflow permissions for a repository
- **`actions/set-github-actions-default-workflow-permissions-repository`**: Set default workflow permissions for a repository
- **`actions/list-self-hosted-runners-for-repo`**: List self-hosted runners for a repository
- **`actions/list-runner-applications-for-repo`**: List runner applications for a repository
- **`actions/generate-runner-jitconfig-for-repo`**: Create configuration for a just-in-time runner for a repository
- **`actions/create-registration-token-for-repo`**: Create a registration token for a repository
- **`actions/create-remove-token-for-repo`**: Create a remove token for a repository
- **`actions/get-self-hosted-runner-for-repo`**: Get a self-hosted runner for a repository
- **`actions/delete-self-hosted-runner-from-repo`**: Delete a self-hosted runner from a repository
- **`actions/list-labels-for-self-hosted-runner-for-repo`**: List labels for a self-hosted runner for a repository
- **`actions/add-custom-labels-to-self-hosted-runner-for-repo`**: Add custom labels to a self-hosted runner for a repository
- **`actions/set-custom-labels-for-self-hosted-runner-for-repo`**: Set custom labels for a self-hosted runner for a repository
- **`actions/remove-all-custom-labels-from-self-hosted-runner-for-repo`**: Remove all custom labels from a self-hosted runner for a repository
- **`actions/remove-custom-label-from-self-hosted-runner-for-repo`**: Remove a custom label from a self-hosted runner for a repository
- **`actions/list-workflow-runs-for-repo`**: List workflow runs for a repository
- **`actions/get-workflow-run`**: Get a workflow run
- **`actions/delete-workflow-run`**: Delete a workflow run
- **`actions/get-reviews-for-run`**: Get the review history for a workflow run
- **`actions/approve-workflow-run`**: Approve a workflow run for a fork pull request
- **`actions/list-workflow-run-artifacts`**: List workflow run artifacts
- **`actions/get-workflow-run-attempt`**: Get a workflow run attempt
- **`actions/list-jobs-for-workflow-run-attempt`**: List jobs for a workflow run attempt
- **`actions/download-workflow-run-attempt-logs`**: Download workflow run attempt logs
- **`actions/cancel-workflow-run`**: Cancel a workflow run
- **`actions/review-custom-gates-for-run`**: Review custom deployment protection rules for a workflow run
- **`actions/force-cancel-workflow-run`**: Force cancel a workflow run
- **`actions/list-jobs-for-workflow-run`**: List jobs for a workflow run
- **`actions/download-workflow-run-logs`**: Download workflow run logs
- **`actions/delete-workflow-run-logs`**: Delete workflow run logs
- **`actions/get-pending-deployments-for-run`**: Get pending deployments for a workflow run
- **`actions/review-pending-deployments-for-run`**: Review pending deployments for a workflow run
- **`actions/re-run-workflow`**: Re-run a workflow
- **`actions/re-run-workflow-failed-jobs`**: Re-run failed jobs from a workflow run
- **`actions/get-workflow-run-usage`**: Get workflow run usage
- **`actions/list-repo-secrets`**: List repository secrets
- **`actions/get-repo-public-key`**: Get a repository public key
- **`actions/get-repo-secret`**: Get a repository secret
- **`actions/create-or-update-repo-secret`**: Create or update a repository secret
- **`actions/delete-repo-secret`**: Delete a repository secret
- **`actions/list-repo-variables`**: List repository variables
- **`actions/create-repo-variable`**: Create a repository variable
- **`actions/get-repo-variable`**: Get a repository variable
- **`actions/update-repo-variable`**: Update a repository variable
- **`actions/delete-repo-variable`**: Delete a repository variable
- **`actions/list-repo-workflows`**: List repository workflows
- **`actions/get-workflow`**: Get a workflow
- **`actions/disable-workflow`**: Disable a workflow
- **`actions/create-workflow-dispatch`**: Create a workflow dispatch event
- **`actions/enable-workflow`**: Enable a workflow
- **`actions/list-workflow-runs`**: List workflow runs for a workflow
- **`actions/get-workflow-usage`**: Get workflow usage
- **`repos/list-activities`**: List repository activities
- **`issues/list-assignees`**: List assignees
- **`issues/check-user-can-be-assigned`**: Check if a user can be assigned
- **`repos/create-attestation`**: Create an attestation
- **`repos/list-attestations`**: List attestations
- **`repos/list-autolinks`**: Get all autolinks of a repository
- **`repos/create-autolink`**: Create an autolink reference for a repository
- **`repos/get-autolink`**: Get an autolink reference of a repository
- **`repos/delete-autolink`**: Delete an autolink reference from a repository
- **`repos/check-automated-security-fixes`**: Check if Dependabot security updates are enabled for a repository
- **`repos/enable-automated-security-fixes`**: Enable Dependabot security updates
- **`repos/disable-automated-security-fixes`**: Disable Dependabot security updates
- **`repos/list-branches`**: List branches
- **`repos/get-branch`**: Get a branch
- **`repos/get-branch-protection`**: Get branch protection
- **`repos/update-branch-protection`**: Update branch protection
- **`repos/delete-branch-protection`**: Delete branch protection
- **`repos/get-admin-branch-protection`**: Get admin branch protection
- **`repos/set-admin-branch-protection`**: Set admin branch protection
- **`repos/delete-admin-branch-protection`**: Delete admin branch protection
- **`repos/get-pull-request-review-protection`**: Get pull request review protection
- **`repos/update-pull-request-review-protection`**: Update pull request review protection
- **`repos/delete-pull-request-review-protection`**: Delete pull request review protection
- **`repos/get-commit-signature-protection`**: Get commit signature protection
- **`repos/create-commit-signature-protection`**: Create commit signature protection
- **`repos/delete-commit-signature-protection`**: Delete commit signature protection
- **`repos/get-status-checks-protection`**: Get status checks protection
- **`repos/update-status-check-protection`**: Update status check protection
- **`repos/remove-status-check-protection`**: Remove status check protection
- **`repos/get-all-status-check-contexts`**: Get all status check contexts
- **`repos/add-status-check-contexts`**: Add status check contexts
- **`repos/set-status-check-contexts`**: Set status check contexts
- **`repos/remove-status-check-contexts`**: Remove status check contexts
- **`repos/get-access-restrictions`**: Get access restrictions
- **`repos/delete-access-restrictions`**: Delete access restrictions
- **`repos/get-apps-with-access-to-protected-branch`**: Get apps with access to the protected branch
- **`repos/add-app-access-restrictions`**: Add app access restrictions
- **`repos/set-app-access-restrictions`**: Set app access restrictions
- **`repos/remove-app-access-restrictions`**: Remove app access restrictions
- **`repos/get-teams-with-access-to-protected-branch`**: Get teams with access to the protected branch
- **`repos/add-team-access-restrictions`**: Add team access restrictions
- **`repos/set-team-access-restrictions`**: Set team access restrictions
- **`repos/remove-team-access-restrictions`**: Remove team access restrictions
- **`repos/get-users-with-access-to-protected-branch`**: Get users with access to the protected branch
- **`repos/add-user-access-restrictions`**: Add user access restrictions
- **`repos/set-user-access-restrictions`**: Set user access restrictions
- **`repos/remove-user-access-restrictions`**: Remove user access restrictions
- **`repos/rename-branch`**: Rename a branch
- **`checks/create`**: Create a check run
- **`checks/get`**: Get a check run
- **`checks/update`**: Update a check run
- **`checks/list-annotations`**: List check run annotations
- **`checks/rerequest-run`**: Rerequest a check run
- **`checks/create-suite`**: Create a check suite
- **`checks/set-suites-preferences`**: Update repository preferences for check suites
- **`checks/get-suite`**: Get a check suite
- **`checks/list-for-suite`**: List check runs in a check suite
- **`checks/rerequest-suite`**: Rerequest a check suite
- **`code-scanning/list-alerts-for-repo`**: List code scanning alerts for a repository
- **`code-scanning/get-alert`**: Get a code scanning alert
- **`code-scanning/update-alert`**: Update a code scanning alert
- **`code-scanning/get-autofix`**: Get the status of an autofix for a code scanning alert
- **`code-scanning/create-autofix`**: Create an autofix for a code scanning alert
- **`code-scanning/commit-autofix`**: Commit an autofix for a code scanning alert
- **`code-scanning/list-alert-instances`**: List instances of a code scanning alert
- **`code-scanning/list-recent-analyses`**: List code scanning analyses for a repository
- **`code-scanning/get-analysis`**: Get a code scanning analysis for a repository
- **`code-scanning/delete-analysis`**: Delete a code scanning analysis from a repository
- **`code-scanning/list-codeql-databases`**: List CodeQL databases for a repository
- **`code-scanning/get-codeql-database`**: Get a CodeQL database for a repository
- **`code-scanning/delete-codeql-database`**: Delete a CodeQL database
- **`code-scanning/create-variant-analysis`**: Create a CodeQL variant analysis
- **`code-scanning/get-variant-analysis`**: Get the summary of a CodeQL variant analysis
- **`code-scanning/get-variant-analysis-repo-task`**: Get the analysis status of a repository in a CodeQL variant analysis
- **`code-scanning/get-default-setup`**: Get a code scanning default setup configuration
- **`code-scanning/update-default-setup`**: Update a code scanning default setup configuration
- **`code-scanning/upload-sarif`**: Upload an analysis as SARIF data
- **`code-scanning/get-sarif`**: Get information about a SARIF upload
- **`code-security/get-configuration-for-repository`**: Get the code security configuration associated with a repository
- **`repos/codeowners-errors`**: List CODEOWNERS errors
- **`codespaces/list-in-repository-for-authenticated-user`**: List codespaces in a repository for the authenticated user
- **`codespaces/create-with-repo-for-authenticated-user`**: Create a codespace in a repository
- **`codespaces/list-devcontainers-in-repository-for-authenticated-user`**: List devcontainer configurations in a repository for the authenticated user
- **`codespaces/repo-machines-for-authenticated-user`**: List available machine types for a repository
- **`codespaces/pre-flight-with-repo-for-authenticated-user`**: Get default attributes for a codespace
- **`codespaces/check-permissions-for-devcontainer`**: Check if permissions defined by a devcontainer have been accepted by the authenticated user
- **`codespaces/list-repo-secrets`**: List repository secrets
- **`codespaces/get-repo-public-key`**: Get a repository public key
- **`codespaces/get-repo-secret`**: Get a repository secret
- **`codespaces/create-or-update-repo-secret`**: Create or update a repository secret
- **`codespaces/delete-repo-secret`**: Delete a repository secret
- **`repos/list-collaborators`**: List repository collaborators
- **`repos/check-collaborator`**: Check if a user is a repository collaborator
- **`repos/add-collaborator`**: Add a repository collaborator
- **`repos/remove-collaborator`**: Remove a repository collaborator
- **`repos/get-collaborator-permission-level`**: Get repository permissions for a user
- **`repos/list-commit-comments-for-repo`**: List commit comments for a repository
- **`repos/get-commit-comment`**: Get a commit comment
- **`repos/update-commit-comment`**: Update a commit comment
- **`repos/delete-commit-comment`**: Delete a commit comment
- **`reactions/list-for-commit-comment`**: List reactions for a commit comment
- **`reactions/create-for-commit-comment`**: Create reaction for a commit comment
- **`reactions/delete-for-commit-comment`**: Delete a commit comment reaction
- **`repos/list-commits`**: List commits
- **`repos/list-branches-for-head-commit`**: List branches for HEAD commit
- **`repos/list-comments-for-commit`**: List commit comments
- **`repos/create-commit-comment`**: Create a commit comment
- **`repos/list-pull-requests-associated-with-commit`**: List pull requests associated with a commit
- **`repos/get-commit`**: Get a commit
- **`checks/list-for-ref`**: List check runs for a Git reference
- **`checks/list-suites-for-ref`**: List check suites for a Git reference
- **`repos/get-combined-status-for-ref`**: Get the combined status for a specific reference
- **`repos/list-commit-statuses-for-ref`**: List commit statuses for a reference
- **`repos/get-community-profile-metrics`**: Get community profile metrics
- **`repos/compare-commits`**: Compare two commits
- **`repos/get-content`**: Get repository content
- **`repos/create-or-update-file-contents`**: Create or update file contents
- **`repos/delete-file`**: Delete a file
- **`repos/list-contributors`**: List repository contributors
- **`dependabot/list-alerts-for-repo`**: List Dependabot alerts for a repository
- **`dependabot/get-alert`**: Get a Dependabot alert
- **`dependabot/update-alert`**: Update a Dependabot alert
- **`dependabot/list-repo-secrets`**: List repository secrets
- **`dependabot/get-repo-public-key`**: Get a repository public key
- **`dependabot/get-repo-secret`**: Get a repository secret
- **`dependabot/create-or-update-repo-secret`**: Create or update a repository secret
- **`dependabot/delete-repo-secret`**: Delete a repository secret
- **`dependency-graph/diff-range`**: Get a diff of the dependencies between commits
- **`dependency-graph/export-sbom`**: Export a software bill of materials (SBOM) for a repository.
- **`dependency-graph/create-repository-snapshot`**: Create a snapshot of dependencies for a repository
- **`repos/list-deployments`**: List deployments
- **`repos/create-deployment`**: Create a deployment
- **`repos/get-deployment`**: Get a deployment
- **`repos/delete-deployment`**: Delete a deployment
- **`repos/list-deployment-statuses`**: List deployment statuses
- **`repos/create-deployment-status`**: Create a deployment status
- **`repos/get-deployment-status`**: Get a deployment status
- **`repos/create-dispatch-event`**: Create a repository dispatch event
- **`repos/get-all-environments`**: List environments
- **`repos/get-environment`**: Get an environment
- **`repos/create-or-update-environment`**: Create or update an environment
- **`repos/delete-an-environment`**: Delete an environment
- **`repos/list-deployment-branch-policies`**: List deployment branch policies
- **`repos/create-deployment-branch-policy`**: Create a deployment branch policy
- **`repos/get-deployment-branch-policy`**: Get a deployment branch policy
- **`repos/update-deployment-branch-policy`**: Update a deployment branch policy
- **`repos/delete-deployment-branch-policy`**: Delete a deployment branch policy
- **`repos/get-all-deployment-protection-rules`**: Get all deployment protection rules for an environment
- **`repos/create-deployment-protection-rule`**: Create a custom deployment protection rule on an environment
- **`repos/list-custom-deployment-rule-integrations`**: List custom deployment rule integrations available for an environment
- **`repos/get-custom-deployment-protection-rule`**: Get a custom deployment protection rule
- **`repos/disable-deployment-protection-rule`**: Disable a custom protection rule for an environment
- **`actions/list-environment-secrets`**: List environment secrets
- **`actions/get-environment-public-key`**: Get an environment public key
- **`actions/get-environment-secret`**: Get an environment secret
- **`actions/create-or-update-environment-secret`**: Create or update an environment secret
- **`actions/delete-environment-secret`**: Delete an environment secret
- **`actions/list-environment-variables`**: List environment variables
- **`actions/create-environment-variable`**: Create an environment variable
- **`actions/get-environment-variable`**: Get an environment variable
- **`actions/update-environment-variable`**: Update an environment variable
- **`actions/delete-environment-variable`**: Delete an environment variable
- **`activity/list-repo-events`**: List repository events
- **`repos/list-forks`**: List forks
- **`repos/create-fork`**: Create a fork
- **`git/create-blob`**: Create a blob
- **`git/get-blob`**: Get a blob
- **`git/create-commit`**: Create a commit
- **`git/get-commit`**: Get a commit object
- **`git/list-matching-refs`**: List matching references
- **`git/get-ref`**: Get a reference
- **`git/create-ref`**: Create a reference
- **`git/update-ref`**: Update a reference
- **`git/delete-ref`**: Delete a reference
- **`git/create-tag`**: Create a tag object
- **`git/get-tag`**: Get a tag
- **`git/create-tree`**: Create a tree
- **`git/get-tree`**: Get a tree
- **`repos/list-webhooks`**: List repository webhooks
- **`repos/create-webhook`**: Create a repository webhook
- **`repos/get-webhook`**: Get a repository webhook
- **`repos/update-webhook`**: Update a repository webhook
- **`repos/delete-webhook`**: Delete a repository webhook
- **`repos/get-webhook-config-for-repo`**: Get a webhook configuration for a repository
- **`repos/update-webhook-config-for-repo`**: Update a webhook configuration for a repository
- **`repos/list-webhook-deliveries`**: List deliveries for a repository webhook
- **`repos/get-webhook-delivery`**: Get a delivery for a repository webhook
- **`repos/redeliver-webhook-delivery`**: Redeliver a delivery for a repository webhook
- **`repos/ping-webhook`**: Ping a repository webhook
- **`repos/test-push-webhook`**: Test the push repository webhook
- **`migrations/get-import-status`**: Get an import status
- **`migrations/start-import`**: Start an import
- **`migrations/update-import`**: Update an import
- **`migrations/cancel-import`**: Cancel an import
- **`migrations/get-commit-authors`**: Get commit authors
- **`migrations/map-commit-author`**: Map a commit author
- **`migrations/get-large-files`**: Get large files
- **`migrations/set-lfs-preference`**: Update Git LFS preference
- **`apps/get-repo-installation`**: Get a repository installation for the authenticated app
- **`interactions/get-restrictions-for-repo`**: Get interaction restrictions for a repository
- **`interactions/set-restrictions-for-repo`**: Set interaction restrictions for a repository
- **`interactions/remove-restrictions-for-repo`**: Remove interaction restrictions for a repository
- **`repos/list-invitations`**: List repository invitations
- **`repos/update-invitation`**: Update a repository invitation
- **`repos/delete-invitation`**: Delete a repository invitation
- **`issues/list-for-repo`**: List repository issues
- **`issues/create`**: Create an issue
- **`issues/list-comments-for-repo`**: List issue comments for a repository
- **`issues/get-comment`**: Get an issue comment
- **`issues/update-comment`**: Update an issue comment
- **`issues/delete-comment`**: Delete an issue comment
- **`reactions/list-for-issue-comment`**: List reactions for an issue comment
- **`reactions/create-for-issue-comment`**: Create reaction for an issue comment
- **`reactions/delete-for-issue-comment`**: Delete an issue comment reaction
- **`issues/list-events-for-repo`**: List issue events for a repository
- **`issues/get-event`**: Get an issue event
- **`issues/get`**: Get an issue
- **`issues/update`**: Update an issue
- **`issues/add-assignees`**: Add assignees to an issue
- **`issues/remove-assignees`**: Remove assignees from an issue
- **`issues/check-user-can-be-assigned-to-issue`**: Check if a user can be assigned to a issue
- **`issues/list-comments`**: List issue comments
- **`issues/create-comment`**: Create an issue comment
- **`issues/list-events`**: List issue events
- **`issues/list-labels-on-issue`**: List labels for an issue
- **`issues/add-labels`**: Add labels to an issue
- **`issues/set-labels`**: Set labels for an issue
- **`issues/remove-all-labels`**: Remove all labels from an issue
- **`issues/remove-label`**: Remove a label from an issue
- **`issues/lock`**: Lock an issue
- **`issues/unlock`**: Unlock an issue
- **`reactions/list-for-issue`**: List reactions for an issue
- **`reactions/create-for-issue`**: Create reaction for an issue
- **`reactions/delete-for-issue`**: Delete an issue reaction
- **`issues/remove-sub-issue`**: Remove sub-issue
- **`issues/list-sub-issues`**: List sub-issues
- **`issues/add-sub-issue`**: Add sub-issue
- **`issues/reprioritize-sub-issue`**: Reprioritize sub-issue
- **`issues/list-events-for-timeline`**: List timeline events for an issue
- **`repos/list-deploy-keys`**: List deploy keys
- **`repos/create-deploy-key`**: Create a deploy key
- **`repos/get-deploy-key`**: Get a deploy key
- **`repos/delete-deploy-key`**: Delete a deploy key
- **`issues/list-labels-for-repo`**: List labels for a repository
- **`issues/create-label`**: Create a label
- **`issues/get-label`**: Get a label
- **`issues/update-label`**: Update a label
- **`issues/delete-label`**: Delete a label
- **`repos/list-languages`**: List repository languages
- **`licenses/get-for-repo`**: Get the license for a repository
- **`repos/merge-upstream`**: Sync a fork branch with the upstream repository
- **`repos/merge`**: Merge a branch
- **`issues/list-milestones`**: List milestones
- **`issues/create-milestone`**: Create a milestone
- **`issues/get-milestone`**: Get a milestone
- **`issues/update-milestone`**: Update a milestone
- **`issues/delete-milestone`**: Delete a milestone
- **`issues/list-labels-for-milestone`**: List labels for issues in a milestone
- **`activity/list-repo-notifications-for-authenticated-user`**: List repository notifications for the authenticated user
- **`activity/mark-repo-notifications-as-read`**: Mark repository notifications as read
- **`repos/get-pages`**: Get a GitHub Pages site
- **`repos/create-pages-site`**: Create a GitHub Pages site
- **`repos/update-information-about-pages-site`**: Update information about a GitHub Pages site
- **`repos/delete-pages-site`**: Delete a GitHub Pages site
- **`repos/list-pages-builds`**: List GitHub Pages builds
- **`repos/request-pages-build`**: Request a GitHub Pages build
- **`repos/get-latest-pages-build`**: Get latest Pages build
- **`repos/get-pages-build`**: Get GitHub Pages build
- **`repos/create-pages-deployment`**: Create a GitHub Pages deployment
- **`repos/get-pages-deployment`**: Get the status of a GitHub Pages deployment
- **`repos/cancel-pages-deployment`**: Cancel a GitHub Pages deployment
- **`repos/get-pages-health-check`**: Get a DNS health check for GitHub Pages
- **`repos/check-private-vulnerability-reporting`**: Check if private vulnerability reporting is enabled for a repository
- **`repos/enable-private-vulnerability-reporting`**: Enable private vulnerability reporting for a repository
- **`repos/disable-private-vulnerability-reporting`**: Disable private vulnerability reporting for a repository
- **`projects-classic/list-for-repo`**: List repository projects
- **`projects-classic/create-for-repo`**: Create a repository project
- **`repos/get-custom-properties-values`**: Get all custom property values for a repository
- **`repos/create-or-update-custom-properties-values`**: Create or update custom property values for a repository
- **`pulls/list`**: List pull requests
- **`pulls/create`**: Create a pull request
- **`pulls/list-review-comments-for-repo`**: List review comments in a repository
- **`pulls/get-review-comment`**: Get a review comment for a pull request
- **`pulls/update-review-comment`**: Update a review comment for a pull request
- **`pulls/delete-review-comment`**: Delete a review comment for a pull request
- **`reactions/list-for-pull-request-review-comment`**: List reactions for a pull request review comment
- **`reactions/create-for-pull-request-review-comment`**: Create reaction for a pull request review comment
- **`reactions/delete-for-pull-request-comment`**: Delete a pull request comment reaction
- **`pulls/get`**: Get a pull request
- **`pulls/update`**: Update a pull request
- **`codespaces/create-with-pr-for-authenticated-user`**: Create a codespace from a pull request
- **`pulls/list-review-comments`**: List review comments on a pull request
- **`pulls/create-review-comment`**: Create a review comment for a pull request
- **`pulls/create-reply-for-review-comment`**: Create a reply for a review comment
- **`pulls/list-commits`**: List commits on a pull request
- **`pulls/list-files`**: List pull requests files
- **`pulls/check-if-merged`**: Check if a pull request has been merged
- **`pulls/merge`**: Merge a pull request
- **`pulls/list-requested-reviewers`**: Get all requested reviewers for a pull request
- **`pulls/request-reviewers`**: Request reviewers for a pull request
- **`pulls/remove-requested-reviewers`**: Remove requested reviewers from a pull request
- **`pulls/list-reviews`**: List reviews for a pull request
- **`pulls/create-review`**: Create a review for a pull request
- **`pulls/get-review`**: Get a review for a pull request
- **`pulls/update-review`**: Update a review for a pull request
- **`pulls/delete-pending-review`**: Delete a pending review for a pull request
- **`pulls/list-comments-for-review`**: List comments for a pull request review
- **`pulls/dismiss-review`**: Dismiss a review for a pull request
- **`pulls/submit-review`**: Submit a review for a pull request
- **`pulls/update-branch`**: Update a pull request branch
- **`repos/get-readme`**: Get a repository README
- **`repos/get-readme-in-directory`**: Get a repository README for a directory
- **`repos/list-releases`**: List releases
- **`repos/create-release`**: Create a release
- **`repos/get-release-asset`**: Get a release asset
- **`repos/update-release-asset`**: Update a release asset
- **`repos/delete-release-asset`**: Delete a release asset
- **`repos/generate-release-notes`**: Generate release notes content for a release
- **`repos/get-latest-release`**: Get the latest release
- **`repos/get-release-by-tag`**: Get a release by tag name
- **`repos/get-release`**: Get a release
- **`repos/update-release`**: Update a release
- **`repos/delete-release`**: Delete a release
- **`repos/list-release-assets`**: List release assets
- **`repos/upload-release-asset`**: Upload a release asset
- **`reactions/list-for-release`**: List reactions for a release
- **`reactions/create-for-release`**: Create reaction for a release
- **`reactions/delete-for-release`**: Delete a release reaction
- **`repos/get-branch-rules`**: Get rules for a branch
- **`repos/get-repo-rulesets`**: Get all repository rulesets
- **`repos/create-repo-ruleset`**: Create a repository ruleset
- **`repos/get-repo-rule-suites`**: List repository rule suites
- **`repos/get-repo-rule-suite`**: Get a repository rule suite
- **`repos/get-repo-ruleset`**: Get a repository ruleset
- **`repos/update-repo-ruleset`**: Update a repository ruleset
- **`repos/delete-repo-ruleset`**: Delete a repository ruleset
- **`repos/get-repo-ruleset-history`**: Get repository ruleset history
- **`repos/get-repo-ruleset-version`**: Get repository ruleset version
- **`secret-scanning/list-alerts-for-repo`**: List secret scanning alerts for a repository
- **`secret-scanning/get-alert`**: Get a secret scanning alert
- **`secret-scanning/update-alert`**: Update a secret scanning alert
- **`secret-scanning/list-locations-for-alert`**: List locations for a secret scanning alert
- **`secret-scanning/create-push-protection-bypass`**: Create a push protection bypass
- **`secret-scanning/get-scan-history`**: Get secret scanning scan history for a repository
- **`security-advisories/list-repository-advisories`**: List repository security advisories
- **`security-advisories/create-repository-advisory`**: Create a repository security advisory
- **`security-advisories/create-private-vulnerability-report`**: Privately report a security vulnerability
- **`security-advisories/get-repository-advisory`**: Get a repository security advisory
- **`security-advisories/update-repository-advisory`**: Update a repository security advisory
- **`security-advisories/create-repository-advisory-cve-request`**: Request a CVE for a repository security advisory
- **`security-advisories/create-fork`**: Create a temporary private fork
- **`activity/list-stargazers-for-repo`**: List stargazers
- **`repos/get-code-frequency-stats`**: Get the weekly commit activity
- **`repos/get-commit-activity-stats`**: Get the last year of commit activity
- **`repos/get-contributors-stats`**: Get all contributor commit activity
- **`repos/get-participation-stats`**: Get the weekly commit count
- **`repos/get-punch-card-stats`**: Get the hourly commit count for each day
- **`repos/create-commit-status`**: Create a commit status
- **`activity/list-watchers-for-repo`**: List watchers
- **`activity/get-repo-subscription`**: Get a repository subscription
- **`activity/set-repo-subscription`**: Set a repository subscription
- **`activity/delete-repo-subscription`**: Delete a repository subscription
- **`repos/list-tags`**: List repository tags
- **`repos/list-tag-protection`**: Closing down - List tag protection states for a repository
- **`repos/create-tag-protection`**: Closing down - Create a tag protection state for a repository
- **`repos/delete-tag-protection`**: Closing down - Delete a tag protection state for a repository
- **`repos/download-tarball-archive`**: Download a repository archive (tar)
- **`repos/list-teams`**: List repository teams
- **`repos/get-all-topics`**: Get all repository topics
- **`repos/replace-all-topics`**: Replace all repository topics
- **`repos/get-clones`**: Get repository clones
- **`repos/get-top-paths`**: Get top referral paths
- **`repos/get-top-referrers`**: Get top referral sources
- **`repos/get-views`**: Get page views
- **`repos/transfer`**: Transfer a repository
- **`repos/check-vulnerability-alerts`**: Check if vulnerability alerts are enabled for a repository
- **`repos/enable-vulnerability-alerts`**: Enable vulnerability alerts
- **`repos/disable-vulnerability-alerts`**: Disable vulnerability alerts
- **`repos/download-zipball-archive`**: Download a repository archive (zip)
- **`repos/create-using-template`**: Create a repository using a template
- **`repos/list-public`**: List public repositories
- **`search/code`**: Search code
- **`search/commits`**: Search commits
- **`search/issues-and-pull-requests`**: Search issues and pull requests
- **`search/labels`**: Search labels
- **`search/repos`**: Search repositories
- **`search/topics`**: Search topics
- **`search/users`**: Search users
- **`teams/get-legacy`**: Get a team (Legacy)
- **`teams/update-legacy`**: Update a team (Legacy)
- **`teams/delete-legacy`**: Delete a team (Legacy)
- **`teams/list-discussions-legacy`**: List discussions (Legacy)
- **`teams/create-discussion-legacy`**: Create a discussion (Legacy)
- **`teams/get-discussion-legacy`**: Get a discussion (Legacy)
- **`teams/update-discussion-legacy`**: Update a discussion (Legacy)
- **`teams/delete-discussion-legacy`**: Delete a discussion (Legacy)
- **`teams/list-discussion-comments-legacy`**: List discussion comments (Legacy)
- **`teams/create-discussion-comment-legacy`**: Create a discussion comment (Legacy)
- **`teams/get-discussion-comment-legacy`**: Get a discussion comment (Legacy)
- **`teams/update-discussion-comment-legacy`**: Update a discussion comment (Legacy)
- **`teams/delete-discussion-comment-legacy`**: Delete a discussion comment (Legacy)
- **`reactions/list-for-team-discussion-comment-legacy`**: List reactions for a team discussion comment (Legacy)
- **`reactions/create-for-team-discussion-comment-legacy`**: Create reaction for a team discussion comment (Legacy)
- **`reactions/list-for-team-discussion-legacy`**: List reactions for a team discussion (Legacy)
- **`reactions/create-for-team-discussion-legacy`**: Create reaction for a team discussion (Legacy)
- **`teams/list-pending-invitations-legacy`**: List pending team invitations (Legacy)
- **`teams/list-members-legacy`**: List team members (Legacy)
- **`teams/get-member-legacy`**: Get team member (Legacy)
- **`teams/add-member-legacy`**: Add team member (Legacy)
- **`teams/remove-member-legacy`**: Remove team member (Legacy)
- **`teams/get-membership-for-user-legacy`**: Get team membership for a user (Legacy)
- **`teams/add-or-update-membership-for-user-legacy`**: Add or update team membership for a user (Legacy)
- **`teams/remove-membership-for-user-legacy`**: Remove team membership for a user (Legacy)
- **`teams/list-projects-legacy`**: List team projects (Legacy)
- **`teams/check-permissions-for-project-legacy`**: Check team permissions for a project (Legacy)
- **`teams/add-or-update-project-permissions-legacy`**: Add or update team project permissions (Legacy)
- **`teams/remove-project-legacy`**: Remove a project from a team (Legacy)
- **`teams/list-repos-legacy`**: List team repositories (Legacy)
- **`teams/check-permissions-for-repo-legacy`**: Check team permissions for a repository (Legacy)
- **`teams/add-or-update-repo-permissions-legacy`**: Add or update team repository permissions (Legacy)
- **`teams/remove-repo-legacy`**: Remove a repository from a team (Legacy)
- **`teams/list-child-legacy`**: List child teams (Legacy)
- **`users/get-authenticated`**: Get the authenticated user
- **`users/update-authenticated`**: Update the authenticated user
- **`users/list-blocked-by-authenticated-user`**: List users blocked by the authenticated user
- **`users/check-blocked`**: Check if a user is blocked by the authenticated user
- **`users/block`**: Block a user
- **`users/unblock`**: Unblock a user
- **`codespaces/list-for-authenticated-user`**: List codespaces for the authenticated user
- **`codespaces/create-for-authenticated-user`**: Create a codespace for the authenticated user
- **`codespaces/list-secrets-for-authenticated-user`**: List secrets for the authenticated user
- **`codespaces/get-public-key-for-authenticated-user`**: Get public key for the authenticated user
- **`codespaces/get-secret-for-authenticated-user`**: Get a secret for the authenticated user
- **`codespaces/create-or-update-secret-for-authenticated-user`**: Create or update a secret for the authenticated user
- **`codespaces/delete-secret-for-authenticated-user`**: Delete a secret for the authenticated user
- **`codespaces/list-repositories-for-secret-for-authenticated-user`**: List selected repositories for a user secret
- **`codespaces/set-repositories-for-secret-for-authenticated-user`**: Set selected repositories for a user secret
- **`codespaces/add-repository-for-secret-for-authenticated-user`**: Add a selected repository to a user secret
- **`codespaces/remove-repository-for-secret-for-authenticated-user`**: Remove a selected repository from a user secret
- **`codespaces/get-for-authenticated-user`**: Get a codespace for the authenticated user
- **`codespaces/update-for-authenticated-user`**: Update a codespace for the authenticated user
- **`codespaces/delete-for-authenticated-user`**: Delete a codespace for the authenticated user
- **`codespaces/export-for-authenticated-user`**: Export a codespace for the authenticated user
- **`codespaces/get-export-details-for-authenticated-user`**: Get details about a codespace export
- **`codespaces/codespace-machines-for-authenticated-user`**: List machine types for a codespace
- **`codespaces/publish-for-authenticated-user`**: Create a repository from an unpublished codespace
- **`codespaces/start-for-authenticated-user`**: Start a codespace for the authenticated user
- **`codespaces/stop-for-authenticated-user`**: Stop a codespace for the authenticated user
- **`packages/list-docker-migration-conflicting-packages-for-authenticated-user`**: Get list of conflicting packages during Docker migration for authenticated-user
- **`users/set-primary-email-visibility-for-authenticated-user`**: Set primary email visibility for the authenticated user
- **`users/list-emails-for-authenticated-user`**: List email addresses for the authenticated user
- **`users/add-email-for-authenticated-user`**: Add an email address for the authenticated user
- **`users/delete-email-for-authenticated-user`**: Delete an email address for the authenticated user
- **`users/list-followers-for-authenticated-user`**: List followers of the authenticated user
- **`users/list-followed-by-authenticated-user`**: List the people the authenticated user follows
- **`users/check-person-is-followed-by-authenticated`**: Check if a person is followed by the authenticated user
- **`users/follow`**: Follow a user
- **`users/unfollow`**: Unfollow a user
- **`users/list-gpg-keys-for-authenticated-user`**: List GPG keys for the authenticated user
- **`users/create-gpg-key-for-authenticated-user`**: Create a GPG key for the authenticated user
- **`users/get-gpg-key-for-authenticated-user`**: Get a GPG key for the authenticated user
- **`users/delete-gpg-key-for-authenticated-user`**: Delete a GPG key for the authenticated user
- **`apps/list-installations-for-authenticated-user`**: List app installations accessible to the user access token
- **`apps/list-installation-repos-for-authenticated-user`**: List repositories accessible to the user access token
- **`apps/add-repo-to-installation-for-authenticated-user`**: Add a repository to an app installation
- **`apps/remove-repo-from-installation-for-authenticated-user`**: Remove a repository from an app installation
- **`interactions/get-restrictions-for-authenticated-user`**: Get interaction restrictions for your public repositories
- **`interactions/set-restrictions-for-authenticated-user`**: Set interaction restrictions for your public repositories
- **`interactions/remove-restrictions-for-authenticated-user`**: Remove interaction restrictions from your public repositories
- **`issues/list-for-authenticated-user`**: List user account issues assigned to the authenticated user
- **`users/list-public-ssh-keys-for-authenticated-user`**: List public SSH keys for the authenticated user
- **`users/create-public-ssh-key-for-authenticated-user`**: Create a public SSH key for the authenticated user
- **`users/get-public-ssh-key-for-authenticated-user`**: Get a public SSH key for the authenticated user
- **`users/delete-public-ssh-key-for-authenticated-user`**: Delete a public SSH key for the authenticated user
- **`apps/list-subscriptions-for-authenticated-user`**: List subscriptions for the authenticated user
- **`apps/list-subscriptions-for-authenticated-user-stubbed`**: List subscriptions for the authenticated user (stubbed)
- **`orgs/list-memberships-for-authenticated-user`**: List organization memberships for the authenticated user
- **`orgs/get-membership-for-authenticated-user`**: Get an organization membership for the authenticated user
- **`orgs/update-membership-for-authenticated-user`**: Update an organization membership for the authenticated user
- **`migrations/list-for-authenticated-user`**: List user migrations
- **`migrations/start-for-authenticated-user`**: Start a user migration
- **`migrations/get-status-for-authenticated-user`**: Get a user migration status
- **`migrations/get-archive-for-authenticated-user`**: Download a user migration archive
- **`migrations/delete-archive-for-authenticated-user`**: Delete a user migration archive
- **`migrations/unlock-repo-for-authenticated-user`**: Unlock a user repository
- **`migrations/list-repos-for-authenticated-user`**: List repositories for a user migration
- **`orgs/list-for-authenticated-user`**: List organizations for the authenticated user
- **`packages/list-packages-for-authenticated-user`**: List packages for the authenticated user&#x27;s namespace
- **`packages/get-package-for-authenticated-user`**: Get a package for the authenticated user
- **`packages/delete-package-for-authenticated-user`**: Delete a package for the authenticated user
- **`packages/restore-package-for-authenticated-user`**: Restore a package for the authenticated user
- **`packages/get-all-package-versions-for-package-owned-by-authenticated-user`**: List package versions for a package owned by the authenticated user
- **`packages/get-package-version-for-authenticated-user`**: Get a package version for the authenticated user
- **`packages/delete-package-version-for-authenticated-user`**: Delete a package version for the authenticated user
- **`packages/restore-package-version-for-authenticated-user`**: Restore a package version for the authenticated user
- **`projects-classic/create-for-authenticated-user`**: Create a user project
- **`users/list-public-emails-for-authenticated-user`**: List public email addresses for the authenticated user
- **`repos/list-for-authenticated-user`**: List repositories for the authenticated user
- **`repos/create-for-authenticated-user`**: Create a repository for the authenticated user
- **`repos/list-invitations-for-authenticated-user`**: List repository invitations for the authenticated user
- **`repos/accept-invitation-for-authenticated-user`**: Accept a repository invitation
- **`repos/decline-invitation-for-authenticated-user`**: Decline a repository invitation
- **`users/list-social-accounts-for-authenticated-user`**: List social accounts for the authenticated user
- **`users/add-social-account-for-authenticated-user`**: Add social accounts for the authenticated user
- **`users/delete-social-account-for-authenticated-user`**: Delete social accounts for the authenticated user
- **`users/list-ssh-signing-keys-for-authenticated-user`**: List SSH signing keys for the authenticated user
- **`users/create-ssh-signing-key-for-authenticated-user`**: Create a SSH signing key for the authenticated user
- **`users/get-ssh-signing-key-for-authenticated-user`**: Get an SSH signing key for the authenticated user
- **`users/delete-ssh-signing-key-for-authenticated-user`**: Delete an SSH signing key for the authenticated user
- **`activity/list-repos-starred-by-authenticated-user`**: List repositories starred by the authenticated user
- **`activity/check-repo-is-starred-by-authenticated-user`**: Check if a repository is starred by the authenticated user
- **`activity/star-repo-for-authenticated-user`**: Star a repository for the authenticated user
- **`activity/unstar-repo-for-authenticated-user`**: Unstar a repository for the authenticated user
- **`activity/list-watched-repos-for-authenticated-user`**: List repositories watched by the authenticated user
- **`teams/list-for-authenticated-user`**: List teams for the authenticated user
- **`users/get-by-id`**: Get a user using their ID
- **`users/list`**: List users
- **`users/get-by-username`**: Get a user
- **`users/list-attestations-bulk`**: List attestations by bulk subject digests
- **`users/delete-attestations-bulk`**: Delete attestations in bulk
- **`users/delete-attestations-by-subject-digest`**: Delete attestations by subject digest
- **`users/delete-attestations-by-id`**: Delete attestations by ID
- **`users/list-attestations`**: List attestations
- **`packages/list-docker-migration-conflicting-packages-for-user`**: Get list of conflicting packages during Docker migration for user
- **`activity/list-events-for-authenticated-user`**: List events for the authenticated user
- **`activity/list-org-events-for-authenticated-user`**: List organization events for the authenticated user
- **`activity/list-public-events-for-user`**: List public events for a user
- **`users/list-followers-for-user`**: List followers of a user
- **`users/list-following-for-user`**: List the people a user follows
- **`users/check-following-for-user`**: Check if a user follows another user
- **`gists/list-for-user`**: List gists for a user
- **`users/list-gpg-keys-for-user`**: List GPG keys for a user
- **`users/get-context-for-user`**: Get contextual information for a user
- **`apps/get-user-installation`**: Get a user installation for the authenticated app
- **`users/list-public-keys-for-user`**: List public keys for a user
- **`orgs/list-for-user`**: List organizations for a user
- **`packages/list-packages-for-user`**: List packages for a user
- **`packages/get-package-for-user`**: Get a package for a user
- **`packages/delete-package-for-user`**: Delete a package for a user
- **`packages/restore-package-for-user`**: Restore a package for a user
- **`packages/get-all-package-versions-for-package-owned-by-user`**: List package versions for a package owned by a user
- **`packages/get-package-version-for-user`**: Get a package version for a user
- **`packages/delete-package-version-for-user`**: Delete package version for a user
- **`packages/restore-package-version-for-user`**: Restore package version for a user
- **`projects-classic/list-for-user`**: List user projects
- **`activity/list-received-events-for-user`**: List events received by the authenticated user
- **`activity/list-received-public-events-for-user`**: List public events received by a user
- **`repos/list-for-user`**: List repositories for a user
- **`billing/get-github-actions-billing-user`**: Get GitHub Actions billing for a user
- **`billing/get-github-packages-billing-user`**: Get GitHub Packages billing for a user
- **`billing/get-shared-storage-billing-user`**: Get shared storage billing for a user
- **`billing/get-github-billing-usage-report-user`**: Get billing usage report for a user
- **`users/list-social-accounts-for-user`**: List social accounts for a user
- **`users/list-ssh-signing-keys-for-user`**: List SSH signing keys for a user
- **`activity/list-repos-starred-by-user`**: List repositories starred by a user
- **`activity/list-repos-watched-by-user`**: List repositories watched by a user
- **`meta/get-all-versions`**: Get all API versions
- **`meta/get-zen`**: Get the Zen of GitHub

**Total: 1039 tools available** 🎯

## Support This Project

Hi! I'm Sargon, a software engineer passionate about AI tools and automation. I create open-source MCP servers to help developers integrate AI assistants with their favorite services.

Your support helps me continue developing and maintaining these tools, and motivates me to create new integrations that make AI assistants even more powerful! 🚀

[![Support on Boosty](https://img.shields.io/badge/Support-Boosty-orange?logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEyIDJMMTMuMDkgOC4yNkwyMCA5TDEzLjA5IDE1Ljc0TDEyIDIyTDEwLjkxIDE1Ljc0TDQgOUwxMC45MSA4LjI2TDEyIDJaIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4K)](https://boosty.to/sargonpiraev)

## Connect with Author

- 🌐 Visit [sargonpiraev.com](https://sargonpiraev.com)
- 📧 Email: [sargonpiraev@gmail.com](mailto:sargonpiraev@gmail.com)
- 💬 Join [Discord](https://discord.gg/ZsWGxRGj)
