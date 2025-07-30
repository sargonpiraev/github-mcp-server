import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import axios, { AxiosInstance } from 'axios'
import dotenv from 'dotenv'
import { CallToolResult } from '@modelcontextprotocol/sdk/types.js'

dotenv.config()

export const envSchema = z.object({
  GITHUB_API_KEY: z.string(),
})

export const mcpServer = new McpServer(
  {
    name: '@sargonpiraev/github-mcp-server',
    version: '1.1.4',
  },
  {
    instructions: ``,
    capabilities: {
      tools: {},
      logging: {},
    },
  }
)

export const env = envSchema.parse(process.env)

export const apiClient: AxiosInstance = axios.create({
  baseURL: 'https://api.github.com',
  headers: {
    Accept: 'application/json',
  },
  timeout: 30000,
})

apiClient.interceptors.request.use(
  (config) => {
    if (env.GITHUB_API_KEY) {
      config.headers['Authorization'] = env.GITHUB_API_KEY
    }

    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

function handleResult(data: unknown): CallToolResult {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2),
      },
    ],
  }
}

function handleError(error: unknown): CallToolResult {
  console.error(error)

  if (axios.isAxiosError(error)) {
    const message = error.response?.data?.message || error.message
    return {
      isError: true,
      content: [{ type: 'text', text: `API Error: ${message}` }],
    } as CallToolResult
  }

  return {
    isError: true,
    content: [{ type: 'text', text: `Error: ${error}` }],
  } as CallToolResult
}

// Register tools
mcpServer.tool('meta/root', `GitHub API Root`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'security-advisories/list-global-advisories',
  `List global security advisories`,
  {
    ghsa_id: z.string().optional(),
    type: z.string().optional(),
    cve_id: z.string().optional(),
    ecosystem: z.string().optional(),
    severity: z.string().optional(),
    cwes: z.string().optional(),
    is_withdrawn: z.string().optional(),
    affects: z.string().optional(),
    published: z.string().optional(),
    updated: z.string().optional(),
    modified: z.string().optional(),
    epss_percentage: z.string().optional(),
    epss_percentile: z.string().optional(),
    per_page: z.string().optional(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/advisories',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/get-global-advisory',
  `Get a global security advisory`,
  {
    ghsa_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { ghsa_id, ...queryParams } = args
      const url = `/advisories/${ghsa_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('apps/get-authenticated', `Get the authenticated app`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/app',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'apps/create-from-manifest',
  `Create a GitHub App from a manifest`,
  {
    code: z.string(),
  },
  async (args, extra) => {
    try {
      const { code, ...requestData } = args
      const url = `/app-manifests/${code}/conversions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('apps/get-webhook-config-for-app', `Get a webhook configuration for an app`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/app/hook/config',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'apps/update-webhook-config-for-app',
  `Update a webhook configuration for an app`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: '/app/hook/config',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('apps/list-webhook-deliveries', `List deliveries for an app webhook`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/app/hook/deliveries',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'apps/get-webhook-delivery',
  `Get a delivery for an app webhook`,
  {
    delivery_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { delivery_id, ...queryParams } = args
      const url = `/app/hook/deliveries/${delivery_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/redeliver-webhook-delivery',
  `Redeliver a delivery for an app webhook`,
  {
    delivery_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { delivery_id, ...requestData } = args
      const url = `/app/hook/deliveries/${delivery_id}/attempts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/list-installation-requests-for-authenticated-app',
  `List installation requests for the authenticated app`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/app/installation-requests',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/list-installations',
  `List installations for the authenticated app`,
  {
    outdated: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/app/installations',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/get-installation',
  `Get an installation for the authenticated app`,
  {
    installation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { installation_id, ...queryParams } = args
      const url = `/app/installations/${installation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/delete-installation',
  `Delete an installation for the authenticated app`,
  {
    installation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { installation_id, ...queryParams } = args
      const url = `/app/installations/${installation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/create-installation-access-token',
  `Create an installation access token for an app`,
  {
    installation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { installation_id, ...requestData } = args
      const url = `/app/installations/${installation_id}/access_tokens`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/suspend-installation',
  `Suspend an app installation`,
  {
    installation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { installation_id, ...requestData } = args
      const url = `/app/installations/${installation_id}/suspended`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/unsuspend-installation',
  `Unsuspend an app installation`,
  {
    installation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { installation_id, ...queryParams } = args
      const url = `/app/installations/${installation_id}/suspended`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/delete-authorization',
  `Delete an app authorization`,
  {
    client_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { client_id, ...queryParams } = args
      const url = `/applications/${client_id}/grant`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/check-token',
  `Check a token`,
  {
    client_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { client_id, ...requestData } = args
      const url = `/applications/${client_id}/token`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/reset-token',
  `Reset a token`,
  {
    client_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { client_id, ...requestData } = args
      const url = `/applications/${client_id}/token`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/delete-token',
  `Delete an app token`,
  {
    client_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { client_id, ...queryParams } = args
      const url = `/applications/${client_id}/token`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/scope-token',
  `Create a scoped access token`,
  {
    client_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { client_id, ...requestData } = args
      const url = `/applications/${client_id}/token/scoped`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/get-by-slug',
  `Get an app`,
  {
    app_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { app_slug, ...queryParams } = args
      const url = `/apps/${app_slug}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'classroom/get-an-assignment',
  `Get an assignment`,
  {
    assignment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { assignment_id, ...queryParams } = args
      const url = `/assignments/${assignment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'classroom/list-accepted-assignments-for-an-assignment',
  `List accepted assignments for an assignment`,
  {
    assignment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { assignment_id, ...queryParams } = args
      const url = `/assignments/${assignment_id}/accepted_assignments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'classroom/get-assignment-grades',
  `Get assignment grades`,
  {
    assignment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { assignment_id, ...queryParams } = args
      const url = `/assignments/${assignment_id}/grades`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('classroom/list-classrooms', `List classrooms`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/classrooms',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'classroom/get-a-classroom',
  `Get a classroom`,
  {
    classroom_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { classroom_id, ...queryParams } = args
      const url = `/classrooms/${classroom_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'classroom/list-assignments-for-a-classroom',
  `List assignments for a classroom`,
  {
    classroom_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { classroom_id, ...queryParams } = args
      const url = `/classrooms/${classroom_id}/assignments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('codes-of-conduct/get-all-codes-of-conduct', `Get all codes of conduct`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/codes_of_conduct',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'codes-of-conduct/get-conduct-code',
  `Get a code of conduct`,
  {
    key: z.string(),
  },
  async (args, extra) => {
    try {
      const { key, ...queryParams } = args
      const url = `/codes_of_conduct/${key}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('credentials/revoke', `Revoke a list of credentials`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'POST',
      url: '/credentials/revoke',
      data: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('emojis/get', `Get emojis`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/emojis',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'code-security/get-configurations-for-enterprise',
  `Get code security configurations for an enterprise`,
  {
    enterprise: z.string(),
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { enterprise, ...queryParams } = args
      const url = `/enterprises/${enterprise}/code-security/configurations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/create-configuration-for-enterprise',
  `Create a code security configuration for an enterprise`,
  {
    enterprise: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, ...requestData } = args
      const url = `/enterprises/${enterprise}/code-security/configurations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/get-default-configurations-for-enterprise',
  `Get default code security configurations for an enterprise`,
  {
    enterprise: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, ...queryParams } = args
      const url = `/enterprises/${enterprise}/code-security/configurations/defaults`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/get-single-configuration-for-enterprise',
  `Retrieve a code security configuration of an enterprise`,
  {
    enterprise: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, configuration_id, ...queryParams } = args
      const url = `/enterprises/${enterprise}/code-security/configurations/${configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/update-enterprise-configuration',
  `Update a custom code security configuration for an enterprise`,
  {
    enterprise: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, configuration_id, ...requestData } = args
      const url = `/enterprises/${enterprise}/code-security/configurations/${configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/delete-configuration-for-enterprise',
  `Delete a code security configuration for an enterprise`,
  {
    enterprise: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, configuration_id, ...queryParams } = args
      const url = `/enterprises/${enterprise}/code-security/configurations/${configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/attach-enterprise-configuration',
  `Attach an enterprise configuration to repositories`,
  {
    enterprise: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, configuration_id, ...requestData } = args
      const url = `/enterprises/${enterprise}/code-security/configurations/${configuration_id}/attach`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/set-configuration-as-default-for-enterprise',
  `Set a code security configuration as a default for an enterprise`,
  {
    enterprise: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, configuration_id, ...requestData } = args
      const url = `/enterprises/${enterprise}/code-security/configurations/${configuration_id}/defaults`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/get-repositories-for-enterprise-configuration',
  `Get repositories associated with an enterprise code security configuration`,
  {
    enterprise: z.string(),
    configuration_id: z.string(),
    per_page: z.string().optional(),
    status: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { enterprise, configuration_id, ...queryParams } = args
      const url = `/enterprises/${enterprise}/code-security/configurations/${configuration_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/list-alerts-for-enterprise',
  `List Dependabot alerts for an enterprise`,
  {
    enterprise: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, ...queryParams } = args
      const url = `/enterprises/${enterprise}/dependabot/alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'secret-scanning/list-alerts-for-enterprise',
  `List secret scanning alerts for an enterprise`,
  {
    enterprise: z.string(),
  },
  async (args, extra) => {
    try {
      const { enterprise, ...queryParams } = args
      const url = `/enterprises/${enterprise}/secret-scanning/alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('activity/list-public-events', `List public events`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/events',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('activity/get-feeds', `Get feeds`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/feeds',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('gists/list', `List gists for the authenticated user`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/gists',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('gists/create', `Create a gist`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'POST',
      url: '/gists',
      data: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('gists/list-public', `List public gists`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/gists/public',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('gists/list-starred', `List starred gists`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/gists/starred',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'gists/get',
  `Get a gist`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...queryParams } = args
      const url = `/gists/${gist_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/update',
  `Update a gist`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...requestData } = args
      const url = `/gists/${gist_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/delete',
  `Delete a gist`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...queryParams } = args
      const url = `/gists/${gist_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/list-comments',
  `List gist comments`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...queryParams } = args
      const url = `/gists/${gist_id}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/create-comment',
  `Create a gist comment`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...requestData } = args
      const url = `/gists/${gist_id}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/get-comment',
  `Get a gist comment`,
  {
    gist_id: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, comment_id, ...queryParams } = args
      const url = `/gists/${gist_id}/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/update-comment',
  `Update a gist comment`,
  {
    gist_id: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, comment_id, ...requestData } = args
      const url = `/gists/${gist_id}/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/delete-comment',
  `Delete a gist comment`,
  {
    gist_id: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, comment_id, ...queryParams } = args
      const url = `/gists/${gist_id}/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/list-commits',
  `List gist commits`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...queryParams } = args
      const url = `/gists/${gist_id}/commits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/list-forks',
  `List gist forks`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...queryParams } = args
      const url = `/gists/${gist_id}/forks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/fork',
  `Fork a gist`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...requestData } = args
      const url = `/gists/${gist_id}/forks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/check-is-starred',
  `Check if a gist is starred`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...queryParams } = args
      const url = `/gists/${gist_id}/star`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/star',
  `Star a gist`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...requestData } = args
      const url = `/gists/${gist_id}/star`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/unstar',
  `Unstar a gist`,
  {
    gist_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, ...queryParams } = args
      const url = `/gists/${gist_id}/star`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/get-revision',
  `Get a gist revision`,
  {
    gist_id: z.string(),
    sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { gist_id, sha, ...queryParams } = args
      const url = `/gists/${gist_id}/${sha}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('gitignore/get-all-templates', `Get all gitignore templates`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/gitignore/templates',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'gitignore/get-template',
  `Get a gitignore template`,
  {
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { name, ...queryParams } = args
      const url = `/gitignore/templates/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/list-repos-accessible-to-installation',
  `List repositories accessible to the app installation`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/installation/repositories',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/revoke-installation-access-token',
  `Revoke an installation access token`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: '/installation/token',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list',
  `List issues assigned to the authenticated user`,
  {
    filter: z.string().optional(),
    state: z.string().optional(),
    sort: z.string().optional(),
    collab: z.string().optional(),
    orgs: z.string().optional(),
    owned: z.string().optional(),
    pulls: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/issues',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'licenses/get-all-commonly-used',
  `Get all commonly used licenses`,
  {
    featured: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/licenses',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'licenses/get',
  `Get a license`,
  {
    license: z.string(),
  },
  async (args, extra) => {
    try {
      const { license, ...queryParams } = args
      const url = `/licenses/${license}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('markdown/render', `Render a Markdown document`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'POST',
      url: '/markdown',
      data: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('markdown/render-raw', `Render a Markdown document in raw mode`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'POST',
      url: '/markdown/raw',
      data: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'apps/get-subscription-plan-for-account',
  `Get a subscription plan for an account`,
  {
    account_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { account_id, ...queryParams } = args
      const url = `/marketplace_listing/accounts/${account_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('apps/list-plans', `List plans`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/marketplace_listing/plans',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'apps/list-accounts-for-plan',
  `List accounts for a plan`,
  {
    plan_id: z.string(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { plan_id, ...queryParams } = args
      const url = `/marketplace_listing/plans/${plan_id}/accounts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/get-subscription-plan-for-account-stubbed',
  `Get a subscription plan for an account (stubbed)`,
  {
    account_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { account_id, ...queryParams } = args
      const url = `/marketplace_listing/stubbed/accounts/${account_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('apps/list-plans-stubbed', `List plans (stubbed)`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/marketplace_listing/stubbed/plans',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'apps/list-accounts-for-plan-stubbed',
  `List accounts for a plan (stubbed)`,
  {
    plan_id: z.string(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { plan_id, ...queryParams } = args
      const url = `/marketplace_listing/stubbed/plans/${plan_id}/accounts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('meta/get', `Get GitHub meta information`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/meta',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'activity/list-public-events-for-repo-network',
  `List public events for a network of repositories`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/networks/${owner}/${repo}/events`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-notifications-for-authenticated-user',
  `List notifications for the authenticated user`,
  {
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/notifications',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('activity/mark-notifications-as-read', `Mark notifications as read`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'PUT',
      url: '/notifications',
      data: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'activity/get-thread',
  `Get a thread`,
  {
    thread_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { thread_id, ...queryParams } = args
      const url = `/notifications/threads/${thread_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/mark-thread-as-read',
  `Mark a thread as read`,
  {
    thread_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { thread_id, ...requestData } = args
      const url = `/notifications/threads/${thread_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/mark-thread-as-done',
  `Mark a thread as done`,
  {
    thread_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { thread_id, ...queryParams } = args
      const url = `/notifications/threads/${thread_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/get-thread-subscription-for-authenticated-user',
  `Get a thread subscription for the authenticated user`,
  {
    thread_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { thread_id, ...queryParams } = args
      const url = `/notifications/threads/${thread_id}/subscription`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/set-thread-subscription',
  `Set a thread subscription`,
  {
    thread_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { thread_id, ...requestData } = args
      const url = `/notifications/threads/${thread_id}/subscription`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/delete-thread-subscription',
  `Delete a thread subscription`,
  {
    thread_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { thread_id, ...queryParams } = args
      const url = `/notifications/threads/${thread_id}/subscription`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'meta/get-octocat',
  `Get Octocat`,
  {
    s: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/octocat',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('orgs/list', `List organizations`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/organizations',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'dependabot/repository-access-for-org',
  `Lists the repositories Dependabot can access in an organization`,
  {
    org: z.string(),
    page: z.string().optional(),
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/organizations/${org}/dependabot/repository-access`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/update-repository-access-for-org',
  `Updates Dependabot&#x27;s repository access list for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/organizations/${org}/dependabot/repository-access`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/set-repository-access-default-level',
  `Set the default repository access level for Dependabot`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/organizations/${org}/dependabot/repository-access/default-level`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'billing/get-github-billing-usage-report-org',
  `Get billing usage report for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/organizations/${org}/settings/billing/usage`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get',
  `Get an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/update',
  `Update an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/delete',
  `Delete an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-actions-cache-usage-for-org',
  `Get GitHub Actions cache usage for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/cache/usage`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-actions-cache-usage-by-repo-for-org',
  `List repositories with GitHub Actions cache usage for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/cache/usage-by-repository`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-hosted-runners-for-org',
  `List GitHub-hosted runners for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/hosted-runners`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-hosted-runner-for-org',
  `Create a GitHub-hosted runner for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/hosted-runners`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-hosted-runners-github-owned-images-for-org',
  `Get GitHub-owned images for GitHub-hosted runners in an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/hosted-runners/images/github-owned`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-hosted-runners-partner-images-for-org',
  `Get partner images for GitHub-hosted runners in an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/hosted-runners/images/partner`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-hosted-runners-limits-for-org',
  `Get limits on GitHub-hosted runners for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/hosted-runners/limits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-hosted-runners-machine-specs-for-org',
  `Get GitHub-hosted runners machine specs for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/hosted-runners/machine-sizes`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-hosted-runners-platforms-for-org',
  `Get platforms for GitHub-hosted runners in an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/hosted-runners/platforms`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-hosted-runner-for-org',
  `Get a GitHub-hosted runner for an organization`,
  {
    org: z.string(),
    hosted_runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hosted_runner_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/hosted-runners/${hosted_runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/update-hosted-runner-for-org',
  `Update a GitHub-hosted runner for an organization`,
  {
    org: z.string(),
    hosted_runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hosted_runner_id, ...requestData } = args
      const url = `/orgs/${org}/actions/hosted-runners/${hosted_runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-hosted-runner-for-org',
  `Delete a GitHub-hosted runner for an organization`,
  {
    org: z.string(),
    hosted_runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hosted_runner_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/hosted-runners/${hosted_runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'oidc/get-oidc-custom-sub-template-for-org',
  `Get the customization template for an OIDC subject claim for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/oidc/customization/sub`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'oidc/update-oidc-custom-sub-template-for-org',
  `Set the customization template for an OIDC subject claim for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/oidc/customization/sub`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-github-actions-permissions-organization',
  `Get GitHub Actions permissions for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/permissions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-github-actions-permissions-organization',
  `Set GitHub Actions permissions for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/permissions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-selected-repositories-enabled-github-actions-organization',
  `List selected repositories enabled for GitHub Actions in an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/permissions/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-selected-repositories-enabled-github-actions-organization',
  `Set selected repositories enabled for GitHub Actions in an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/permissions/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/enable-selected-repository-github-actions-organization',
  `Enable a selected repository for GitHub Actions in an organization`,
  {
    org: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, repository_id, ...requestData } = args
      const url = `/orgs/${org}/actions/permissions/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/disable-selected-repository-github-actions-organization',
  `Disable a selected repository for GitHub Actions in an organization`,
  {
    org: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, repository_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/permissions/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-allowed-actions-organization',
  `Get allowed actions and reusable workflows for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/permissions/selected-actions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-allowed-actions-organization',
  `Set allowed actions and reusable workflows for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/permissions/selected-actions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-github-actions-default-workflow-permissions-organization',
  `Get default workflow permissions for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/permissions/workflow`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-github-actions-default-workflow-permissions-organization',
  `Set default workflow permissions for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/permissions/workflow`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-self-hosted-runner-groups-for-org',
  `List self-hosted runner groups for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/runner-groups`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-self-hosted-runner-group-for-org',
  `Create a self-hosted runner group for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/runner-groups`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-self-hosted-runner-group-for-org',
  `Get a self-hosted runner group for an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/update-self-hosted-runner-group-for-org',
  `Update a self-hosted runner group for an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, ...requestData } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-self-hosted-runner-group-from-org',
  `Delete a self-hosted runner group from an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-github-hosted-runners-in-group-for-org',
  `List GitHub-hosted runners in a group for an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/hosted-runners`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-repo-access-to-self-hosted-runner-group-in-org',
  `List repository access to a self-hosted runner group in an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-repo-access-to-self-hosted-runner-group-in-org',
  `Set repository access for a self-hosted runner group in an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, ...requestData } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/add-repo-access-to-self-hosted-runner-group-in-org',
  `Add repository access to a self-hosted runner group in an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, repository_id, ...requestData } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/remove-repo-access-to-self-hosted-runner-group-in-org',
  `Remove repository access to a self-hosted runner group in an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, repository_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-self-hosted-runners-in-group-for-org',
  `List self-hosted runners in a group for an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/runners`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-self-hosted-runners-in-group-for-org',
  `Set self-hosted runners in a group for an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, ...requestData } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/runners`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/add-self-hosted-runner-to-group-for-org',
  `Add a self-hosted runner to a group for an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, runner_id, ...requestData } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/runners/${runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/remove-self-hosted-runner-from-group-for-org',
  `Remove a self-hosted runner from a group for an organization`,
  {
    org: z.string(),
    runner_group_id: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_group_id, runner_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runner-groups/${runner_group_id}/runners/${runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-self-hosted-runners-for-org',
  `List self-hosted runners for an organization`,
  {
    org: z.string(),
    name: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/runners`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-runner-applications-for-org',
  `List runner applications for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/runners/downloads`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/generate-runner-jitconfig-for-org',
  `Create configuration for a just-in-time runner for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/runners/generate-jitconfig`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-registration-token-for-org',
  `Create a registration token for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/runners/registration-token`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-remove-token-for-org',
  `Create a remove token for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/runners/remove-token`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-self-hosted-runner-for-org',
  `Get a self-hosted runner for an organization`,
  {
    org: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runners/${runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-self-hosted-runner-from-org',
  `Delete a self-hosted runner from an organization`,
  {
    org: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runners/${runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-labels-for-self-hosted-runner-for-org',
  `List labels for a self-hosted runner for an organization`,
  {
    org: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runners/${runner_id}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/add-custom-labels-to-self-hosted-runner-for-org',
  `Add custom labels to a self-hosted runner for an organization`,
  {
    org: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_id, ...requestData } = args
      const url = `/orgs/${org}/actions/runners/${runner_id}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-custom-labels-for-self-hosted-runner-for-org',
  `Set custom labels for a self-hosted runner for an organization`,
  {
    org: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_id, ...requestData } = args
      const url = `/orgs/${org}/actions/runners/${runner_id}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/remove-all-custom-labels-from-self-hosted-runner-for-org',
  `Remove all custom labels from a self-hosted runner for an organization`,
  {
    org: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/runners/${runner_id}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/remove-custom-label-from-self-hosted-runner-for-org',
  `Remove a custom label from a self-hosted runner for an organization`,
  {
    org: z.string(),
    runner_id: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, runner_id, name, ...queryParams } = args
      const url = `/orgs/${org}/actions/runners/${runner_id}/labels/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-org-secrets',
  `List organization secrets`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/secrets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-org-public-key',
  `Get an organization public key`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/secrets/public-key`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-org-secret',
  `Get an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/actions/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-or-update-org-secret',
  `Create or update an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...requestData } = args
      const url = `/orgs/${org}/actions/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-org-secret',
  `Delete an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/actions/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-selected-repos-for-org-secret',
  `List selected repositories for an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/actions/secrets/${secret_name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-selected-repos-for-org-secret',
  `Set selected repositories for an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...requestData } = args
      const url = `/orgs/${org}/actions/secrets/${secret_name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/add-selected-repo-to-org-secret',
  `Add selected repository to an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, repository_id, ...requestData } = args
      const url = `/orgs/${org}/actions/secrets/${secret_name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/remove-selected-repo-from-org-secret',
  `Remove selected repository from an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, repository_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/secrets/${secret_name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-org-variables',
  `List organization variables`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/actions/variables`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-org-variable',
  `Create an organization variable`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/actions/variables`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-org-variable',
  `Get an organization variable`,
  {
    org: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, name, ...queryParams } = args
      const url = `/orgs/${org}/actions/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/update-org-variable',
  `Update an organization variable`,
  {
    org: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, name, ...requestData } = args
      const url = `/orgs/${org}/actions/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-org-variable',
  `Delete an organization variable`,
  {
    org: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, name, ...queryParams } = args
      const url = `/orgs/${org}/actions/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-selected-repos-for-org-variable',
  `List selected repositories for an organization variable`,
  {
    org: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, name, ...queryParams } = args
      const url = `/orgs/${org}/actions/variables/${name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-selected-repos-for-org-variable',
  `Set selected repositories for an organization variable`,
  {
    org: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, name, ...requestData } = args
      const url = `/orgs/${org}/actions/variables/${name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/add-selected-repo-to-org-variable',
  `Add selected repository to an organization variable`,
  {
    org: z.string(),
    name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, name, repository_id, ...requestData } = args
      const url = `/orgs/${org}/actions/variables/${name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/remove-selected-repo-from-org-variable',
  `Remove selected repository from an organization variable`,
  {
    org: z.string(),
    name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, name, repository_id, ...queryParams } = args
      const url = `/orgs/${org}/actions/variables/${name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-attestations-bulk',
  `List attestations by bulk subject digests`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/attestations/bulk-list`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/delete-attestations-bulk',
  `Delete attestations in bulk`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/attestations/delete-request`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/delete-attestations-by-subject-digest',
  `Delete attestations by subject digest`,
  {
    org: z.string(),
    subject_digest: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, subject_digest, ...queryParams } = args
      const url = `/orgs/${org}/attestations/digest/${subject_digest}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/delete-attestations-by-id',
  `Delete attestations by ID`,
  {
    org: z.string(),
    attestation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, attestation_id, ...queryParams } = args
      const url = `/orgs/${org}/attestations/${attestation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-attestations',
  `List attestations`,
  {
    org: z.string(),
    subject_digest: z.string(),
    predicate_type: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, subject_digest, ...queryParams } = args
      const url = `/orgs/${org}/attestations/${subject_digest}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-blocked-users',
  `List users blocked by an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/blocks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/check-blocked-user',
  `Check if a user is blocked by an organization`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/blocks/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/block-user',
  `Block a user from an organization`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...requestData } = args
      const url = `/orgs/${org}/blocks/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/unblock-user',
  `Unblock a user from an organization`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/blocks/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'campaigns/list-org-campaigns',
  `List campaigns for an organization`,
  {
    org: z.string(),
    state: z.string().optional(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/campaigns`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'campaigns/create-campaign',
  `Create a campaign for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/campaigns`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'campaigns/get-campaign-summary',
  `Get a campaign for an organization`,
  {
    org: z.string(),
    campaign_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, campaign_number, ...queryParams } = args
      const url = `/orgs/${org}/campaigns/${campaign_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'campaigns/update-campaign',
  `Update a campaign`,
  {
    org: z.string(),
    campaign_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, campaign_number, ...requestData } = args
      const url = `/orgs/${org}/campaigns/${campaign_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'campaigns/delete-campaign',
  `Delete a campaign for an organization`,
  {
    org: z.string(),
    campaign_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, campaign_number, ...queryParams } = args
      const url = `/orgs/${org}/campaigns/${campaign_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/list-alerts-for-org',
  `List code scanning alerts for an organization`,
  {
    org: z.string(),
    state: z.string().optional(),
    sort: z.string().optional(),
    severity: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/code-scanning/alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/get-configurations-for-org',
  `Get code security configurations for an organization`,
  {
    org: z.string(),
    target_type: z.string().optional(),
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/code-security/configurations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/create-configuration',
  `Create a code security configuration`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/code-security/configurations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/get-default-configurations',
  `Get default code security configurations`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/code-security/configurations/defaults`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/detach-configuration',
  `Detach configurations from repositories`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/code-security/configurations/detach`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/get-configuration',
  `Get a code security configuration`,
  {
    org: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, configuration_id, ...queryParams } = args
      const url = `/orgs/${org}/code-security/configurations/${configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/update-configuration',
  `Update a code security configuration`,
  {
    org: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, configuration_id, ...requestData } = args
      const url = `/orgs/${org}/code-security/configurations/${configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/delete-configuration',
  `Delete a code security configuration`,
  {
    org: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, configuration_id, ...queryParams } = args
      const url = `/orgs/${org}/code-security/configurations/${configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/attach-configuration',
  `Attach a configuration to repositories`,
  {
    org: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, configuration_id, ...requestData } = args
      const url = `/orgs/${org}/code-security/configurations/${configuration_id}/attach`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/set-configuration-as-default',
  `Set a code security configuration as a default for an organization`,
  {
    org: z.string(),
    configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, configuration_id, ...requestData } = args
      const url = `/orgs/${org}/code-security/configurations/${configuration_id}/defaults`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/get-repositories-for-configuration',
  `Get repositories associated with a code security configuration`,
  {
    org: z.string(),
    configuration_id: z.string(),
    per_page: z.string().optional(),
    status: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, configuration_id, ...queryParams } = args
      const url = `/orgs/${org}/code-security/configurations/${configuration_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-in-organization',
  `List codespaces for the organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/codespaces`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/set-codespaces-access',
  `Manage access control for organization codespaces`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/codespaces/access`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/set-codespaces-access-users',
  `Add users to Codespaces access for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/codespaces/access/selected_users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/delete-codespaces-access-users',
  `Remove users from Codespaces access for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/codespaces/access/selected_users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-org-secrets',
  `List organization secrets`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/codespaces/secrets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-org-public-key',
  `Get an organization public key`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/codespaces/secrets/public-key`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-org-secret',
  `Get an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/create-or-update-org-secret',
  `Create or update an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...requestData } = args
      const url = `/orgs/${org}/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/delete-org-secret',
  `Delete an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-selected-repos-for-org-secret',
  `List selected repositories for an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/codespaces/secrets/${secret_name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/set-selected-repos-for-org-secret',
  `Set selected repositories for an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...requestData } = args
      const url = `/orgs/${org}/codespaces/secrets/${secret_name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/add-selected-repo-to-org-secret',
  `Add selected repository to an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, repository_id, ...requestData } = args
      const url = `/orgs/${org}/codespaces/secrets/${secret_name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/remove-selected-repo-from-org-secret',
  `Remove selected repository from an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, repository_id, ...queryParams } = args
      const url = `/orgs/${org}/codespaces/secrets/${secret_name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/get-copilot-organization-details',
  `Get Copilot seat information and settings for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/copilot/billing`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/list-copilot-seats',
  `List all Copilot seat assignments for an organization`,
  {
    org: z.string(),
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/copilot/billing/seats`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/add-copilot-seats-for-teams',
  `Add teams to the Copilot subscription for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/copilot/billing/selected_teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/cancel-copilot-seat-assignment-for-teams',
  `Remove teams from the Copilot subscription for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/copilot/billing/selected_teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/add-copilot-seats-for-users',
  `Add users to the Copilot subscription for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/copilot/billing/selected_users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/cancel-copilot-seat-assignment-for-users',
  `Remove users from the Copilot subscription for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/copilot/billing/selected_users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/copilot-metrics-for-organization',
  `Get Copilot metrics for an organization`,
  {
    org: z.string(),
    since: z.string().optional(),
    until: z.string().optional(),
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/copilot/metrics`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/list-alerts-for-org',
  `List Dependabot alerts for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/dependabot/alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/list-org-secrets',
  `List organization secrets`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/dependabot/secrets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/get-org-public-key',
  `Get an organization public key`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/dependabot/secrets/public-key`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/get-org-secret',
  `Get an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/dependabot/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/create-or-update-org-secret',
  `Create or update an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...requestData } = args
      const url = `/orgs/${org}/dependabot/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/delete-org-secret',
  `Delete an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/dependabot/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/list-selected-repos-for-org-secret',
  `List selected repositories for an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/dependabot/secrets/${secret_name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/set-selected-repos-for-org-secret',
  `Set selected repositories for an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...requestData } = args
      const url = `/orgs/${org}/dependabot/secrets/${secret_name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/add-selected-repo-to-org-secret',
  `Add selected repository to an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, repository_id, ...requestData } = args
      const url = `/orgs/${org}/dependabot/secrets/${secret_name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/remove-selected-repo-from-org-secret',
  `Remove selected repository from an organization secret`,
  {
    org: z.string(),
    secret_name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, repository_id, ...queryParams } = args
      const url = `/orgs/${org}/dependabot/secrets/${secret_name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/list-docker-migration-conflicting-packages-for-organization',
  `Get list of conflicting packages during Docker migration for organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/docker/conflicts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-public-org-events',
  `List public organization events`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/events`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-failed-invitations',
  `List failed organization invitations`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/failed_invitations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-webhooks',
  `List organization webhooks`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/hooks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/create-webhook',
  `Create an organization webhook`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/hooks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-webhook',
  `Get an organization webhook`,
  {
    org: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, ...queryParams } = args
      const url = `/orgs/${org}/hooks/${hook_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/update-webhook',
  `Update an organization webhook`,
  {
    org: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, ...requestData } = args
      const url = `/orgs/${org}/hooks/${hook_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/delete-webhook',
  `Delete an organization webhook`,
  {
    org: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, ...queryParams } = args
      const url = `/orgs/${org}/hooks/${hook_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-webhook-config-for-org',
  `Get a webhook configuration for an organization`,
  {
    org: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, ...queryParams } = args
      const url = `/orgs/${org}/hooks/${hook_id}/config`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/update-webhook-config-for-org',
  `Update a webhook configuration for an organization`,
  {
    org: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, ...requestData } = args
      const url = `/orgs/${org}/hooks/${hook_id}/config`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-webhook-deliveries',
  `List deliveries for an organization webhook`,
  {
    org: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, ...queryParams } = args
      const url = `/orgs/${org}/hooks/${hook_id}/deliveries`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-webhook-delivery',
  `Get a webhook delivery for an organization webhook`,
  {
    org: z.string(),
    hook_id: z.string(),
    delivery_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, delivery_id, ...queryParams } = args
      const url = `/orgs/${org}/hooks/${hook_id}/deliveries/${delivery_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/redeliver-webhook-delivery',
  `Redeliver a delivery for an organization webhook`,
  {
    org: z.string(),
    hook_id: z.string(),
    delivery_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, delivery_id, ...requestData } = args
      const url = `/orgs/${org}/hooks/${hook_id}/deliveries/${delivery_id}/attempts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/ping-webhook',
  `Ping an organization webhook`,
  {
    org: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, hook_id, ...requestData } = args
      const url = `/orgs/${org}/hooks/${hook_id}/pings`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-route-stats-by-actor',
  `Get route stats by actor`,
  {
    org: z.string(),
    actor_type: z.string(),
    actor_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, actor_type, actor_id, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/route-stats/${actor_type}/${actor_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-subject-stats',
  `Get subject stats`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/subject-stats`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-summary-stats',
  `Get summary stats`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/summary-stats`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-summary-stats-by-user',
  `Get summary stats by user`,
  {
    org: z.string(),
    user_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, user_id, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/summary-stats/users/${user_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-summary-stats-by-actor',
  `Get summary stats by actor`,
  {
    org: z.string(),
    actor_type: z.string(),
    actor_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, actor_type, actor_id, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/summary-stats/${actor_type}/${actor_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-time-stats',
  `Get time stats`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/time-stats`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-time-stats-by-user',
  `Get time stats by user`,
  {
    org: z.string(),
    user_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, user_id, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/time-stats/users/${user_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-time-stats-by-actor',
  `Get time stats by actor`,
  {
    org: z.string(),
    actor_type: z.string(),
    actor_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, actor_type, actor_id, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/time-stats/${actor_type}/${actor_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'api-insights/get-user-stats',
  `Get user stats`,
  {
    org: z.string(),
    user_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, user_id, ...queryParams } = args
      const url = `/orgs/${org}/insights/api/user-stats/${user_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/get-org-installation',
  `Get an organization installation for the authenticated app`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/installation`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-app-installations',
  `List app installations for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/installations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/get-restrictions-for-org',
  `Get interaction restrictions for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/interaction-limits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/set-restrictions-for-org',
  `Set interaction restrictions for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/interaction-limits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/remove-restrictions-for-org',
  `Remove interaction restrictions for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/interaction-limits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-pending-invitations',
  `List pending organization invitations`,
  {
    org: z.string(),
    role: z.string().optional(),
    invitation_source: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/invitations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/create-invitation',
  `Create an organization invitation`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/invitations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/cancel-invitation',
  `Cancel an organization invitation`,
  {
    org: z.string(),
    invitation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, invitation_id, ...queryParams } = args
      const url = `/orgs/${org}/invitations/${invitation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-invitation-teams',
  `List organization invitation teams`,
  {
    org: z.string(),
    invitation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, invitation_id, ...queryParams } = args
      const url = `/orgs/${org}/invitations/${invitation_id}/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-issue-types',
  `List issue types for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/issue-types`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/create-issue-type',
  `Create issue type for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/issue-types`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/update-issue-type',
  `Update issue type for an organization`,
  {
    org: z.string(),
    issue_type_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, issue_type_id, ...requestData } = args
      const url = `/orgs/${org}/issue-types/${issue_type_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/delete-issue-type',
  `Delete issue type for an organization`,
  {
    org: z.string(),
    issue_type_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, issue_type_id, ...queryParams } = args
      const url = `/orgs/${org}/issue-types/${issue_type_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-for-org',
  `List organization issues assigned to the authenticated user`,
  {
    org: z.string(),
    filter: z.string().optional(),
    state: z.string().optional(),
    type: z.string().optional(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/issues`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-members',
  `List organization members`,
  {
    org: z.string(),
    filter: z.string().optional(),
    role: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/members`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/check-membership-for-user',
  `Check organization membership for a user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/members/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/remove-member',
  `Remove an organization member`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/members/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-codespaces-for-user-in-org',
  `List codespaces for a user in organization`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/members/${username}/codespaces`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/delete-from-organization',
  `Delete a codespace from the organization`,
  {
    org: z.string(),
    username: z.string(),
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, codespace_name, ...queryParams } = args
      const url = `/orgs/${org}/members/${username}/codespaces/${codespace_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/stop-in-organization',
  `Stop a codespace for an organization user`,
  {
    org: z.string(),
    username: z.string(),
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, codespace_name, ...requestData } = args
      const url = `/orgs/${org}/members/${username}/codespaces/${codespace_name}/stop`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/get-copilot-seat-details-for-user',
  `Get Copilot seat assignment details for a user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/members/${username}/copilot`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-membership-for-user',
  `Get organization membership for a user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/set-membership-for-user',
  `Set organization membership for a user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...requestData } = args
      const url = `/orgs/${org}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/remove-membership-for-user',
  `Remove organization membership for a user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/list-for-org',
  `List organization migrations`,
  {
    org: z.string(),
    exclude: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/migrations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/start-for-org',
  `Start an organization migration`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/migrations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/get-status-for-org',
  `Get an organization migration status`,
  {
    org: z.string(),
    migration_id: z.string(),
    exclude: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, migration_id, ...queryParams } = args
      const url = `/orgs/${org}/migrations/${migration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/download-archive-for-org',
  `Download an organization migration archive`,
  {
    org: z.string(),
    migration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, migration_id, ...queryParams } = args
      const url = `/orgs/${org}/migrations/${migration_id}/archive`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/delete-archive-for-org',
  `Delete an organization migration archive`,
  {
    org: z.string(),
    migration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, migration_id, ...queryParams } = args
      const url = `/orgs/${org}/migrations/${migration_id}/archive`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/unlock-repo-for-org',
  `Unlock an organization repository`,
  {
    org: z.string(),
    migration_id: z.string(),
    repo_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, migration_id, repo_name, ...queryParams } = args
      const url = `/orgs/${org}/migrations/${migration_id}/repos/${repo_name}/lock`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/list-repos-for-org',
  `List repositories in an organization migration`,
  {
    org: z.string(),
    migration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, migration_id, ...queryParams } = args
      const url = `/orgs/${org}/migrations/${migration_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-org-roles',
  `Get all organization roles for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/organization-roles`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/revoke-all-org-roles-team',
  `Remove all organization roles for a team`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/organization-roles/teams/${team_slug}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/assign-team-to-org-role',
  `Assign an organization role to a team`,
  {
    org: z.string(),
    team_slug: z.string(),
    role_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, role_id, ...requestData } = args
      const url = `/orgs/${org}/organization-roles/teams/${team_slug}/${role_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/revoke-org-role-team',
  `Remove an organization role from a team`,
  {
    org: z.string(),
    team_slug: z.string(),
    role_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, role_id, ...queryParams } = args
      const url = `/orgs/${org}/organization-roles/teams/${team_slug}/${role_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/revoke-all-org-roles-user',
  `Remove all organization roles for a user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/organization-roles/users/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/assign-user-to-org-role',
  `Assign an organization role to a user`,
  {
    org: z.string(),
    username: z.string(),
    role_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, role_id, ...requestData } = args
      const url = `/orgs/${org}/organization-roles/users/${username}/${role_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/revoke-org-role-user',
  `Remove an organization role from a user`,
  {
    org: z.string(),
    username: z.string(),
    role_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, role_id, ...queryParams } = args
      const url = `/orgs/${org}/organization-roles/users/${username}/${role_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-org-role',
  `Get an organization role`,
  {
    org: z.string(),
    role_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, role_id, ...queryParams } = args
      const url = `/orgs/${org}/organization-roles/${role_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-org-role-teams',
  `List teams that are assigned to an organization role`,
  {
    org: z.string(),
    role_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, role_id, ...queryParams } = args
      const url = `/orgs/${org}/organization-roles/${role_id}/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-org-role-users',
  `List users that are assigned to an organization role`,
  {
    org: z.string(),
    role_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, role_id, ...queryParams } = args
      const url = `/orgs/${org}/organization-roles/${role_id}/users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-outside-collaborators',
  `List outside collaborators for an organization`,
  {
    org: z.string(),
    filter: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/outside_collaborators`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/convert-member-to-outside-collaborator',
  `Convert an organization member to outside collaborator`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...requestData } = args
      const url = `/orgs/${org}/outside_collaborators/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/remove-outside-collaborator',
  `Remove outside collaborator from an organization`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/outside_collaborators/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/list-packages-for-organization',
  `List packages for an organization`,
  {
    org: z.string(),
    package_type: z.string(),
    page: z.string().optional(),
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/packages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-package-for-organization',
  `Get a package for an organization`,
  {
    org: z.string(),
    package_type: z.string(),
    package_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, package_type, package_name, ...queryParams } = args
      const url = `/orgs/${org}/packages/${package_type}/${package_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/delete-package-for-org',
  `Delete a package for an organization`,
  {
    org: z.string(),
    package_type: z.string(),
    package_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, package_type, package_name, ...queryParams } = args
      const url = `/orgs/${org}/packages/${package_type}/${package_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/restore-package-for-org',
  `Restore a package for an organization`,
  {
    org: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    token: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, package_type, package_name, ...requestData } = args
      const url = `/orgs/${org}/packages/${package_type}/${package_name}/restore`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-all-package-versions-for-package-owned-by-org',
  `List package versions for a package owned by an organization`,
  {
    org: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, package_type, package_name, ...queryParams } = args
      const url = `/orgs/${org}/packages/${package_type}/${package_name}/versions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-package-version-for-organization',
  `Get a package version for an organization`,
  {
    org: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, package_type, package_name, package_version_id, ...queryParams } = args
      const url = `/orgs/${org}/packages/${package_type}/${package_name}/versions/${package_version_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/delete-package-version-for-org',
  `Delete package version for an organization`,
  {
    org: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, package_type, package_name, package_version_id, ...queryParams } = args
      const url = `/orgs/${org}/packages/${package_type}/${package_name}/versions/${package_version_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/restore-package-version-for-org',
  `Restore package version for an organization`,
  {
    org: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, package_type, package_name, package_version_id, ...requestData } = args
      const url = `/orgs/${org}/packages/${package_type}/${package_name}/versions/${package_version_id}/restore`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-pat-grant-requests',
  `List requests to access organization resources with fine-grained personal access tokens`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/personal-access-token-requests`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/review-pat-grant-requests-in-bulk',
  `Review requests to access organization resources with fine-grained personal access tokens`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/personal-access-token-requests`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/review-pat-grant-request',
  `Review a request to access organization resources with a fine-grained personal access token`,
  {
    org: z.string(),
    pat_request_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, pat_request_id, ...requestData } = args
      const url = `/orgs/${org}/personal-access-token-requests/${pat_request_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-pat-grant-request-repositories',
  `List repositories requested to be accessed by a fine-grained personal access token`,
  {
    org: z.string(),
    pat_request_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, pat_request_id, ...queryParams } = args
      const url = `/orgs/${org}/personal-access-token-requests/${pat_request_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-pat-grants',
  `List fine-grained personal access tokens with access to organization resources`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/personal-access-tokens`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/update-pat-accesses',
  `Update the access to organization resources via fine-grained personal access tokens`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/personal-access-tokens`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/update-pat-access',
  `Update the access a fine-grained personal access token has to organization resources`,
  {
    org: z.string(),
    pat_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, pat_id, ...requestData } = args
      const url = `/orgs/${org}/personal-access-tokens/${pat_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-pat-grant-repositories',
  `List repositories a fine-grained personal access token has access to`,
  {
    org: z.string(),
    pat_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, pat_id, ...queryParams } = args
      const url = `/orgs/${org}/personal-access-tokens/${pat_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'private-registries/list-org-private-registries',
  `List private registries for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/private-registries`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'private-registries/create-org-private-registry',
  `Create a private registry for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/private-registries`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'private-registries/get-org-public-key',
  `Get private registries public key for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/private-registries/public-key`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'private-registries/get-org-private-registry',
  `Get a private registry for an organization`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/private-registries/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'private-registries/update-org-private-registry',
  `Update a private registry for an organization`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...requestData } = args
      const url = `/orgs/${org}/private-registries/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'private-registries/delete-org-private-registry',
  `Delete a private registry for an organization`,
  {
    org: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, secret_name, ...queryParams } = args
      const url = `/orgs/${org}/private-registries/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/list-for-org',
  `List organization projects`,
  {
    org: z.string(),
    state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/projects`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/create-for-org',
  `Create an organization project`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/projects`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-all-custom-properties',
  `Get all custom properties for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/properties/schema`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/create-or-update-custom-properties',
  `Create or update custom properties for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/properties/schema`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-custom-property',
  `Get a custom property for an organization`,
  {
    org: z.string(),
    custom_property_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, custom_property_name, ...queryParams } = args
      const url = `/orgs/${org}/properties/schema/${custom_property_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/create-or-update-custom-property',
  `Create or update a custom property for an organization`,
  {
    org: z.string(),
    custom_property_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, custom_property_name, ...requestData } = args
      const url = `/orgs/${org}/properties/schema/${custom_property_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/remove-custom-property',
  `Remove a custom property for an organization`,
  {
    org: z.string(),
    custom_property_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, custom_property_name, ...queryParams } = args
      const url = `/orgs/${org}/properties/schema/${custom_property_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-custom-properties-values-for-repos',
  `List custom property values for organization repositories`,
  {
    org: z.string(),
    repository_query: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/properties/values`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/create-or-update-custom-properties-values-for-repos',
  `Create or update custom property values for organization repositories`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/properties/values`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-public-members',
  `List public organization members`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/public_members`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/check-public-membership-for-user',
  `Check public organization membership for a user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/public_members/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/set-public-membership-for-authenticated-user',
  `Set public organization membership for the authenticated user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...requestData } = args
      const url = `/orgs/${org}/public_members/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/remove-public-membership-for-authenticated-user',
  `Remove public organization membership for the authenticated user`,
  {
    org: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, username, ...queryParams } = args
      const url = `/orgs/${org}/public_members/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-for-org',
  `List organization repositories`,
  {
    org: z.string(),
    type: z.string().optional(),
    sort: z.string().optional(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/repos`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-in-org',
  `Create an organization repository`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/repos`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-org-rulesets',
  `Get all organization repository rulesets`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/rulesets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-org-ruleset',
  `Create an organization repository ruleset`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/rulesets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-org-rule-suites',
  `List organization rule suites`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/rulesets/rule-suites`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-org-rule-suite',
  `Get an organization rule suite`,
  {
    org: z.string(),
    rule_suite_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, rule_suite_id, ...queryParams } = args
      const url = `/orgs/${org}/rulesets/rule-suites/${rule_suite_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-org-ruleset',
  `Get an organization repository ruleset`,
  {
    org: z.string(),
    ruleset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ruleset_id, ...queryParams } = args
      const url = `/orgs/${org}/rulesets/${ruleset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-org-ruleset',
  `Update an organization repository ruleset`,
  {
    org: z.string(),
    ruleset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ruleset_id, ...requestData } = args
      const url = `/orgs/${org}/rulesets/${ruleset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-org-ruleset',
  `Delete an organization repository ruleset`,
  {
    org: z.string(),
    ruleset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ruleset_id, ...queryParams } = args
      const url = `/orgs/${org}/rulesets/${ruleset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-org-ruleset-history',
  `Get organization ruleset history`,
  {
    org: z.string(),
    ruleset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ruleset_id, ...queryParams } = args
      const url = `/orgs/${org}/rulesets/${ruleset_id}/history`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-org-ruleset-version',
  `Get organization ruleset version`,
  {
    org: z.string(),
    ruleset_id: z.string(),
    version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ruleset_id, version_id, ...queryParams } = args
      const url = `/orgs/${org}/rulesets/${ruleset_id}/history/${version_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'secret-scanning/list-alerts-for-org',
  `List secret scanning alerts for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/secret-scanning/alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/list-org-repository-advisories',
  `List repository security advisories for an organization`,
  {
    org: z.string(),
    sort: z.string().optional(),
    per_page: z.string().optional(),
    state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/security-advisories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-security-manager-teams',
  `List security manager teams`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/security-managers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/add-security-manager-team',
  `Add a security manager team`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...requestData } = args
      const url = `/orgs/${org}/security-managers/teams/${team_slug}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/remove-security-manager-team',
  `Remove a security manager team`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/security-managers/teams/${team_slug}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'billing/get-github-actions-billing-org',
  `Get GitHub Actions billing for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/settings/billing/actions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'billing/get-github-packages-billing-org',
  `Get GitHub Packages billing for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/settings/billing/packages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'billing/get-shared-storage-billing-org',
  `Get shared storage billing for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/settings/billing/shared-storage`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'hosted-compute/list-network-configurations-for-org',
  `List hosted compute network configurations for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/settings/network-configurations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'hosted-compute/create-network-configuration-for-org',
  `Create a hosted compute network configuration for an organization`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/settings/network-configurations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'hosted-compute/get-network-configuration-for-org',
  `Get a hosted compute network configuration for an organization`,
  {
    org: z.string(),
    network_configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, network_configuration_id, ...queryParams } = args
      const url = `/orgs/${org}/settings/network-configurations/${network_configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'hosted-compute/update-network-configuration-for-org',
  `Update a hosted compute network configuration for an organization`,
  {
    org: z.string(),
    network_configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, network_configuration_id, ...requestData } = args
      const url = `/orgs/${org}/settings/network-configurations/${network_configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'hosted-compute/delete-network-configuration-from-org',
  `Delete a hosted compute network configuration from an organization`,
  {
    org: z.string(),
    network_configuration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, network_configuration_id, ...queryParams } = args
      const url = `/orgs/${org}/settings/network-configurations/${network_configuration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'hosted-compute/get-network-settings-for-org',
  `Get a hosted compute network settings resource for an organization`,
  {
    org: z.string(),
    network_settings_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, network_settings_id, ...queryParams } = args
      const url = `/orgs/${org}/settings/network-settings/${network_settings_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'copilot/copilot-metrics-for-team',
  `Get Copilot metrics for a team`,
  {
    org: z.string(),
    team_slug: z.string(),
    since: z.string().optional(),
    until: z.string().optional(),
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/team/${team_slug}/copilot/metrics`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list',
  `List teams`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/orgs/${org}/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/create',
  `Create a team`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/orgs/${org}/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-by-name',
  `Get a team by name`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/update-in-org',
  `Update a team`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/delete-in-org',
  `Delete a team`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-discussions-in-org',
  `List discussions`,
  {
    org: z.string(),
    team_slug: z.string(),
    pinned: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/create-discussion-in-org',
  `Create a discussion`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-discussion-in-org',
  `Get a discussion`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/update-discussion-in-org',
  `Update a discussion`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/delete-discussion-in-org',
  `Delete a discussion`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-discussion-comments-in-org',
  `List discussion comments`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/create-discussion-comment-in-org',
  `Create a discussion comment`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-discussion-comment-in-org',
  `Get a discussion comment`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, comment_number, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/comments/${comment_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/update-discussion-comment-in-org',
  `Update a discussion comment`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, comment_number, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/comments/${comment_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/delete-discussion-comment-in-org',
  `Delete a discussion comment`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, comment_number, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/comments/${comment_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-team-discussion-comment-in-org',
  `List reactions for a team discussion comment`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, comment_number, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/comments/${comment_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-team-discussion-comment-in-org',
  `Create reaction for a team discussion comment`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, comment_number, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/comments/${comment_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/delete-for-team-discussion-comment',
  `Delete team discussion comment reaction`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
    reaction_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, comment_number, reaction_id, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/comments/${comment_number}/reactions/${reaction_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-team-discussion-in-org',
  `List reactions for a team discussion`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-team-discussion-in-org',
  `Create reaction for a team discussion`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/delete-for-team-discussion',
  `Delete team discussion reaction`,
  {
    org: z.string(),
    team_slug: z.string(),
    discussion_number: z.string(),
    reaction_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, discussion_number, reaction_id, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/discussions/${discussion_number}/reactions/${reaction_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-pending-invitations-in-org',
  `List pending team invitations`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/invitations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-members-in-org',
  `List team members`,
  {
    org: z.string(),
    team_slug: z.string(),
    role: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/members`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-membership-for-user-in-org',
  `Get team membership for a user`,
  {
    org: z.string(),
    team_slug: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, username, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/add-or-update-membership-for-user-in-org',
  `Add or update team membership for a user`,
  {
    org: z.string(),
    team_slug: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, username, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/remove-membership-for-user-in-org',
  `Remove team membership for a user`,
  {
    org: z.string(),
    team_slug: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, username, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-projects-in-org',
  `List team projects`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/projects`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/check-permissions-for-project-in-org',
  `Check team permissions for a project`,
  {
    org: z.string(),
    team_slug: z.string(),
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, project_id, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/add-or-update-project-permissions-in-org',
  `Add or update team project permissions`,
  {
    org: z.string(),
    team_slug: z.string(),
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, project_id, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/remove-project-in-org',
  `Remove a project from a team`,
  {
    org: z.string(),
    team_slug: z.string(),
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, project_id, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-repos-in-org',
  `List team repositories`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/repos`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/check-permissions-for-repo-in-org',
  `Check team permissions for a repository`,
  {
    org: z.string(),
    team_slug: z.string(),
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, owner, repo, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/add-or-update-repo-permissions-in-org',
  `Add or update team repository permissions`,
  {
    org: z.string(),
    team_slug: z.string(),
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, owner, repo, ...requestData } = args
      const url = `/orgs/${org}/teams/${team_slug}/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/remove-repo-in-org',
  `Remove a repository from a team`,
  {
    org: z.string(),
    team_slug: z.string(),
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, owner, repo, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-child-in-org',
  `List child teams`,
  {
    org: z.string(),
    team_slug: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, team_slug, ...queryParams } = args
      const url = `/orgs/${org}/teams/${team_slug}/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/enable-or-disable-security-product-on-all-org-repos',
  `Enable or disable a security feature for an organization`,
  {
    org: z.string(),
    security_product: z.string(),
    enablement: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, security_product, enablement, ...requestData } = args
      const url = `/orgs/${org}/${security_product}/${enablement}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/get-card',
  `Get a project card`,
  {
    card_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { card_id, ...queryParams } = args
      const url = `/projects/columns/cards/${card_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/update-card',
  `Update an existing project card`,
  {
    card_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { card_id, ...requestData } = args
      const url = `/projects/columns/cards/${card_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/delete-card',
  `Delete a project card`,
  {
    card_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { card_id, ...queryParams } = args
      const url = `/projects/columns/cards/${card_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/move-card',
  `Move a project card`,
  {
    card_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { card_id, ...requestData } = args
      const url = `/projects/columns/cards/${card_id}/moves`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/get-column',
  `Get a project column`,
  {
    column_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { column_id, ...queryParams } = args
      const url = `/projects/columns/${column_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/update-column',
  `Update an existing project column`,
  {
    column_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { column_id, ...requestData } = args
      const url = `/projects/columns/${column_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/delete-column',
  `Delete a project column`,
  {
    column_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { column_id, ...queryParams } = args
      const url = `/projects/columns/${column_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/list-cards',
  `List project cards`,
  {
    column_id: z.string(),
    archived_state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { column_id, ...queryParams } = args
      const url = `/projects/columns/${column_id}/cards`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/create-card',
  `Create a project card`,
  {
    column_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { column_id, ...requestData } = args
      const url = `/projects/columns/${column_id}/cards`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/move-column',
  `Move a project column`,
  {
    column_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { column_id, ...requestData } = args
      const url = `/projects/columns/${column_id}/moves`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/get',
  `Get a project`,
  {
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { project_id, ...queryParams } = args
      const url = `/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/update',
  `Update a project`,
  {
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { project_id, ...requestData } = args
      const url = `/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/delete',
  `Delete a project`,
  {
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { project_id, ...queryParams } = args
      const url = `/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/list-collaborators',
  `List project collaborators`,
  {
    project_id: z.string(),
    affiliation: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { project_id, ...queryParams } = args
      const url = `/projects/${project_id}/collaborators`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/add-collaborator',
  `Add project collaborator`,
  {
    project_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { project_id, username, ...requestData } = args
      const url = `/projects/${project_id}/collaborators/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/remove-collaborator',
  `Remove user as a collaborator`,
  {
    project_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { project_id, username, ...queryParams } = args
      const url = `/projects/${project_id}/collaborators/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/get-permission-for-user',
  `Get project permission for a user`,
  {
    project_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { project_id, username, ...queryParams } = args
      const url = `/projects/${project_id}/collaborators/${username}/permission`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/list-columns',
  `List project columns`,
  {
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { project_id, ...queryParams } = args
      const url = `/projects/${project_id}/columns`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/create-column',
  `Create a project column`,
  {
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { project_id, ...requestData } = args
      const url = `/projects/${project_id}/columns`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('rate-limit/get', `Get rate limit status for the authenticated user`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/rate_limit',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'repos/get',
  `Get a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update',
  `Update a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete',
  `Delete a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-artifacts-for-repo',
  `List artifacts for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/artifacts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-artifact',
  `Get an artifact`,
  {
    owner: z.string(),
    repo: z.string(),
    artifact_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, artifact_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/artifacts/${artifact_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-artifact',
  `Delete an artifact`,
  {
    owner: z.string(),
    repo: z.string(),
    artifact_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, artifact_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/artifacts/${artifact_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/download-artifact',
  `Download an artifact`,
  {
    owner: z.string(),
    repo: z.string(),
    artifact_id: z.string(),
    archive_format: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, artifact_id, archive_format, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/artifacts/${artifact_id}/${archive_format}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-actions-cache-usage',
  `Get GitHub Actions cache usage for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/cache/usage`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-actions-cache-list',
  `List GitHub Actions caches for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/caches`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-actions-cache-by-key',
  `Delete GitHub Actions caches for a repository (using a cache key)`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/caches`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-actions-cache-by-id',
  `Delete a GitHub Actions cache for a repository (using a cache ID)`,
  {
    owner: z.string(),
    repo: z.string(),
    cache_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, cache_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/caches/${cache_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-job-for-workflow-run',
  `Get a job for a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    job_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, job_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/jobs/${job_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/download-job-logs-for-workflow-run',
  `Download job logs for a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    job_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, job_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/jobs/${job_id}/logs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/re-run-job-for-workflow-run',
  `Re-run a job from a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    job_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, job_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/jobs/${job_id}/rerun`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-custom-oidc-sub-claim-for-repo',
  `Get the customization template for an OIDC subject claim for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/oidc/customization/sub`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-custom-oidc-sub-claim-for-repo',
  `Set the customization template for an OIDC subject claim for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/oidc/customization/sub`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-repo-organization-secrets',
  `List repository organization secrets`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/organization-secrets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-repo-organization-variables',
  `List repository organization variables`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/organization-variables`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-github-actions-permissions-repository',
  `Get GitHub Actions permissions for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/permissions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-github-actions-permissions-repository',
  `Set GitHub Actions permissions for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/permissions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-workflow-access-to-repository',
  `Get the level of access for workflows outside of the repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/permissions/access`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-workflow-access-to-repository',
  `Set the level of access for workflows outside of the repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/permissions/access`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-allowed-actions-repository',
  `Get allowed actions and reusable workflows for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/permissions/selected-actions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-allowed-actions-repository',
  `Set allowed actions and reusable workflows for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/permissions/selected-actions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-github-actions-default-workflow-permissions-repository',
  `Get default workflow permissions for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/permissions/workflow`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-github-actions-default-workflow-permissions-repository',
  `Set default workflow permissions for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/permissions/workflow`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-self-hosted-runners-for-repo',
  `List self-hosted runners for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    name: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runners`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-runner-applications-for-repo',
  `List runner applications for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runners/downloads`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/generate-runner-jitconfig-for-repo',
  `Create configuration for a just-in-time runner for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runners/generate-jitconfig`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-registration-token-for-repo',
  `Create a registration token for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runners/registration-token`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-remove-token-for-repo',
  `Create a remove token for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runners/remove-token`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-self-hosted-runner-for-repo',
  `Get a self-hosted runner for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, runner_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runners/${runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-self-hosted-runner-from-repo',
  `Delete a self-hosted runner from a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, runner_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runners/${runner_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-labels-for-self-hosted-runner-for-repo',
  `List labels for a self-hosted runner for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, runner_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runners/${runner_id}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/add-custom-labels-to-self-hosted-runner-for-repo',
  `Add custom labels to a self-hosted runner for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, runner_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runners/${runner_id}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/set-custom-labels-for-self-hosted-runner-for-repo',
  `Set custom labels for a self-hosted runner for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, runner_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runners/${runner_id}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/remove-all-custom-labels-from-self-hosted-runner-for-repo',
  `Remove all custom labels from a self-hosted runner for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    runner_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, runner_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runners/${runner_id}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/remove-custom-label-from-self-hosted-runner-for-repo',
  `Remove a custom label from a self-hosted runner for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    runner_id: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, runner_id, name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runners/${runner_id}/labels/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-workflow-runs-for-repo',
  `List workflow runs for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-workflow-run',
  `Get a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-workflow-run',
  `Delete a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-reviews-for-run',
  `Get the review history for a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/approvals`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/approve-workflow-run',
  `Approve a workflow run for a fork pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/approve`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-workflow-run-artifacts',
  `List workflow run artifacts`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/artifacts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-workflow-run-attempt',
  `Get a workflow run attempt`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
    attempt_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, attempt_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/attempts/${attempt_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-jobs-for-workflow-run-attempt',
  `List jobs for a workflow run attempt`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
    attempt_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, attempt_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/attempts/${attempt_number}/jobs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/download-workflow-run-attempt-logs',
  `Download workflow run attempt logs`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
    attempt_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, attempt_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/attempts/${attempt_number}/logs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/cancel-workflow-run',
  `Cancel a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/cancel`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/review-custom-gates-for-run',
  `Review custom deployment protection rules for a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/deployment_protection_rule`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/force-cancel-workflow-run',
  `Force cancel a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/force-cancel`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-jobs-for-workflow-run',
  `List jobs for a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
    filter: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/jobs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/download-workflow-run-logs',
  `Download workflow run logs`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/logs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-workflow-run-logs',
  `Delete workflow run logs`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/logs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-pending-deployments-for-run',
  `Get pending deployments for a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/pending_deployments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/review-pending-deployments-for-run',
  `Review pending deployments for a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/pending_deployments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/re-run-workflow',
  `Re-run a workflow`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/rerun`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/re-run-workflow-failed-jobs',
  `Re-run failed jobs from a workflow run`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/rerun-failed-jobs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-workflow-run-usage',
  `Get workflow run usage`,
  {
    owner: z.string(),
    repo: z.string(),
    run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/runs/${run_id}/timing`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-repo-secrets',
  `List repository secrets`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/secrets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-repo-public-key',
  `Get a repository public key`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/secrets/public-key`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-repo-secret',
  `Get a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-or-update-repo-secret',
  `Create or update a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-repo-secret',
  `Delete a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-repo-variables',
  `List repository variables`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/variables`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-repo-variable',
  `Create a repository variable`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/variables`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-repo-variable',
  `Get a repository variable`,
  {
    owner: z.string(),
    repo: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/update-repo-variable',
  `Update a repository variable`,
  {
    owner: z.string(),
    repo: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-repo-variable',
  `Delete a repository variable`,
  {
    owner: z.string(),
    repo: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-repo-workflows',
  `List repository workflows`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/workflows`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-workflow',
  `Get a workflow`,
  {
    owner: z.string(),
    repo: z.string(),
    workflow_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, workflow_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/workflows/${workflow_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/disable-workflow',
  `Disable a workflow`,
  {
    owner: z.string(),
    repo: z.string(),
    workflow_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, workflow_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/workflows/${workflow_id}/disable`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-workflow-dispatch',
  `Create a workflow dispatch event`,
  {
    owner: z.string(),
    repo: z.string(),
    workflow_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, workflow_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/workflows/${workflow_id}/dispatches`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/enable-workflow',
  `Enable a workflow`,
  {
    owner: z.string(),
    repo: z.string(),
    workflow_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, workflow_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/actions/workflows/${workflow_id}/enable`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-workflow-runs',
  `List workflow runs for a workflow`,
  {
    owner: z.string(),
    repo: z.string(),
    workflow_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, workflow_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/workflows/${workflow_id}/runs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-workflow-usage',
  `Get workflow usage`,
  {
    owner: z.string(),
    repo: z.string(),
    workflow_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, workflow_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/actions/workflows/${workflow_id}/timing`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-activities',
  `List repository activities`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string().optional(),
    actor: z.string().optional(),
    time_period: z.string().optional(),
    activity_type: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/activity`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-assignees',
  `List assignees`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/assignees`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/check-user-can-be-assigned',
  `Check if a user can be assigned`,
  {
    owner: z.string(),
    repo: z.string(),
    assignee: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, assignee, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/assignees/${assignee}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-attestation',
  `Create an attestation`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/attestations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-attestations',
  `List attestations`,
  {
    owner: z.string(),
    repo: z.string(),
    subject_digest: z.string(),
    predicate_type: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, subject_digest, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/attestations/${subject_digest}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-autolinks',
  `Get all autolinks of a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/autolinks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-autolink',
  `Create an autolink reference for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/autolinks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-autolink',
  `Get an autolink reference of a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    autolink_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, autolink_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/autolinks/${autolink_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-autolink',
  `Delete an autolink reference from a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    autolink_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, autolink_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/autolinks/${autolink_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/check-automated-security-fixes',
  `Check if Dependabot security updates are enabled for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/automated-security-fixes`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/enable-automated-security-fixes',
  `Enable Dependabot security updates`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/automated-security-fixes`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/disable-automated-security-fixes',
  `Disable Dependabot security updates`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/automated-security-fixes`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-branches',
  `List branches`,
  {
    owner: z.string(),
    repo: z.string(),
    protected: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-branch',
  `Get a branch`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-branch-protection',
  `Get branch protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-branch-protection',
  `Update branch protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-branch-protection',
  `Delete branch protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-admin-branch-protection',
  `Get admin branch protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/enforce_admins`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/set-admin-branch-protection',
  `Set admin branch protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/enforce_admins`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-admin-branch-protection',
  `Delete admin branch protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/enforce_admins`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-pull-request-review-protection',
  `Get pull request review protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_pull_request_reviews`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-pull-request-review-protection',
  `Update pull request review protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_pull_request_reviews`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-pull-request-review-protection',
  `Delete pull request review protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_pull_request_reviews`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-commit-signature-protection',
  `Get commit signature protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_signatures`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-commit-signature-protection',
  `Create commit signature protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_signatures`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-commit-signature-protection',
  `Delete commit signature protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_signatures`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-status-checks-protection',
  `Get status checks protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_status_checks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-status-check-protection',
  `Update status check protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_status_checks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/remove-status-check-protection',
  `Remove status check protection`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_status_checks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-all-status-check-contexts',
  `Get all status check contexts`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_status_checks/contexts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/add-status-check-contexts',
  `Add status check contexts`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_status_checks/contexts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/set-status-check-contexts',
  `Set status check contexts`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_status_checks/contexts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/remove-status-check-contexts',
  `Remove status check contexts`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/required_status_checks/contexts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-access-restrictions',
  `Get access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-access-restrictions',
  `Delete access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-apps-with-access-to-protected-branch',
  `Get apps with access to the protected branch`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/apps`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/add-app-access-restrictions',
  `Add app access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/apps`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/set-app-access-restrictions',
  `Set app access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/apps`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/remove-app-access-restrictions',
  `Remove app access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/apps`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-teams-with-access-to-protected-branch',
  `Get teams with access to the protected branch`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/add-team-access-restrictions',
  `Add team access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/set-team-access-restrictions',
  `Set team access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/remove-team-access-restrictions',
  `Remove team access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-users-with-access-to-protected-branch',
  `Get users with access to the protected branch`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/add-user-access-restrictions',
  `Add user access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/set-user-access-restrictions',
  `Set user access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/remove-user-access-restrictions',
  `Remove user access restrictions`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/protection/restrictions/users`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/rename-branch',
  `Rename a branch`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...requestData } = args
      const url = `/repos/${owner}/${repo}/branches/${branch}/rename`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/create',
  `Create a check run`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/check-runs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/get',
  `Get a check run`,
  {
    owner: z.string(),
    repo: z.string(),
    check_run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, check_run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/check-runs/${check_run_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/update',
  `Update a check run`,
  {
    owner: z.string(),
    repo: z.string(),
    check_run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, check_run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/check-runs/${check_run_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/list-annotations',
  `List check run annotations`,
  {
    owner: z.string(),
    repo: z.string(),
    check_run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, check_run_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/check-runs/${check_run_id}/annotations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/rerequest-run',
  `Rerequest a check run`,
  {
    owner: z.string(),
    repo: z.string(),
    check_run_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, check_run_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/check-runs/${check_run_id}/rerequest`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/create-suite',
  `Create a check suite`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/check-suites`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/set-suites-preferences',
  `Update repository preferences for check suites`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/check-suites/preferences`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/get-suite',
  `Get a check suite`,
  {
    owner: z.string(),
    repo: z.string(),
    check_suite_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, check_suite_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/check-suites/${check_suite_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/list-for-suite',
  `List check runs in a check suite`,
  {
    owner: z.string(),
    repo: z.string(),
    check_suite_id: z.string(),
    filter: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, check_suite_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/check-suites/${check_suite_id}/check-runs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/rerequest-suite',
  `Rerequest a check suite`,
  {
    owner: z.string(),
    repo: z.string(),
    check_suite_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, check_suite_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/check-suites/${check_suite_id}/rerequest`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/list-alerts-for-repo',
  `List code scanning alerts for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    sort: z.string().optional(),
    state: z.string().optional(),
    severity: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/get-alert',
  `Get a code scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/alerts/${alert_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/update-alert',
  `Update a code scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/code-scanning/alerts/${alert_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/get-autofix',
  `Get the status of an autofix for a code scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/alerts/${alert_number}/autofix`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/create-autofix',
  `Create an autofix for a code scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/code-scanning/alerts/${alert_number}/autofix`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/commit-autofix',
  `Commit an autofix for a code scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/code-scanning/alerts/${alert_number}/autofix/commits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/list-alert-instances',
  `List instances of a code scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/alerts/${alert_number}/instances`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/list-recent-analyses',
  `List code scanning analyses for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string().optional(),
    sarif_id: z.string().optional(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/analyses`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/get-analysis',
  `Get a code scanning analysis for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    analysis_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, analysis_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/analyses/${analysis_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/delete-analysis',
  `Delete a code scanning analysis from a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    analysis_id: z.string(),
    confirm_delete: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, analysis_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/analyses/${analysis_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/list-codeql-databases',
  `List CodeQL databases for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/codeql/databases`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/get-codeql-database',
  `Get a CodeQL database for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    language: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, language, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/codeql/databases/${language}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/delete-codeql-database',
  `Delete a CodeQL database`,
  {
    owner: z.string(),
    repo: z.string(),
    language: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, language, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/codeql/databases/${language}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/create-variant-analysis',
  `Create a CodeQL variant analysis`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/code-scanning/codeql/variant-analyses`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/get-variant-analysis',
  `Get the summary of a CodeQL variant analysis`,
  {
    owner: z.string(),
    repo: z.string(),
    codeql_variant_analysis_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, codeql_variant_analysis_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/codeql/variant-analyses/${codeql_variant_analysis_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/get-variant-analysis-repo-task',
  `Get the analysis status of a repository in a CodeQL variant analysis`,
  {
    owner: z.string(),
    repo: z.string(),
    codeql_variant_analysis_id: z.string(),
    repo_owner: z.string(),
    repo_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, codeql_variant_analysis_id, repo_owner, repo_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/codeql/variant-analyses/${codeql_variant_analysis_id}/repos/${repo_owner}/${repo_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/get-default-setup',
  `Get a code scanning default setup configuration`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/default-setup`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/update-default-setup',
  `Update a code scanning default setup configuration`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/code-scanning/default-setup`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/upload-sarif',
  `Upload an analysis as SARIF data`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/code-scanning/sarifs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-scanning/get-sarif',
  `Get information about a SARIF upload`,
  {
    owner: z.string(),
    repo: z.string(),
    sarif_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, sarif_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-scanning/sarifs/${sarif_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'code-security/get-configuration-for-repository',
  `Get the code security configuration associated with a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/code-security-configuration`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/codeowners-errors',
  `List CODEOWNERS errors`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codeowners/errors`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-in-repository-for-authenticated-user',
  `List codespaces in a repository for the authenticated user`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/create-with-repo-for-authenticated-user',
  `Create a codespace in a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/codespaces`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-devcontainers-in-repository-for-authenticated-user',
  `List devcontainer configurations in a repository for the authenticated user`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces/devcontainers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/repo-machines-for-authenticated-user',
  `List available machine types for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    location: z.string().optional(),
    client_ip: z.string().optional(),
    ref: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces/machines`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/pre-flight-with-repo-for-authenticated-user',
  `Get default attributes for a codespace`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string().optional(),
    client_ip: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces/new`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/check-permissions-for-devcontainer',
  `Check if permissions defined by a devcontainer have been accepted by the authenticated user`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
    devcontainer_path: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces/permissions_check`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-repo-secrets',
  `List repository secrets`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces/secrets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-repo-public-key',
  `Get a repository public key`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces/secrets/public-key`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-repo-secret',
  `Get a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/create-or-update-repo-secret',
  `Create or update a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/delete-repo-secret',
  `Delete a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-collaborators',
  `List repository collaborators`,
  {
    owner: z.string(),
    repo: z.string(),
    affiliation: z.string().optional(),
    permission: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/collaborators`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/check-collaborator',
  `Check if a user is a repository collaborator`,
  {
    owner: z.string(),
    repo: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, username, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/collaborators/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/add-collaborator',
  `Add a repository collaborator`,
  {
    owner: z.string(),
    repo: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, username, ...requestData } = args
      const url = `/repos/${owner}/${repo}/collaborators/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/remove-collaborator',
  `Remove a repository collaborator`,
  {
    owner: z.string(),
    repo: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, username, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/collaborators/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-collaborator-permission-level',
  `Get repository permissions for a user`,
  {
    owner: z.string(),
    repo: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, username, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/collaborators/${username}/permission`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-commit-comments-for-repo',
  `List commit comments for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-commit-comment',
  `Get a commit comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-commit-comment',
  `Update a commit comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-commit-comment',
  `Delete a commit comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-commit-comment',
  `List reactions for a commit comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/comments/${comment_id}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-commit-comment',
  `Create reaction for a commit comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/comments/${comment_id}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/delete-for-commit-comment',
  `Delete a commit comment reaction`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
    reaction_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, reaction_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/comments/${comment_id}/reactions/${reaction_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-commits',
  `List commits`,
  {
    owner: z.string(),
    repo: z.string(),
    sha: z.string().optional(),
    path: z.string().optional(),
    author: z.string().optional(),
    committer: z.string().optional(),
    since: z.string().optional(),
    until: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-branches-for-head-commit',
  `List branches for HEAD commit`,
  {
    owner: z.string(),
    repo: z.string(),
    commit_sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, commit_sha, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits/${commit_sha}/branches-where-head`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-comments-for-commit',
  `List commit comments`,
  {
    owner: z.string(),
    repo: z.string(),
    commit_sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, commit_sha, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits/${commit_sha}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-commit-comment',
  `Create a commit comment`,
  {
    owner: z.string(),
    repo: z.string(),
    commit_sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, commit_sha, ...requestData } = args
      const url = `/repos/${owner}/${repo}/commits/${commit_sha}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-pull-requests-associated-with-commit',
  `List pull requests associated with a commit`,
  {
    owner: z.string(),
    repo: z.string(),
    commit_sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, commit_sha, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits/${commit_sha}/pulls`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-commit',
  `Get a commit`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits/${ref}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/list-for-ref',
  `List check runs for a Git reference`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
    filter: z.string().optional(),
    app_id: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits/${ref}/check-runs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'checks/list-suites-for-ref',
  `List check suites for a Git reference`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
    app_id: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits/${ref}/check-suites`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-combined-status-for-ref',
  `Get the combined status for a specific reference`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits/${ref}/status`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-commit-statuses-for-ref',
  `List commit statuses for a reference`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/commits/${ref}/statuses`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-community-profile-metrics',
  `Get community profile metrics`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/community/profile`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/compare-commits',
  `Compare two commits`,
  {
    owner: z.string(),
    repo: z.string(),
    basehead: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, basehead, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/compare/${basehead}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-content',
  `Get repository content`,
  {
    owner: z.string(),
    repo: z.string(),
    path: z.string(),
    ref: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, path, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/contents/${path}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-or-update-file-contents',
  `Create or update file contents`,
  {
    owner: z.string(),
    repo: z.string(),
    path: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, path, ...requestData } = args
      const url = `/repos/${owner}/${repo}/contents/${path}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-file',
  `Delete a file`,
  {
    owner: z.string(),
    repo: z.string(),
    path: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, path, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/contents/${path}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-contributors',
  `List repository contributors`,
  {
    owner: z.string(),
    repo: z.string(),
    anon: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/contributors`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/list-alerts-for-repo',
  `List Dependabot alerts for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    page: z.string().optional(),
    per_page: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/dependabot/alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/get-alert',
  `Get a Dependabot alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/dependabot/alerts/${alert_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/update-alert',
  `Update a Dependabot alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/dependabot/alerts/${alert_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/list-repo-secrets',
  `List repository secrets`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/dependabot/secrets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/get-repo-public-key',
  `Get a repository public key`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/dependabot/secrets/public-key`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/get-repo-secret',
  `Get a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/dependabot/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/create-or-update-repo-secret',
  `Create or update a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/dependabot/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependabot/delete-repo-secret',
  `Delete a repository secret`,
  {
    owner: z.string(),
    repo: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, secret_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/dependabot/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependency-graph/diff-range',
  `Get a diff of the dependencies between commits`,
  {
    owner: z.string(),
    repo: z.string(),
    basehead: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, basehead, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/dependency-graph/compare/${basehead}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependency-graph/export-sbom',
  `Export a software bill of materials (SBOM) for a repository.`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/dependency-graph/sbom`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'dependency-graph/create-repository-snapshot',
  `Create a snapshot of dependencies for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/dependency-graph/snapshots`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-deployments',
  `List deployments`,
  {
    owner: z.string(),
    repo: z.string(),
    sha: z.string().optional(),
    ref: z.string().optional(),
    task: z.string().optional(),
    environment: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/deployments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-deployment',
  `Create a deployment`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/deployments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-deployment',
  `Get a deployment`,
  {
    owner: z.string(),
    repo: z.string(),
    deployment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, deployment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/deployments/${deployment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-deployment',
  `Delete a deployment`,
  {
    owner: z.string(),
    repo: z.string(),
    deployment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, deployment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/deployments/${deployment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-deployment-statuses',
  `List deployment statuses`,
  {
    owner: z.string(),
    repo: z.string(),
    deployment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, deployment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/deployments/${deployment_id}/statuses`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-deployment-status',
  `Create a deployment status`,
  {
    owner: z.string(),
    repo: z.string(),
    deployment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, deployment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/deployments/${deployment_id}/statuses`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-deployment-status',
  `Get a deployment status`,
  {
    owner: z.string(),
    repo: z.string(),
    deployment_id: z.string(),
    status_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, deployment_id, status_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/deployments/${deployment_id}/statuses/${status_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-dispatch-event',
  `Create a repository dispatch event`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/dispatches`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-all-environments',
  `List environments`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-environment',
  `Get an environment`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-or-update-environment',
  `Create or update an environment`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-an-environment',
  `Delete an environment`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-deployment-branch-policies',
  `List deployment branch policies`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment-branch-policies`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-deployment-branch-policy',
  `Create a deployment branch policy`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment-branch-policies`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-deployment-branch-policy',
  `Get a deployment branch policy`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    branch_policy_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, branch_policy_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment-branch-policies/${branch_policy_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-deployment-branch-policy',
  `Update a deployment branch policy`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    branch_policy_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, branch_policy_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment-branch-policies/${branch_policy_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-deployment-branch-policy',
  `Delete a deployment branch policy`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    branch_policy_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, branch_policy_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment-branch-policies/${branch_policy_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-all-deployment-protection-rules',
  `Get all deployment protection rules for an environment`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment_protection_rules`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-deployment-protection-rule',
  `Create a custom deployment protection rule on an environment`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment_protection_rules`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-custom-deployment-rule-integrations',
  `List custom deployment rule integrations available for an environment`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment_protection_rules/apps`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-custom-deployment-protection-rule',
  `Get a custom deployment protection rule`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    protection_rule_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, protection_rule_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment_protection_rules/${protection_rule_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/disable-deployment-protection-rule',
  `Disable a custom protection rule for an environment`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    protection_rule_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, protection_rule_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/deployment_protection_rules/${protection_rule_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-environment-secrets',
  `List environment secrets`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/secrets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-environment-public-key',
  `Get an environment public key`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/secrets/public-key`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-environment-secret',
  `Get an environment secret`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, secret_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-or-update-environment-secret',
  `Create or update an environment secret`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, secret_name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-environment-secret',
  `Delete an environment secret`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, secret_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/list-environment-variables',
  `List environment variables`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/variables`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/create-environment-variable',
  `Create an environment variable`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/variables`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/get-environment-variable',
  `Get an environment variable`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/update-environment-variable',
  `Update an environment variable`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'actions/delete-environment-variable',
  `Delete an environment variable`,
  {
    owner: z.string(),
    repo: z.string(),
    environment_name: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, environment_name, name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/environments/${environment_name}/variables/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-repo-events',
  `List repository events`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/events`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-forks',
  `List forks`,
  {
    owner: z.string(),
    repo: z.string(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/forks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-fork',
  `Create a fork`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/forks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/create-blob',
  `Create a blob`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/git/blobs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/get-blob',
  `Get a blob`,
  {
    owner: z.string(),
    repo: z.string(),
    file_sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, file_sha, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/git/blobs/${file_sha}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/create-commit',
  `Create a commit`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/git/commits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/get-commit',
  `Get a commit object`,
  {
    owner: z.string(),
    repo: z.string(),
    commit_sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, commit_sha, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/git/commits/${commit_sha}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/list-matching-refs',
  `List matching references`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/git/matching-refs/${ref}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/get-ref',
  `Get a reference`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/git/ref/${ref}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/create-ref',
  `Create a reference`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/git/refs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/update-ref',
  `Update a reference`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...requestData } = args
      const url = `/repos/${owner}/${repo}/git/refs/${ref}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/delete-ref',
  `Delete a reference`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/git/refs/${ref}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/create-tag',
  `Create a tag object`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/git/tags`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/get-tag',
  `Get a tag`,
  {
    owner: z.string(),
    repo: z.string(),
    tag_sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, tag_sha, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/git/tags/${tag_sha}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/create-tree',
  `Create a tree`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/git/trees`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'git/get-tree',
  `Get a tree`,
  {
    owner: z.string(),
    repo: z.string(),
    tree_sha: z.string(),
    recursive: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, tree_sha, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/git/trees/${tree_sha}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-webhooks',
  `List repository webhooks`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/hooks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-webhook',
  `Create a repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/hooks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-webhook',
  `Get a repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-webhook',
  `Update a repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-webhook',
  `Delete a repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-webhook-config-for-repo',
  `Get a webhook configuration for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}/config`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-webhook-config-for-repo',
  `Update a webhook configuration for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}/config`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-webhook-deliveries',
  `List deliveries for a repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}/deliveries`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-webhook-delivery',
  `Get a delivery for a repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
    delivery_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, delivery_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}/deliveries/${delivery_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/redeliver-webhook-delivery',
  `Redeliver a delivery for a repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
    delivery_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, delivery_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}/deliveries/${delivery_id}/attempts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/ping-webhook',
  `Ping a repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}/pings`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/test-push-webhook',
  `Test the push repository webhook`,
  {
    owner: z.string(),
    repo: z.string(),
    hook_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, hook_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/hooks/${hook_id}/tests`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/get-import-status',
  `Get an import status`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/import`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/start-import',
  `Start an import`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/import`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/update-import',
  `Update an import`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/import`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/cancel-import',
  `Cancel an import`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/import`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/get-commit-authors',
  `Get commit authors`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/import/authors`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/map-commit-author',
  `Map a commit author`,
  {
    owner: z.string(),
    repo: z.string(),
    author_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, author_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/import/authors/${author_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/get-large-files',
  `Get large files`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/import/large_files`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/set-lfs-preference',
  `Update Git LFS preference`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/import/lfs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/get-repo-installation',
  `Get a repository installation for the authenticated app`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/installation`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/get-restrictions-for-repo',
  `Get interaction restrictions for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/interaction-limits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/set-restrictions-for-repo',
  `Set interaction restrictions for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/interaction-limits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/remove-restrictions-for-repo',
  `Remove interaction restrictions for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/interaction-limits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-invitations',
  `List repository invitations`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/invitations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-invitation',
  `Update a repository invitation`,
  {
    owner: z.string(),
    repo: z.string(),
    invitation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, invitation_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/invitations/${invitation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-invitation',
  `Delete a repository invitation`,
  {
    owner: z.string(),
    repo: z.string(),
    invitation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, invitation_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/invitations/${invitation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-for-repo',
  `List repository issues`,
  {
    owner: z.string(),
    repo: z.string(),
    milestone: z.string().optional(),
    state: z.string().optional(),
    assignee: z.string().optional(),
    type: z.string().optional(),
    creator: z.string().optional(),
    mentioned: z.string().optional(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/create',
  `Create an issue`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-comments-for-repo',
  `List issue comments for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/get-comment',
  `Get an issue comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/update-comment',
  `Update an issue comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/delete-comment',
  `Delete an issue comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-issue-comment',
  `List reactions for an issue comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/comments/${comment_id}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-issue-comment',
  `Create reaction for an issue comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/comments/${comment_id}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/delete-for-issue-comment',
  `Delete an issue comment reaction`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
    reaction_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, reaction_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/comments/${comment_id}/reactions/${reaction_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-events-for-repo',
  `List issue events for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/events`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/get-event',
  `Get an issue event`,
  {
    owner: z.string(),
    repo: z.string(),
    event_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, event_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/events/${event_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/get',
  `Get an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/update',
  `Update an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/add-assignees',
  `Add assignees to an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/assignees`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/remove-assignees',
  `Remove assignees from an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/assignees`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/check-user-can-be-assigned-to-issue',
  `Check if a user can be assigned to a issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
    assignee: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, assignee, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/assignees/${assignee}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-comments',
  `List issue comments`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/create-comment',
  `Create an issue comment`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-events',
  `List issue events`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/events`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-labels-on-issue',
  `List labels for an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/add-labels',
  `Add labels to an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/set-labels',
  `Set labels for an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/remove-all-labels',
  `Remove all labels from an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/remove-label',
  `Remove a label from an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/labels/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/lock',
  `Lock an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/lock`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/unlock',
  `Unlock an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/lock`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-issue',
  `List reactions for an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-issue',
  `Create reaction for an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/delete-for-issue',
  `Delete an issue reaction`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
    reaction_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, reaction_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/reactions/${reaction_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/remove-sub-issue',
  `Remove sub-issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/sub_issue`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-sub-issues',
  `List sub-issues`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/sub_issues`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/add-sub-issue',
  `Add sub-issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/sub_issues`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/reprioritize-sub-issue',
  `Reprioritize sub-issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/sub_issues/priority`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-events-for-timeline',
  `List timeline events for an issue`,
  {
    owner: z.string(),
    repo: z.string(),
    issue_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, issue_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/issues/${issue_number}/timeline`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-deploy-keys',
  `List deploy keys`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/keys`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-deploy-key',
  `Create a deploy key`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/keys`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-deploy-key',
  `Get a deploy key`,
  {
    owner: z.string(),
    repo: z.string(),
    key_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, key_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/keys/${key_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-deploy-key',
  `Delete a deploy key`,
  {
    owner: z.string(),
    repo: z.string(),
    key_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, key_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/keys/${key_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-labels-for-repo',
  `List labels for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/create-label',
  `Create a label`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/get-label',
  `Get a label`,
  {
    owner: z.string(),
    repo: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/labels/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/update-label',
  `Update a label`,
  {
    owner: z.string(),
    repo: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, name, ...requestData } = args
      const url = `/repos/${owner}/${repo}/labels/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/delete-label',
  `Delete a label`,
  {
    owner: z.string(),
    repo: z.string(),
    name: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, name, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/labels/${name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-languages',
  `List repository languages`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/languages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'licenses/get-for-repo',
  `Get the license for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/license`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/merge-upstream',
  `Sync a fork branch with the upstream repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/merge-upstream`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/merge',
  `Merge a branch`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/merges`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-milestones',
  `List milestones`,
  {
    owner: z.string(),
    repo: z.string(),
    state: z.string().optional(),
    sort: z.string().optional(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/milestones`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/create-milestone',
  `Create a milestone`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/milestones`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/get-milestone',
  `Get a milestone`,
  {
    owner: z.string(),
    repo: z.string(),
    milestone_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, milestone_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/milestones/${milestone_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/update-milestone',
  `Update a milestone`,
  {
    owner: z.string(),
    repo: z.string(),
    milestone_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, milestone_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/milestones/${milestone_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/delete-milestone',
  `Delete a milestone`,
  {
    owner: z.string(),
    repo: z.string(),
    milestone_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, milestone_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/milestones/${milestone_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-labels-for-milestone',
  `List labels for issues in a milestone`,
  {
    owner: z.string(),
    repo: z.string(),
    milestone_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, milestone_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/milestones/${milestone_number}/labels`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-repo-notifications-for-authenticated-user',
  `List repository notifications for the authenticated user`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/notifications`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/mark-repo-notifications-as-read',
  `Mark repository notifications as read`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/notifications`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-pages',
  `Get a GitHub Pages site`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-pages-site',
  `Create a GitHub Pages site`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-information-about-pages-site',
  `Update information about a GitHub Pages site`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-pages-site',
  `Delete a GitHub Pages site`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-pages-builds',
  `List GitHub Pages builds`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pages/builds`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/request-pages-build',
  `Request a GitHub Pages build`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pages/builds`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-latest-pages-build',
  `Get latest Pages build`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pages/builds/latest`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-pages-build',
  `Get GitHub Pages build`,
  {
    owner: z.string(),
    repo: z.string(),
    build_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, build_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pages/builds/${build_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-pages-deployment',
  `Create a GitHub Pages deployment`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pages/deployments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-pages-deployment',
  `Get the status of a GitHub Pages deployment`,
  {
    owner: z.string(),
    repo: z.string(),
    pages_deployment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pages_deployment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pages/deployments/${pages_deployment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/cancel-pages-deployment',
  `Cancel a GitHub Pages deployment`,
  {
    owner: z.string(),
    repo: z.string(),
    pages_deployment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pages_deployment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pages/deployments/${pages_deployment_id}/cancel`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-pages-health-check',
  `Get a DNS health check for GitHub Pages`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pages/health`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/check-private-vulnerability-reporting',
  `Check if private vulnerability reporting is enabled for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/private-vulnerability-reporting`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/enable-private-vulnerability-reporting',
  `Enable private vulnerability reporting for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/private-vulnerability-reporting`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/disable-private-vulnerability-reporting',
  `Disable private vulnerability reporting for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/private-vulnerability-reporting`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/list-for-repo',
  `List repository projects`,
  {
    owner: z.string(),
    repo: z.string(),
    state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/projects`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/create-for-repo',
  `Create a repository project`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/projects`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-custom-properties-values',
  `Get all custom property values for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/properties/values`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-or-update-custom-properties-values',
  `Create or update custom property values for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/properties/values`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/list',
  `List pull requests`,
  {
    owner: z.string(),
    repo: z.string(),
    state: z.string().optional(),
    head: z.string().optional(),
    base: z.string().optional(),
    sort: z.string().optional(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/create',
  `Create a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/list-review-comments-for-repo',
  `List review comments in a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    sort: z.string().optional(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/get-review-comment',
  `Get a review comment for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/update-review-comment',
  `Update a review comment for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/delete-review-comment',
  `Delete a review comment for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/comments/${comment_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-pull-request-review-comment',
  `List reactions for a pull request review comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/comments/${comment_id}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-pull-request-review-comment',
  `Create reaction for a pull request review comment`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/comments/${comment_id}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/delete-for-pull-request-comment',
  `Delete a pull request comment reaction`,
  {
    owner: z.string(),
    repo: z.string(),
    comment_id: z.string(),
    reaction_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, comment_id, reaction_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/comments/${comment_id}/reactions/${reaction_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/get',
  `Get a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/update',
  `Update a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/create-with-pr-for-authenticated-user',
  `Create a codespace from a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/codespaces`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/list-review-comments',
  `List review comments on a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/create-review-comment',
  `Create a review comment for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/create-reply-for-review-comment',
  `Create a reply for a review comment`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
    comment_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, comment_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/comments/${comment_id}/replies`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/list-commits',
  `List commits on a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/commits`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/list-files',
  `List pull requests files`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/files`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/check-if-merged',
  `Check if a pull request has been merged`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/merge`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/merge',
  `Merge a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/merge`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/list-requested-reviewers',
  `Get all requested reviewers for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/requested_reviewers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/request-reviewers',
  `Request reviewers for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/requested_reviewers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/remove-requested-reviewers',
  `Remove requested reviewers from a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/requested_reviewers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/list-reviews',
  `List reviews for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/reviews`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/create-review',
  `Create a review for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/reviews`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/get-review',
  `Get a review for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
    review_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, review_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/reviews/${review_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/update-review',
  `Update a review for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
    review_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, review_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/reviews/${review_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/delete-pending-review',
  `Delete a pending review for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
    review_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, review_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/reviews/${review_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/list-comments-for-review',
  `List comments for a pull request review`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
    review_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, review_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/reviews/${review_id}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/dismiss-review',
  `Dismiss a review for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
    review_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, review_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/reviews/${review_id}/dismissals`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/submit-review',
  `Submit a review for a pull request`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
    review_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, review_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/reviews/${review_id}/events`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'pulls/update-branch',
  `Update a pull request branch`,
  {
    owner: z.string(),
    repo: z.string(),
    pull_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, pull_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/pulls/${pull_number}/update-branch`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-readme',
  `Get a repository README`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/readme`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-readme-in-directory',
  `Get a repository README for a directory`,
  {
    owner: z.string(),
    repo: z.string(),
    dir: z.string(),
    ref: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, dir, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/readme/${dir}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-releases',
  `List releases`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-release',
  `Create a release`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/releases`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-release-asset',
  `Get a release asset`,
  {
    owner: z.string(),
    repo: z.string(),
    asset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, asset_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/assets/${asset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-release-asset',
  `Update a release asset`,
  {
    owner: z.string(),
    repo: z.string(),
    asset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, asset_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/releases/assets/${asset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-release-asset',
  `Delete a release asset`,
  {
    owner: z.string(),
    repo: z.string(),
    asset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, asset_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/assets/${asset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/generate-release-notes',
  `Generate release notes content for a release`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/releases/generate-notes`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-latest-release',
  `Get the latest release`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/latest`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-release-by-tag',
  `Get a release by tag name`,
  {
    owner: z.string(),
    repo: z.string(),
    tag: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, tag, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/tags/${tag}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-release',
  `Get a release`,
  {
    owner: z.string(),
    repo: z.string(),
    release_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, release_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/${release_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-release',
  `Update a release`,
  {
    owner: z.string(),
    repo: z.string(),
    release_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, release_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/releases/${release_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-release',
  `Delete a release`,
  {
    owner: z.string(),
    repo: z.string(),
    release_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, release_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/${release_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-release-assets',
  `List release assets`,
  {
    owner: z.string(),
    repo: z.string(),
    release_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, release_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/${release_id}/assets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/upload-release-asset',
  `Upload a release asset`,
  {
    owner: z.string(),
    repo: z.string(),
    release_id: z.string(),
    name: z.string(),
    label: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, release_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/releases/${release_id}/assets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-release',
  `List reactions for a release`,
  {
    owner: z.string(),
    repo: z.string(),
    release_id: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, release_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/${release_id}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-release',
  `Create reaction for a release`,
  {
    owner: z.string(),
    repo: z.string(),
    release_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, release_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/releases/${release_id}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/delete-for-release',
  `Delete a release reaction`,
  {
    owner: z.string(),
    repo: z.string(),
    release_id: z.string(),
    reaction_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, release_id, reaction_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/releases/${release_id}/reactions/${reaction_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-branch-rules',
  `Get rules for a branch`,
  {
    owner: z.string(),
    repo: z.string(),
    branch: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, branch, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/rules/branches/${branch}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-repo-rulesets',
  `Get all repository rulesets`,
  {
    owner: z.string(),
    repo: z.string(),
    includes_parents: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/rulesets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-repo-ruleset',
  `Create a repository ruleset`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/rulesets`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-repo-rule-suites',
  `List repository rule suites`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/rulesets/rule-suites`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-repo-rule-suite',
  `Get a repository rule suite`,
  {
    owner: z.string(),
    repo: z.string(),
    rule_suite_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, rule_suite_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/rulesets/rule-suites/${rule_suite_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-repo-ruleset',
  `Get a repository ruleset`,
  {
    owner: z.string(),
    repo: z.string(),
    ruleset_id: z.string(),
    includes_parents: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ruleset_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/rulesets/${ruleset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/update-repo-ruleset',
  `Update a repository ruleset`,
  {
    owner: z.string(),
    repo: z.string(),
    ruleset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ruleset_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/rulesets/${ruleset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-repo-ruleset',
  `Delete a repository ruleset`,
  {
    owner: z.string(),
    repo: z.string(),
    ruleset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ruleset_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/rulesets/${ruleset_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-repo-ruleset-history',
  `Get repository ruleset history`,
  {
    owner: z.string(),
    repo: z.string(),
    ruleset_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ruleset_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/rulesets/${ruleset_id}/history`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-repo-ruleset-version',
  `Get repository ruleset version`,
  {
    owner: z.string(),
    repo: z.string(),
    ruleset_id: z.string(),
    version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ruleset_id, version_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/rulesets/${ruleset_id}/history/${version_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'secret-scanning/list-alerts-for-repo',
  `List secret scanning alerts for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/secret-scanning/alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'secret-scanning/get-alert',
  `Get a secret scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/secret-scanning/alerts/${alert_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'secret-scanning/update-alert',
  `Update a secret scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...requestData } = args
      const url = `/repos/${owner}/${repo}/secret-scanning/alerts/${alert_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'secret-scanning/list-locations-for-alert',
  `List locations for a secret scanning alert`,
  {
    owner: z.string(),
    repo: z.string(),
    alert_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, alert_number, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/secret-scanning/alerts/${alert_number}/locations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'secret-scanning/create-push-protection-bypass',
  `Create a push protection bypass`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/secret-scanning/push-protection-bypasses`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'secret-scanning/get-scan-history',
  `Get secret scanning scan history for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/secret-scanning/scan-history`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/list-repository-advisories',
  `List repository security advisories`,
  {
    owner: z.string(),
    repo: z.string(),
    sort: z.string().optional(),
    per_page: z.string().optional(),
    state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/security-advisories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/create-repository-advisory',
  `Create a repository security advisory`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/security-advisories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/create-private-vulnerability-report',
  `Privately report a security vulnerability`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/security-advisories/reports`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/get-repository-advisory',
  `Get a repository security advisory`,
  {
    owner: z.string(),
    repo: z.string(),
    ghsa_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ghsa_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/security-advisories/${ghsa_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/update-repository-advisory',
  `Update a repository security advisory`,
  {
    owner: z.string(),
    repo: z.string(),
    ghsa_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ghsa_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/security-advisories/${ghsa_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/create-repository-advisory-cve-request',
  `Request a CVE for a repository security advisory`,
  {
    owner: z.string(),
    repo: z.string(),
    ghsa_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ghsa_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/security-advisories/${ghsa_id}/cve`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'security-advisories/create-fork',
  `Create a temporary private fork`,
  {
    owner: z.string(),
    repo: z.string(),
    ghsa_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ghsa_id, ...requestData } = args
      const url = `/repos/${owner}/${repo}/security-advisories/${ghsa_id}/forks`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-stargazers-for-repo',
  `List stargazers`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/stargazers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-code-frequency-stats',
  `Get the weekly commit activity`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/stats/code_frequency`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-commit-activity-stats',
  `Get the last year of commit activity`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/stats/commit_activity`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-contributors-stats',
  `Get all contributor commit activity`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/stats/contributors`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-participation-stats',
  `Get the weekly commit count`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/stats/participation`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-punch-card-stats',
  `Get the hourly commit count for each day`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/stats/punch_card`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-commit-status',
  `Create a commit status`,
  {
    owner: z.string(),
    repo: z.string(),
    sha: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, sha, ...requestData } = args
      const url = `/repos/${owner}/${repo}/statuses/${sha}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-watchers-for-repo',
  `List watchers`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/subscribers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/get-repo-subscription',
  `Get a repository subscription`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/subscription`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/set-repo-subscription',
  `Set a repository subscription`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/subscription`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/delete-repo-subscription',
  `Delete a repository subscription`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/subscription`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-tags',
  `List repository tags`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/tags`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-tag-protection',
  `Closing down - List tag protection states for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/tags/protection`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-tag-protection',
  `Closing down - Create a tag protection state for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/tags/protection`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/delete-tag-protection',
  `Closing down - Delete a tag protection state for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
    tag_protection_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, tag_protection_id, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/tags/protection/${tag_protection_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/download-tarball-archive',
  `Download a repository archive (tar)`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/tarball/${ref}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-teams',
  `List repository teams`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-all-topics',
  `Get all repository topics`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/topics`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/replace-all-topics',
  `Replace all repository topics`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/topics`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-clones',
  `Get repository clones`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/traffic/clones`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-top-paths',
  `Get top referral paths`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/traffic/popular/paths`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-top-referrers',
  `Get top referral sources`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/traffic/popular/referrers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/get-views',
  `Get page views`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/traffic/views`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/transfer',
  `Transfer a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/transfer`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/check-vulnerability-alerts',
  `Check if vulnerability alerts are enabled for a repository`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/vulnerability-alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/enable-vulnerability-alerts',
  `Enable vulnerability alerts`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/repos/${owner}/${repo}/vulnerability-alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/disable-vulnerability-alerts',
  `Disable vulnerability alerts`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/vulnerability-alerts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/download-zipball-archive',
  `Download a repository archive (zip)`,
  {
    owner: z.string(),
    repo: z.string(),
    ref: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ref, ...queryParams } = args
      const url = `/repos/${owner}/${repo}/zipball/${ref}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-using-template',
  `Create a repository using a template`,
  {
    template_owner: z.string(),
    template_repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { template_owner, template_repo, ...requestData } = args
      const url = `/repos/${template_owner}/${template_repo}/generate`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('repos/list-public', `List public repositories`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/repositories',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'search/code',
  `Search code`,
  {
    q: z.string(),
    sort: z.string().optional(),
    order: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/search/code',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'search/commits',
  `Search commits`,
  {
    q: z.string(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/search/commits',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'search/issues-and-pull-requests',
  `Search issues and pull requests`,
  {
    q: z.string(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/search/issues',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'search/labels',
  `Search labels`,
  {
    repository_id: z.string(),
    q: z.string(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/search/labels',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'search/repos',
  `Search repositories`,
  {
    q: z.string(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/search/repositories',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'search/topics',
  `Search topics`,
  {
    q: z.string(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/search/topics',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'search/users',
  `Search users`,
  {
    q: z.string(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/search/users',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-legacy',
  `Get a team (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...queryParams } = args
      const url = `/teams/${team_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/update-legacy',
  `Update a team (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...requestData } = args
      const url = `/teams/${team_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/delete-legacy',
  `Delete a team (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...queryParams } = args
      const url = `/teams/${team_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-discussions-legacy',
  `List discussions (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...queryParams } = args
      const url = `/teams/${team_id}/discussions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/create-discussion-legacy',
  `Create a discussion (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...requestData } = args
      const url = `/teams/${team_id}/discussions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-discussion-legacy',
  `Get a discussion (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, ...queryParams } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/update-discussion-legacy',
  `Update a discussion (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, ...requestData } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/delete-discussion-legacy',
  `Delete a discussion (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, ...queryParams } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-discussion-comments-legacy',
  `List discussion comments (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, ...queryParams } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/create-discussion-comment-legacy',
  `Create a discussion comment (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, ...requestData } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/comments`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-discussion-comment-legacy',
  `Get a discussion comment (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, comment_number, ...queryParams } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/comments/${comment_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/update-discussion-comment-legacy',
  `Update a discussion comment (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, comment_number, ...requestData } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/comments/${comment_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/delete-discussion-comment-legacy',
  `Delete a discussion comment (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, comment_number, ...queryParams } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/comments/${comment_number}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-team-discussion-comment-legacy',
  `List reactions for a team discussion comment (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, comment_number, ...queryParams } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/comments/${comment_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-team-discussion-comment-legacy',
  `Create reaction for a team discussion comment (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
    comment_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, comment_number, ...requestData } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/comments/${comment_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/list-for-team-discussion-legacy',
  `List reactions for a team discussion (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
    content: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, ...queryParams } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'reactions/create-for-team-discussion-legacy',
  `Create reaction for a team discussion (Legacy)`,
  {
    team_id: z.string(),
    discussion_number: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, discussion_number, ...requestData } = args
      const url = `/teams/${team_id}/discussions/${discussion_number}/reactions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-pending-invitations-legacy',
  `List pending team invitations (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...queryParams } = args
      const url = `/teams/${team_id}/invitations`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-members-legacy',
  `List team members (Legacy)`,
  {
    team_id: z.string(),
    role: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...queryParams } = args
      const url = `/teams/${team_id}/members`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-member-legacy',
  `Get team member (Legacy)`,
  {
    team_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, username, ...queryParams } = args
      const url = `/teams/${team_id}/members/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/add-member-legacy',
  `Add team member (Legacy)`,
  {
    team_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, username, ...requestData } = args
      const url = `/teams/${team_id}/members/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/remove-member-legacy',
  `Remove team member (Legacy)`,
  {
    team_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, username, ...queryParams } = args
      const url = `/teams/${team_id}/members/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/get-membership-for-user-legacy',
  `Get team membership for a user (Legacy)`,
  {
    team_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, username, ...queryParams } = args
      const url = `/teams/${team_id}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/add-or-update-membership-for-user-legacy',
  `Add or update team membership for a user (Legacy)`,
  {
    team_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, username, ...requestData } = args
      const url = `/teams/${team_id}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/remove-membership-for-user-legacy',
  `Remove team membership for a user (Legacy)`,
  {
    team_id: z.string(),
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, username, ...queryParams } = args
      const url = `/teams/${team_id}/memberships/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-projects-legacy',
  `List team projects (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...queryParams } = args
      const url = `/teams/${team_id}/projects`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/check-permissions-for-project-legacy',
  `Check team permissions for a project (Legacy)`,
  {
    team_id: z.string(),
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, project_id, ...queryParams } = args
      const url = `/teams/${team_id}/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/add-or-update-project-permissions-legacy',
  `Add or update team project permissions (Legacy)`,
  {
    team_id: z.string(),
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, project_id, ...requestData } = args
      const url = `/teams/${team_id}/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/remove-project-legacy',
  `Remove a project from a team (Legacy)`,
  {
    team_id: z.string(),
    project_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, project_id, ...queryParams } = args
      const url = `/teams/${team_id}/projects/${project_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-repos-legacy',
  `List team repositories (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...queryParams } = args
      const url = `/teams/${team_id}/repos`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/check-permissions-for-repo-legacy',
  `Check team permissions for a repository (Legacy)`,
  {
    team_id: z.string(),
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, owner, repo, ...queryParams } = args
      const url = `/teams/${team_id}/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/add-or-update-repo-permissions-legacy',
  `Add or update team repository permissions (Legacy)`,
  {
    team_id: z.string(),
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, owner, repo, ...requestData } = args
      const url = `/teams/${team_id}/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/remove-repo-legacy',
  `Remove a repository from a team (Legacy)`,
  {
    team_id: z.string(),
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, owner, repo, ...queryParams } = args
      const url = `/teams/${team_id}/repos/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-child-legacy',
  `List child teams (Legacy)`,
  {
    team_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { team_id, ...queryParams } = args
      const url = `/teams/${team_id}/teams`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('users/get-authenticated', `Get the authenticated user`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/user',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('users/update-authenticated', `Update the authenticated user`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'PATCH',
      url: '/user',
      data: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'users/list-blocked-by-authenticated-user',
  `List users blocked by the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/blocks',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/check-blocked',
  `Check if a user is blocked by the authenticated user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/user/blocks/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/block',
  `Block a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...requestData } = args
      const url = `/user/blocks/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/unblock',
  `Unblock a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/user/blocks/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-for-authenticated-user',
  `List codespaces for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/codespaces',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/create-for-authenticated-user',
  `Create a codespace for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: '/user/codespaces',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-secrets-for-authenticated-user',
  `List secrets for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/codespaces/secrets',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-public-key-for-authenticated-user',
  `Get public key for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/codespaces/secrets/public-key',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-secret-for-authenticated-user',
  `Get a secret for the authenticated user`,
  {
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { secret_name, ...queryParams } = args
      const url = `/user/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/create-or-update-secret-for-authenticated-user',
  `Create or update a secret for the authenticated user`,
  {
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { secret_name, ...requestData } = args
      const url = `/user/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/delete-secret-for-authenticated-user',
  `Delete a secret for the authenticated user`,
  {
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { secret_name, ...queryParams } = args
      const url = `/user/codespaces/secrets/${secret_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/list-repositories-for-secret-for-authenticated-user',
  `List selected repositories for a user secret`,
  {
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { secret_name, ...queryParams } = args
      const url = `/user/codespaces/secrets/${secret_name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/set-repositories-for-secret-for-authenticated-user',
  `Set selected repositories for a user secret`,
  {
    secret_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { secret_name, ...requestData } = args
      const url = `/user/codespaces/secrets/${secret_name}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/add-repository-for-secret-for-authenticated-user',
  `Add a selected repository to a user secret`,
  {
    secret_name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { secret_name, repository_id, ...requestData } = args
      const url = `/user/codespaces/secrets/${secret_name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/remove-repository-for-secret-for-authenticated-user',
  `Remove a selected repository from a user secret`,
  {
    secret_name: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { secret_name, repository_id, ...queryParams } = args
      const url = `/user/codespaces/secrets/${secret_name}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-for-authenticated-user',
  `Get a codespace for the authenticated user`,
  {
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, ...queryParams } = args
      const url = `/user/codespaces/${codespace_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/update-for-authenticated-user',
  `Update a codespace for the authenticated user`,
  {
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, ...requestData } = args
      const url = `/user/codespaces/${codespace_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/delete-for-authenticated-user',
  `Delete a codespace for the authenticated user`,
  {
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, ...queryParams } = args
      const url = `/user/codespaces/${codespace_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/export-for-authenticated-user',
  `Export a codespace for the authenticated user`,
  {
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, ...requestData } = args
      const url = `/user/codespaces/${codespace_name}/exports`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/get-export-details-for-authenticated-user',
  `Get details about a codespace export`,
  {
    codespace_name: z.string(),
    export_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, export_id, ...queryParams } = args
      const url = `/user/codespaces/${codespace_name}/exports/${export_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/codespace-machines-for-authenticated-user',
  `List machine types for a codespace`,
  {
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, ...queryParams } = args
      const url = `/user/codespaces/${codespace_name}/machines`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/publish-for-authenticated-user',
  `Create a repository from an unpublished codespace`,
  {
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, ...requestData } = args
      const url = `/user/codespaces/${codespace_name}/publish`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/start-for-authenticated-user',
  `Start a codespace for the authenticated user`,
  {
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, ...requestData } = args
      const url = `/user/codespaces/${codespace_name}/start`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'codespaces/stop-for-authenticated-user',
  `Stop a codespace for the authenticated user`,
  {
    codespace_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { codespace_name, ...requestData } = args
      const url = `/user/codespaces/${codespace_name}/stop`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/list-docker-migration-conflicting-packages-for-authenticated-user',
  `Get list of conflicting packages during Docker migration for authenticated-user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/docker/conflicts',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/set-primary-email-visibility-for-authenticated-user',
  `Set primary email visibility for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: '/user/email/visibility',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-emails-for-authenticated-user',
  `List email addresses for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/emails',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/add-email-for-authenticated-user',
  `Add an email address for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: '/user/emails',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/delete-email-for-authenticated-user',
  `Delete an email address for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: '/user/emails',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-followers-for-authenticated-user',
  `List followers of the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/followers',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-followed-by-authenticated-user',
  `List the people the authenticated user follows`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/following',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/check-person-is-followed-by-authenticated',
  `Check if a person is followed by the authenticated user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/user/following/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/follow',
  `Follow a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...requestData } = args
      const url = `/user/following/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/unfollow',
  `Unfollow a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/user/following/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-gpg-keys-for-authenticated-user',
  `List GPG keys for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/gpg_keys',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/create-gpg-key-for-authenticated-user',
  `Create a GPG key for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: '/user/gpg_keys',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/get-gpg-key-for-authenticated-user',
  `Get a GPG key for the authenticated user`,
  {
    gpg_key_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gpg_key_id, ...queryParams } = args
      const url = `/user/gpg_keys/${gpg_key_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/delete-gpg-key-for-authenticated-user',
  `Delete a GPG key for the authenticated user`,
  {
    gpg_key_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { gpg_key_id, ...queryParams } = args
      const url = `/user/gpg_keys/${gpg_key_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/list-installations-for-authenticated-user',
  `List app installations accessible to the user access token`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/installations',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/list-installation-repos-for-authenticated-user',
  `List repositories accessible to the user access token`,
  {
    installation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { installation_id, ...queryParams } = args
      const url = `/user/installations/${installation_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/add-repo-to-installation-for-authenticated-user',
  `Add a repository to an app installation`,
  {
    installation_id: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { installation_id, repository_id, ...requestData } = args
      const url = `/user/installations/${installation_id}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/remove-repo-from-installation-for-authenticated-user',
  `Remove a repository from an app installation`,
  {
    installation_id: z.string(),
    repository_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { installation_id, repository_id, ...queryParams } = args
      const url = `/user/installations/${installation_id}/repositories/${repository_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/get-restrictions-for-authenticated-user',
  `Get interaction restrictions for your public repositories`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/interaction-limits',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/set-restrictions-for-authenticated-user',
  `Set interaction restrictions for your public repositories`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: '/user/interaction-limits',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'interactions/remove-restrictions-for-authenticated-user',
  `Remove interaction restrictions from your public repositories`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: '/user/interaction-limits',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'issues/list-for-authenticated-user',
  `List user account issues assigned to the authenticated user`,
  {
    filter: z.string().optional(),
    state: z.string().optional(),
    sort: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/issues',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-public-ssh-keys-for-authenticated-user',
  `List public SSH keys for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/keys',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/create-public-ssh-key-for-authenticated-user',
  `Create a public SSH key for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: '/user/keys',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/get-public-ssh-key-for-authenticated-user',
  `Get a public SSH key for the authenticated user`,
  {
    key_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { key_id, ...queryParams } = args
      const url = `/user/keys/${key_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/delete-public-ssh-key-for-authenticated-user',
  `Delete a public SSH key for the authenticated user`,
  {
    key_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { key_id, ...queryParams } = args
      const url = `/user/keys/${key_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/list-subscriptions-for-authenticated-user',
  `List subscriptions for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/marketplace_purchases',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/list-subscriptions-for-authenticated-user-stubbed',
  `List subscriptions for the authenticated user (stubbed)`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/marketplace_purchases/stubbed',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-memberships-for-authenticated-user',
  `List organization memberships for the authenticated user`,
  {
    state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/memberships/orgs',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/get-membership-for-authenticated-user',
  `Get an organization membership for the authenticated user`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...queryParams } = args
      const url = `/user/memberships/orgs/${org}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/update-membership-for-authenticated-user',
  `Update an organization membership for the authenticated user`,
  {
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { org, ...requestData } = args
      const url = `/user/memberships/orgs/${org}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('migrations/list-for-authenticated-user', `List user migrations`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/user/migrations',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('migrations/start-for-authenticated-user', `Start a user migration`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'POST',
      url: '/user/migrations',
      data: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'migrations/get-status-for-authenticated-user',
  `Get a user migration status`,
  {
    migration_id: z.string(),
    exclude: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { migration_id, ...queryParams } = args
      const url = `/user/migrations/${migration_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/get-archive-for-authenticated-user',
  `Download a user migration archive`,
  {
    migration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { migration_id, ...queryParams } = args
      const url = `/user/migrations/${migration_id}/archive`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/delete-archive-for-authenticated-user',
  `Delete a user migration archive`,
  {
    migration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { migration_id, ...queryParams } = args
      const url = `/user/migrations/${migration_id}/archive`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/unlock-repo-for-authenticated-user',
  `Unlock a user repository`,
  {
    migration_id: z.string(),
    repo_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { migration_id, repo_name, ...queryParams } = args
      const url = `/user/migrations/${migration_id}/repos/${repo_name}/lock`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'migrations/list-repos-for-authenticated-user',
  `List repositories for a user migration`,
  {
    migration_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { migration_id, ...queryParams } = args
      const url = `/user/migrations/${migration_id}/repositories`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-for-authenticated-user',
  `List organizations for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/orgs',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/list-packages-for-authenticated-user',
  `List packages for the authenticated user&#x27;s namespace`,
  {
    package_type: z.string(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/packages',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-package-for-authenticated-user',
  `Get a package for the authenticated user`,
  {
    package_type: z.string(),
    package_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { package_type, package_name, ...queryParams } = args
      const url = `/user/packages/${package_type}/${package_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/delete-package-for-authenticated-user',
  `Delete a package for the authenticated user`,
  {
    package_type: z.string(),
    package_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { package_type, package_name, ...queryParams } = args
      const url = `/user/packages/${package_type}/${package_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/restore-package-for-authenticated-user',
  `Restore a package for the authenticated user`,
  {
    package_type: z.string(),
    package_name: z.string(),
    token: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { package_type, package_name, ...requestData } = args
      const url = `/user/packages/${package_type}/${package_name}/restore`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-all-package-versions-for-package-owned-by-authenticated-user',
  `List package versions for a package owned by the authenticated user`,
  {
    package_type: z.string(),
    package_name: z.string(),
    state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { package_type, package_name, ...queryParams } = args
      const url = `/user/packages/${package_type}/${package_name}/versions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-package-version-for-authenticated-user',
  `Get a package version for the authenticated user`,
  {
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { package_type, package_name, package_version_id, ...queryParams } = args
      const url = `/user/packages/${package_type}/${package_name}/versions/${package_version_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/delete-package-version-for-authenticated-user',
  `Delete a package version for the authenticated user`,
  {
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { package_type, package_name, package_version_id, ...queryParams } = args
      const url = `/user/packages/${package_type}/${package_name}/versions/${package_version_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/restore-package-version-for-authenticated-user',
  `Restore a package version for the authenticated user`,
  {
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { package_type, package_name, package_version_id, ...requestData } = args
      const url = `/user/packages/${package_type}/${package_name}/versions/${package_version_id}/restore`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('projects-classic/create-for-authenticated-user', `Create a user project`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'POST',
      url: '/user/projects',
      data: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'users/list-public-emails-for-authenticated-user',
  `List public email addresses for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/public_emails',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-for-authenticated-user',
  `List repositories for the authenticated user`,
  {
    visibility: z.string().optional(),
    affiliation: z.string().optional(),
    type: z.string().optional(),
    sort: z.string().optional(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/repos',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/create-for-authenticated-user',
  `Create a repository for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: '/user/repos',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-invitations-for-authenticated-user',
  `List repository invitations for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/repository_invitations',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/accept-invitation-for-authenticated-user',
  `Accept a repository invitation`,
  {
    invitation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { invitation_id, ...requestData } = args
      const url = `/user/repository_invitations/${invitation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PATCH',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/decline-invitation-for-authenticated-user',
  `Decline a repository invitation`,
  {
    invitation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { invitation_id, ...queryParams } = args
      const url = `/user/repository_invitations/${invitation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-social-accounts-for-authenticated-user',
  `List social accounts for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/social_accounts',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/add-social-account-for-authenticated-user',
  `Add social accounts for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: '/user/social_accounts',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/delete-social-account-for-authenticated-user',
  `Delete social accounts for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: '/user/social_accounts',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-ssh-signing-keys-for-authenticated-user',
  `List SSH signing keys for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/ssh_signing_keys',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/create-ssh-signing-key-for-authenticated-user',
  `Create a SSH signing key for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: '/user/ssh_signing_keys',
        data: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/get-ssh-signing-key-for-authenticated-user',
  `Get an SSH signing key for the authenticated user`,
  {
    ssh_signing_key_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { ssh_signing_key_id, ...queryParams } = args
      const url = `/user/ssh_signing_keys/${ssh_signing_key_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/delete-ssh-signing-key-for-authenticated-user',
  `Delete an SSH signing key for the authenticated user`,
  {
    ssh_signing_key_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { ssh_signing_key_id, ...queryParams } = args
      const url = `/user/ssh_signing_keys/${ssh_signing_key_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-repos-starred-by-authenticated-user',
  `List repositories starred by the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/starred',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/check-repo-is-starred-by-authenticated-user',
  `Check if a repository is starred by the authenticated user`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/user/starred/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/star-repo-for-authenticated-user',
  `Star a repository for the authenticated user`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...requestData } = args
      const url = `/user/starred/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'PUT',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/unstar-repo-for-authenticated-user',
  `Unstar a repository for the authenticated user`,
  {
    owner: z.string(),
    repo: z.string(),
  },
  async (args, extra) => {
    try {
      const { owner, repo, ...queryParams } = args
      const url = `/user/starred/${owner}/${repo}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-watched-repos-for-authenticated-user',
  `List repositories watched by the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/subscriptions',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'teams/list-for-authenticated-user',
  `List teams for the authenticated user`,
  {},
  async (args, extra) => {
    try {
      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: '/user/teams',
        params: args,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/get-by-id',
  `Get a user using their ID`,
  {
    account_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { account_id, ...queryParams } = args
      const url = `/user/${account_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('users/list', `List users`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/users',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool(
  'users/get-by-username',
  `Get a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-attestations-bulk',
  `List attestations by bulk subject digests`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...requestData } = args
      const url = `/users/${username}/attestations/bulk-list`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/delete-attestations-bulk',
  `Delete attestations in bulk`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...requestData } = args
      const url = `/users/${username}/attestations/delete-request`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/delete-attestations-by-subject-digest',
  `Delete attestations by subject digest`,
  {
    username: z.string(),
    subject_digest: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, subject_digest, ...queryParams } = args
      const url = `/users/${username}/attestations/digest/${subject_digest}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/delete-attestations-by-id',
  `Delete attestations by ID`,
  {
    username: z.string(),
    attestation_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, attestation_id, ...queryParams } = args
      const url = `/users/${username}/attestations/${attestation_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-attestations',
  `List attestations`,
  {
    username: z.string(),
    subject_digest: z.string(),
    predicate_type: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { username, subject_digest, ...queryParams } = args
      const url = `/users/${username}/attestations/${subject_digest}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/list-docker-migration-conflicting-packages-for-user',
  `Get list of conflicting packages during Docker migration for user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/docker/conflicts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-events-for-authenticated-user',
  `List events for the authenticated user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/events`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-org-events-for-authenticated-user',
  `List organization events for the authenticated user`,
  {
    username: z.string(),
    org: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, org, ...queryParams } = args
      const url = `/users/${username}/events/orgs/${org}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-public-events-for-user',
  `List public events for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/events/public`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-followers-for-user',
  `List followers of a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/followers`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-following-for-user',
  `List the people a user follows`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/following`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/check-following-for-user',
  `Check if a user follows another user`,
  {
    username: z.string(),
    target_user: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, target_user, ...queryParams } = args
      const url = `/users/${username}/following/${target_user}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'gists/list-for-user',
  `List gists for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/gists`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-gpg-keys-for-user',
  `List GPG keys for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/gpg_keys`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/get-context-for-user',
  `Get contextual information for a user`,
  {
    username: z.string(),
    subject_type: z.string().optional(),
    subject_id: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/hovercard`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'apps/get-user-installation',
  `Get a user installation for the authenticated app`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/installation`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-public-keys-for-user',
  `List public keys for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/keys`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'orgs/list-for-user',
  `List organizations for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/orgs`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/list-packages-for-user',
  `List packages for a user`,
  {
    username: z.string(),
    package_type: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/packages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-package-for-user',
  `Get a package for a user`,
  {
    username: z.string(),
    package_type: z.string(),
    package_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, package_type, package_name, ...queryParams } = args
      const url = `/users/${username}/packages/${package_type}/${package_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/delete-package-for-user',
  `Delete a package for a user`,
  {
    username: z.string(),
    package_type: z.string(),
    package_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, package_type, package_name, ...queryParams } = args
      const url = `/users/${username}/packages/${package_type}/${package_name}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/restore-package-for-user',
  `Restore a package for a user`,
  {
    username: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    token: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { username, package_type, package_name, ...requestData } = args
      const url = `/users/${username}/packages/${package_type}/${package_name}/restore`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-all-package-versions-for-package-owned-by-user',
  `List package versions for a package owned by a user`,
  {
    username: z.string(),
    package_type: z.string(),
    package_name: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, package_type, package_name, ...queryParams } = args
      const url = `/users/${username}/packages/${package_type}/${package_name}/versions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/get-package-version-for-user',
  `Get a package version for a user`,
  {
    username: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, package_type, package_name, package_version_id, ...queryParams } = args
      const url = `/users/${username}/packages/${package_type}/${package_name}/versions/${package_version_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/delete-package-version-for-user',
  `Delete package version for a user`,
  {
    username: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, package_type, package_name, package_version_id, ...queryParams } = args
      const url = `/users/${username}/packages/${package_type}/${package_name}/versions/${package_version_id}`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'DELETE',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'packages/restore-package-version-for-user',
  `Restore package version for a user`,
  {
    username: z.string(),
    package_type: z.string(),
    package_name: z.string(),
    package_version_id: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, package_type, package_name, package_version_id, ...requestData } = args
      const url = `/users/${username}/packages/${package_type}/${package_name}/versions/${package_version_id}/restore`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'POST',
        url: url,
        data: requestData,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'projects-classic/list-for-user',
  `List user projects`,
  {
    username: z.string(),
    state: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/projects`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-received-events-for-user',
  `List events received by the authenticated user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/received_events`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-received-public-events-for-user',
  `List public events received by a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/received_events/public`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'repos/list-for-user',
  `List repositories for a user`,
  {
    username: z.string(),
    type: z.string().optional(),
    sort: z.string().optional(),
    direction: z.string().optional(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/repos`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'billing/get-github-actions-billing-user',
  `Get GitHub Actions billing for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/settings/billing/actions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'billing/get-github-packages-billing-user',
  `Get GitHub Packages billing for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/settings/billing/packages`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'billing/get-shared-storage-billing-user',
  `Get shared storage billing for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/settings/billing/shared-storage`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'billing/get-github-billing-usage-report-user',
  `Get billing usage report for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/settings/billing/usage`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-social-accounts-for-user',
  `List social accounts for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/social_accounts`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'users/list-ssh-signing-keys-for-user',
  `List SSH signing keys for a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/ssh_signing_keys`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-repos-starred-by-user',
  `List repositories starred by a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/starred`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool(
  'activity/list-repos-watched-by-user',
  `List repositories watched by a user`,
  {
    username: z.string(),
  },
  async (args, extra) => {
    try {
      const { username, ...queryParams } = args
      const url = `/users/${username}/subscriptions`

      // Extract authorization token from HTTP request headers
      const authorization = extra?.requestInfo?.headers?.authorization as string
      const bearer = authorization?.replace('Bearer ', '')

      const response = await apiClient.request({
        headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
        method: 'GET',
        url: url,
        params: queryParams,
      })

      return handleResult(response.data)
    } catch (error) {
      return handleError(error)
    }
  }
)

mcpServer.tool('meta/get-all-versions', `Get all API versions`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/versions',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})

mcpServer.tool('meta/get-zen', `Get the Zen of GitHub`, {}, async (args, extra) => {
  try {
    // Extract authorization token from HTTP request headers
    const authorization = extra?.requestInfo?.headers?.authorization as string
    const bearer = authorization?.replace('Bearer ', '')

    const response = await apiClient.request({
      headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
      method: 'GET',
      url: '/zen',
      params: args,
    })

    return handleResult(response.data)
  } catch (error) {
    return handleError(error)
  }
})
