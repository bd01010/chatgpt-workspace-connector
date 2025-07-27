# ChatGPT Google Workspace MCP Connector

This is a ChatGPT Custom Connector that integrates Google Workspace (Drive, Docs, Sheets, Slides) using the Model Context Protocol (MCP).

## Features

- **Required ChatGPT Tools**: `search` and `fetch` for document discovery
- **Google Drive**: List, create, read, update, and delete files
- **Google Docs**: Create new documents
- **Google Sheets**: Create new spreadsheets
- **Google Slides**: Create new presentations
- **OAuth 2.0**: Secure authentication with Google

## Setup

1. Deploy to Vercel
2. Update Google Cloud Console OAuth redirect URI to `https://your-deployment.vercel.app/oauth/callback`
3. Add to ChatGPT as a Custom Connector using the `/sse/` endpoint

## Endpoints

- `/sse/` - Main MCP endpoint for ChatGPT
- `/oauth/authorize` - Start OAuth flow
- `/oauth/callback` - OAuth callback
- `/.well-known/oauth-authorization-server` - OAuth discovery

## Usage in ChatGPT

1. Go to ChatGPT Settings → Connectors
2. Add Custom Connector
3. Enter your deployment URL with `/sse/` endpoint
4. Authenticate with Google when prompted
5. Use Deep Research mode to access your Google Workspace files