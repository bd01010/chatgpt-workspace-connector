"""
ChatGPT Google Workspace MCP Connector - Hybrid Version
Includes both required search/fetch tools AND Google Workspace tools
"""

import os, json, asyncio, typing, httpx
from uuid import uuid4
from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.responses import StreamingResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# ─── Configuration ────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID = "72500811727-amrpcqfmfqc6jd9q0qq64lobrbt7mm7s.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
BASE_URL = "https://chatgpt-mcp-connector.vercel.app"
SESSION_SECRET = "1234"
REDIRECT_URI = f"{BASE_URL}/oauth/callback"
SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/presentations",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
]

# ─── FastAPI setup ───────────────────────────────────────────────────────
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# ─── Google OAuth flow helper ────────────────────────────────────────────
def google_flow() -> Flow:
    return Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )

# ─── Health route ─────────────────────────────────────────────────────────
@app.get("/")
def health():
    return {"status": "ok"}

# ─── Drive helpers ────────────────────────────────────────────────────────
def _creds(req: Request) -> Credentials:
    if "creds" not in req.session:
        raise HTTPException(401, "missing_credentials")
    return Credentials.from_authorized_user_info(req.session["creds"])

def _drive(c: Credentials):
    return build("drive", "v3", credentials=c, cache_discovery=False)

def _docs(c: Credentials):
    return build("docs", "v1", credentials=c, cache_discovery=False)

def _sheets(c: Credentials):
    return build("sheets", "v4", credentials=c, cache_discovery=False)

def _slides(c: Credentials):
    return build("slides", "v1", credentials=c, cache_discovery=False)

# ─── Required search/fetch tools for ChatGPT ─────────────────────────────
def search_fn(creds: Credentials, query: str):
    """Required search tool that returns document IDs"""
    try:
        # Search Google Drive files
        results = _drive(creds).files().list(
            pageSize=10, 
            q=f"name contains '{query}' or fullText contains '{query}'",
            fields="files(id,name,mimeType,modifiedTime)"
        ).execute()
        
        files = results.get('files', [])
        # Return in the required format
        return {"ids": [f["id"] for f in files]}
    except:
        return {"ids": []}

def fetch_fn(creds: Credentials, id: str):
    """Required fetch tool that returns document details"""
    try:
        # Get file metadata
        file = _drive(creds).files().get(fileId=id, fields="id,name,mimeType,modifiedTime,webViewLink").execute()
        
        # Try to get content for text files
        content = ""
        if file.get('mimeType', '').startswith('text/'):
            try:
                content = _drive(creds).files().get_media(fileId=id).execute()
                content = content.decode('utf-8') if isinstance(content, bytes) else str(content)
            except:
                content = "Content not available"
        
        # Return in the required format
        return {
            "id": file['id'],
            "title": file['name'],
            "text": content or f"File: {file['name']} (Type: {file.get('mimeType', 'unknown')})",
            "metadata": {
                "mimeType": file.get('mimeType'),
                "modifiedTime": file.get('modifiedTime'),
                "url": file.get('webViewLink', '')
            }
        }
    except:
        return {"error": f"Document not found: {id}"}

# ─── Google Workspace specific tools ──────────────────────────────────────
def drive_list_fn(creds: Credentials):
    return _drive(creds).files().list(
        pageSize=20, fields="files(id,name,mimeType,modifiedTime)"
    ).execute()["files"]

def drive_create_folder_fn(creds: Credentials, name: str = "New Folder"):
    meta = {"name": name, "mimeType": "application/vnd.google-apps.folder"}
    return _drive(creds).files().create(body=meta, fields="id,name").execute()

def drive_create_file_fn(creds: Credentials, name: str, content: str = "", mimeType: str = "text/plain"):
    import io
    from googleapiclient.http import MediaIoBaseUpload
    
    file_metadata = {"name": name}
    media = MediaIoBaseUpload(io.BytesIO(content.encode()), mimetype=mimeType)
    return _drive(creds).files().create(body=file_metadata, media_body=media, fields="id,name").execute()

def drive_read_file_fn(creds: Credentials, fileId: str):
    try:
        content = _drive(creds).files().get_media(fileId=fileId).execute()
        return {"content": content.decode('utf-8') if isinstance(content, bytes) else str(content)}
    except:
        return {"error": "Could not read file"}

def drive_update_file_fn(creds: Credentials, fileId: str, content: str):
    import io
    from googleapiclient.http import MediaIoBaseUpload
    
    media = MediaIoBaseUpload(io.BytesIO(content.encode()), mimetype="text/plain")
    return _drive(creds).files().update(fileId=fileId, media_body=media, fields="id,name,modifiedTime").execute()

def drive_delete_file_fn(creds: Credentials, fileId: str):
    _drive(creds).files().delete(fileId=fileId).execute()
    return {"deleted": True, "fileId": fileId}

def docs_create_fn(creds: Credentials, title: str = "New Document"):
    body = {"title": title}
    return _docs(creds).documents().create(body=body).execute()

def sheets_create_fn(creds: Credentials, title: str = "New Spreadsheet"):
    body = {"properties": {"title": title}}
    return _sheets(creds).spreadsheets().create(body=body).execute()

def slides_create_fn(creds: Credentials, title: str = "New Presentation"):
    body = {"title": title}
    return _slides(creds).presentations().create(body=body).execute()

# ─── Tools registry ───────────────────────────────────────────────────────
TOOLS_REGISTRY = {
    # Required tools for ChatGPT
    "search": {
        "func": search_fn,
        "parameters": {"query": "string"},
    },
    "fetch": {
        "func": fetch_fn,
        "parameters": {"id": "string"},
    },
    # Google Workspace tools
    "drive_list": {
        "func": drive_list_fn,
        "parameters": {},
    },
    "drive_create_folder": {
        "func": drive_create_folder_fn,
        "parameters": {"name": "string"},
    },
    "drive_create_file": {
        "func": drive_create_file_fn,
        "parameters": {"name": "string", "content": "string", "mimeType": "string"},
    },
    "drive_read_file": {
        "func": drive_read_file_fn,
        "parameters": {"fileId": "string"},
    },
    "drive_update_file": {
        "func": drive_update_file_fn,
        "parameters": {"fileId": "string", "content": "string"},
    },
    "drive_delete_file": {
        "func": drive_delete_file_fn,
        "parameters": {"fileId": "string"},
    },
    "docs_create": {
        "func": docs_create_fn,
        "parameters": {"title": "string"},
    },
    "sheets_create": {
        "func": sheets_create_fn,
        "parameters": {"title": "string"},
    },
    "slides_create": {
        "func": slides_create_fn,
        "parameters": {"title": "string"},
    },
}

# ─── SSE first frame (tools list) ────────────────────────────────────────
TOOLS_EVENT = (
    "event: tools\n" +
    "data: " + json.dumps({
        "tools": [
            # Required tools for ChatGPT
            {
                "name": "search",
                "description": "Search for documents matching the query",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search terms"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "fetch",
                "description": "Fetch a document by ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "description": "Document ID"}
                    },
                    "required": ["id"]
                }
            },
            # Google Workspace tools
            {
                "name": "drive_list",
                "description": "List files in Google Drive",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "drive_create_folder",
                "description": "Create a folder in Google Drive",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Folder name"}
                    },
                    "required": []
                }
            },
            {
                "name": "drive_create_file",
                "description": "Create a file in Google Drive",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "File name"},
                        "content": {"type": "string", "description": "File content"},
                        "mimeType": {"type": "string", "description": "MIME type"}
                    },
                    "required": ["name"]
                }
            },
            {
                "name": "drive_read_file",
                "description": "Read a file from Google Drive",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "fileId": {"type": "string", "description": "File ID"}
                    },
                    "required": ["fileId"]
                }
            },
            {
                "name": "drive_update_file",
                "description": "Update a file in Google Drive",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "fileId": {"type": "string", "description": "File ID"},
                        "content": {"type": "string", "description": "New content"}
                    },
                    "required": ["fileId", "content"]
                }
            },
            {
                "name": "drive_delete_file",
                "description": "Delete a file from Google Drive",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "fileId": {"type": "string", "description": "File ID"}
                    },
                    "required": ["fileId"]
                }
            },
            {
                "name": "docs_create",
                "description": "Create a new Google Doc",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Document title"}
                    },
                    "required": []
                }
            },
            {
                "name": "sheets_create",
                "description": "Create a new Google Sheet",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Spreadsheet title"}
                    },
                    "required": []
                }
            },
            {
                "name": "slides_create",
                "description": "Create a new Google Slides presentation",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Presentation title"}
                    },
                    "required": []
                }
            }
        ]
    }) + "\n\n"
)

# ─── SSE GET handler ─────────────────────────────────────────────────────
@app.get("/sse")
async def sse(req: Request):
    async def gen():
        yield TOOLS_EVENT
        while not await req.is_disconnected():
            yield "event: ping\ndata: {}\n\n"
            await asyncio.sleep(25)
    return StreamingResponse(gen(), media_type="text/event-stream")

@app.get("/sse/")
async def sse_slash(req: Request):
    async def gen():
        yield TOOLS_EVENT
        while not await req.is_disconnected():
            yield "event: ping\ndata: {}\n\n"
            await asyncio.sleep(25)
    return StreamingResponse(gen(), media_type="text/event-stream")

# ─── Streamable‑HTTP POST handler ────────────────────────────────────────
@app.post("/sse")
async def sse_invoke(req: Request):
    payload = await req.json()
    call_id = payload.get("id")
    tool = payload.get("tool", payload.get("name"))  # Support both formats
    args = payload.get("args", payload.get("arguments", {}))

    if tool not in TOOLS_REGISTRY:
        raise HTTPException(400, f"Unknown tool: {tool}")

    creds = _creds(req)
    try:
        # Handle different tool signatures
        if tool in ["search", "fetch"]:
            # These tools expect specific parameters
            if tool == "search":
                result = TOOLS_REGISTRY[tool]["func"](creds, query=args.get("query", ""))
            else:  # fetch
                result = TOOLS_REGISTRY[tool]["func"](creds, id=args.get("id", ""))
        elif tool == "drive_list":
            result = TOOLS_REGISTRY[tool]["func"](creds)
        else:
            result = TOOLS_REGISTRY[tool]["func"](creds, **args)
    except Exception as e:
        result = {"error": str(e)}

    response_body = {"id": call_id, "result": result}
    return response_body

@app.post("/sse/")
async def sse_invoke_slash(req: Request):
    payload = await req.json()
    call_id = payload.get("id")
    tool = payload.get("tool", payload.get("name"))  # Support both formats
    args = payload.get("args", payload.get("arguments", {}))

    if tool not in TOOLS_REGISTRY:
        raise HTTPException(400, f"Unknown tool: {tool}")

    creds = _creds(req)
    try:
        # Handle different tool signatures
        if tool in ["search", "fetch"]:
            # These tools expect specific parameters
            if tool == "search":
                result = TOOLS_REGISTRY[tool]["func"](creds, query=args.get("query", ""))
            else:  # fetch
                result = TOOLS_REGISTRY[tool]["func"](creds, id=args.get("id", ""))
        elif tool == "drive_list":
            result = TOOLS_REGISTRY[tool]["func"](creds)
        else:
            result = TOOLS_REGISTRY[tool]["func"](creds, **args)
    except Exception as e:
        result = {"error": str(e)}

    response_body = {"id": call_id, "result": result}
    return response_body

# ─── OAuth endpoints ─────────────────────────────────────────────────────
@app.get("/oauth/authorize")
def oauth_authorize():
    url, _ = google_flow().authorization_url(access_type="offline", prompt="consent", state=uuid4().hex)
    return RedirectResponse(url, status_code=302)

@app.get("/oauth/callback")
def oauth_callback(req: Request, code: str):
    flow = google_flow()
    flow.fetch_token(code=code)
    req.session["creds"] = json.loads(flow.credentials.to_json())
    return JSONResponse({"ok": True})

@app.post("/oauth/token")
def oauth_token(grant_type: str = Form(...), code: str | None = Form(None), refresh_token: str | None = Form(None)):
    if grant_type == "authorization_code":
        flow = google_flow()
        flow.fetch_token(code=code)
        creds = flow.credentials
    elif grant_type == "refresh_token":
        resp = httpx.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        ).json()
        if "access_token" not in resp:
            raise HTTPException(400, resp.get("error", "refresh_failed"))
        creds = Credentials(token=resp["access_token"], refresh_token=refresh_token, client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET, token_uri="https://oauth2.googleapis.com/token")
    else:
        raise HTTPException(400, "unsupported grant_type")
    return {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }

# ─── Discovery docs ──────────────────────────────────────────────────────
@app.get("/.well-known/oauth-authorization-server")
def disc_auth(req: Request):
    base = f"{req.url.scheme}://{req.url.netloc}"
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/oauth/authorize",
        "token_endpoint": f"{base}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }

@app.get("/.well-known/mcp.json")
def well_known_mcp():
    return {
        "mcpServers": {"gptdrive": {"url": f"{BASE_URL}/sse"}},
        "schemaVersion": 1,
    }

@app.get("/mcp/manifest.json")
def manifest():
    return {
        "id": "gptdrive",
        "name": "Google Workspace",
        "version": "1.0.0",
        "description": "Access Google Drive, Docs, Sheets, and Slides",
        "mcp_server_url": f"{BASE_URL}/sse",
        "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
        "jsonrpc": "2.0",
    }

@app.get("/openapi.json")
def openapi():
    return {"openapi": "3.0.0", "info": {"title": "Google Workspace MCP", "version": "1.0.0"}}