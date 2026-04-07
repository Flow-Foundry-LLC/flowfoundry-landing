import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer } from "node:http";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { z } from "zod";

// ── Config ──────────────────────────────────────────────────────────────────

const GHOST_URL = process.env.GHOST_URL || "https://www.flowfoundry.com/blog";
const GHOST_ADMIN_API_KEY = process.env.GHOST_ADMIN_API_KEY || "";
const MCP_API_KEY = process.env.MCP_API_KEY || "";
const PORT = parseInt(process.env.PORT || "3100", 10);

if (!GHOST_ADMIN_API_KEY) {
  console.error("GHOST_ADMIN_API_KEY environment variable is required");
  process.exit(1);
}
if (!MCP_API_KEY) {
  console.error("MCP_API_KEY environment variable is required (for authenticating Claude.ai requests)");
  process.exit(1);
}

const [KEY_ID, KEY_SECRET] = GHOST_ADMIN_API_KEY.split(":");
const API_BASE = `${GHOST_URL}/ghost/api/admin`;

// ── JWT Auth for Ghost ──────────────────────────────────────────────────────

function base64url(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return buf.toString("base64url");
}

function generateToken(): string {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "HS256", typ: "JWT", kid: KEY_ID };
  const payload = { iat: now, exp: now + 300, aud: "/admin/" };
  const segments = [
    base64url(JSON.stringify(header)),
    base64url(JSON.stringify(payload)),
  ];
  const input = segments.join(".");
  const secretBytes = Buffer.from(KEY_SECRET, "hex");
  const signature = createHmac("sha256", secretBytes).update(input).digest();
  segments.push(base64url(signature));
  return segments.join(".");
}

// ── Ghost HTTP Helper ───────────────────────────────────────────────────────

interface GhostResponse {
  [key: string]: unknown;
  errors?: Array<{ message: string; context?: string; type?: string }>;
}

async function ghostFetch(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    query?: Record<string, string | number | boolean | undefined>;
  } = {}
): Promise<GhostResponse> {
  const { method = "GET", body, query } = options;
  const token = generateToken();

  let url = `${API_BASE}${path}`;
  if (query) {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined) params.set(k, String(v));
    }
    const qs = params.toString();
    if (qs) url += `?${qs}`;
  }

  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Ghost ${token}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (res.status === 204) return {};
  const data = (await res.json()) as GhostResponse;
  if (data.errors) {
    const err = data.errors[0];
    throw new Error(`Ghost API error: ${err.message}${err.context ? ` — ${err.context}` : ""}`);
  }
  return data;
}

async function ghostUpload(
  path: string,
  filePath: string,
  purpose: string = "image"
): Promise<GhostResponse> {
  const token = generateToken();
  const url = `${API_BASE}${path}`;
  const fileBuffer = await readFile(filePath);
  const fileName = basename(filePath);
  const ext = fileName.split(".").pop()?.toLowerCase();
  const mimeTypes: Record<string, string> = {
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg",
    gif: "image/gif", svg: "image/svg+xml", webp: "image/webp",
  };
  const contentType = mimeTypes[ext || ""] || "application/octet-stream";
  const boundary = `----GhostMCP${Date.now()}`;
  const parts: Buffer[] = [];
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: ${contentType}\r\n\r\n`));
  parts.push(fileBuffer);
  parts.push(Buffer.from("\r\n"));
  parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="purpose"\r\n\r\n${purpose}\r\n`));
  parts.push(Buffer.from(`--${boundary}--\r\n`));
  const body = Buffer.concat(parts);

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Ghost ${token}`,
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
    },
    body,
  });
  const data = (await res.json()) as GhostResponse;
  if (data.errors) {
    const err = (data.errors as Array<{ message: string; context?: string }>)[0];
    throw new Error(`Ghost upload error: ${err.message}${err.context ? ` — ${err.context}` : ""}`);
  }
  return data;
}

// ── Build MCP Server (same tools as stdio version) ──────────────────────────

function createGhostMcpServer(): McpServer {
  const server = new McpServer({
    name: "ghost",
    version: "1.0.0",
  });

  // ── Read Tools ──

  server.tool("ghost_get_site", "Get Ghost site information", {}, async () => {
    const data = await ghostFetch("/site/");
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  server.tool("ghost_list_posts", "List blog posts with filters", {
    status: z.enum(["published", "draft", "scheduled", "all"]).optional(),
    tag: z.string().optional(),
    limit: z.number().optional(),
    page: z.number().optional(),
  }, async ({ status, tag, limit, page }) => {
    const query: Record<string, string | number | undefined> = {
      limit: limit || 15, page,
      fields: "id,title,slug,status,published_at,updated_at,excerpt,url",
      order: "published_at desc",
    };
    const filters: string[] = [];
    if (status && status !== "all") filters.push(`status:${status}`);
    if (tag) filters.push(`tag:${tag}`);
    if (filters.length) query.filter = filters.join("+");
    const data = await ghostFetch("/posts/", { query });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  server.tool("ghost_read_post", "Read full post by ID or slug", {
    id: z.string().optional(),
    slug: z.string().optional(),
  }, async ({ id, slug }) => {
    if (!id && !slug) throw new Error("Provide either id or slug");
    const path = id ? `/posts/${id}/` : `/posts/slug/${slug}/`;
    const data = await ghostFetch(path, { query: { formats: "html", include: "tags,authors" } });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  server.tool("ghost_list_tags", "List all tags", {
    limit: z.number().optional(),
  }, async ({ limit }) => {
    const data = await ghostFetch("/tags/", { query: { limit: limit || "all", include: "count.posts" } });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  server.tool("ghost_list_pages", "List static pages", {
    status: z.enum(["published", "draft", "all"]).optional(),
    limit: z.number().optional(),
  }, async ({ status, limit }) => {
    const query: Record<string, string | number | undefined> = {
      limit: limit || "all",
      fields: "id,title,slug,status,published_at,updated_at,url",
    };
    if (status && status !== "all") query.filter = `status:${status}`;
    const data = await ghostFetch("/pages/", { query });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  // ── Post Mutations ──

  server.tool("ghost_create_post", "Create a blog post with HTML content", {
    title: z.string(),
    html: z.string(),
    status: z.enum(["published", "draft", "scheduled"]).optional(),
    tags: z.array(z.string()).optional(),
    excerpt: z.string().optional(),
    featured: z.boolean().optional(),
    feature_image: z.string().optional(),
    feature_image_alt: z.string().optional(),
    published_at: z.string().optional(),
    slug: z.string().optional(),
  }, async ({ title, html, status, tags, excerpt, featured, feature_image, feature_image_alt, published_at, slug }) => {
    const post: Record<string, unknown> = { title, html, status: status || "draft" };
    if (tags) post.tags = tags.map((name) => ({ name }));
    if (excerpt) post.excerpt = excerpt;
    if (featured !== undefined) post.featured = featured;
    if (feature_image) post.feature_image = feature_image;
    if (feature_image_alt) post.feature_image_alt = feature_image_alt;
    if (published_at) post.published_at = published_at;
    if (slug) post.slug = slug;
    const data = await ghostFetch("/posts/", { method: "POST", query: { source: "html" }, body: { posts: [post] } });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  server.tool("ghost_update_post", "Update a blog post (requires updated_at)", {
    id: z.string(),
    updated_at: z.string(),
    title: z.string().optional(),
    html: z.string().optional(),
    status: z.enum(["published", "draft", "scheduled"]).optional(),
    tags: z.array(z.string()).optional(),
    excerpt: z.string().optional(),
    featured: z.boolean().optional(),
    feature_image: z.string().optional(),
    feature_image_alt: z.string().optional(),
    published_at: z.string().optional(),
    slug: z.string().optional(),
  }, async ({ id, updated_at, title, html, status, tags, excerpt, featured, feature_image, feature_image_alt, published_at, slug }) => {
    const post: Record<string, unknown> = { updated_at };
    if (title) post.title = title;
    if (html) post.html = html;
    if (status) post.status = status;
    if (tags) post.tags = tags.map((name) => ({ name }));
    if (excerpt !== undefined) post.excerpt = excerpt;
    if (featured !== undefined) post.featured = featured;
    if (feature_image !== undefined) post.feature_image = feature_image;
    if (feature_image_alt !== undefined) post.feature_image_alt = feature_image_alt;
    if (published_at) post.published_at = published_at;
    if (slug) post.slug = slug;
    const data = await ghostFetch(`/posts/${id}/`, { method: "PUT", query: { source: "html" }, body: { posts: [post] } });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  server.tool("ghost_delete_post", "Delete a blog post permanently", {
    id: z.string(),
  }, async ({ id }) => {
    await ghostFetch(`/posts/${id}/`, { method: "DELETE" });
    return { content: [{ type: "text", text: `Post ${id} deleted.` }] };
  });

  // ── Page Mutations ──

  server.tool("ghost_create_page", "Create a static page", {
    title: z.string(),
    html: z.string(),
    status: z.enum(["published", "draft"]).optional(),
    slug: z.string().optional(),
    feature_image: z.string().optional(),
  }, async ({ title, html, status, slug, feature_image }) => {
    const page: Record<string, unknown> = { title, html, status: status || "draft" };
    if (slug) page.slug = slug;
    if (feature_image) page.feature_image = feature_image;
    const data = await ghostFetch("/pages/", { method: "POST", query: { source: "html" }, body: { pages: [page] } });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  server.tool("ghost_update_page", "Update a static page (requires updated_at)", {
    id: z.string(),
    updated_at: z.string(),
    title: z.string().optional(),
    html: z.string().optional(),
    status: z.enum(["published", "draft"]).optional(),
    slug: z.string().optional(),
    feature_image: z.string().optional(),
  }, async ({ id, updated_at, title, html, status, slug, feature_image }) => {
    const page: Record<string, unknown> = { updated_at };
    if (title) page.title = title;
    if (html) page.html = html;
    if (status) page.status = status;
    if (slug) page.slug = slug;
    if (feature_image !== undefined) page.feature_image = feature_image;
    const data = await ghostFetch(`/pages/${id}/`, { method: "PUT", query: { source: "html" }, body: { pages: [page] } });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  server.tool("ghost_delete_page", "Delete a static page permanently", {
    id: z.string(),
  }, async ({ id }) => {
    await ghostFetch(`/pages/${id}/`, { method: "DELETE" });
    return { content: [{ type: "text", text: `Page ${id} deleted.` }] };
  });

  // ── Tags ──

  server.tool("ghost_create_tag", "Create a tag", {
    name: z.string(),
    slug: z.string().optional(),
    description: z.string().optional(),
  }, async ({ name, slug, description }) => {
    const tag: Record<string, unknown> = { name };
    if (slug) tag.slug = slug;
    if (description) tag.description = description;
    const data = await ghostFetch("/tags/", { method: "POST", body: { tags: [tag] } });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  });

  // ── Image Upload ──

  server.tool("ghost_upload_image", "Upload image to Ghost, returns hosted URL", {
    file_path: z.string(),
    purpose: z.enum(["image", "profile_image", "icon"]).optional(),
  }, async ({ file_path, purpose }) => {
    const data = await ghostUpload("/images/upload/", file_path, purpose || "image");
    const images = data.images as Array<{ url: string }>;
    return { content: [{ type: "text", text: JSON.stringify({ url: images[0].url, message: "Image uploaded." }, null, 2) }] };
  });

  return server;
}

// ── HTTP Server ─────────────────────────────────────────────────────────────

const httpServer = createServer(async (req, res) => {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // Health check
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", server: "ghost-mcp" }));
    return;
  }

  // MCP endpoint
  if (req.method === "POST" && req.url === "/mcp") {
    // Validate API key
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${MCP_API_KEY}`) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    try {
      // Collect request body
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
      }
      const bodyStr = Buffer.concat(chunks).toString("utf-8");
      const parsedBody = JSON.parse(bodyStr);

      // Create a fresh server + transport per request (stateless mode)
      const mcpServer = createGhostMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined, // stateless
      });

      await mcpServer.connect(transport);
      await transport.handleRequest(req, res, parsedBody);
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null }));
      }
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

httpServer.listen(PORT, "127.0.0.1", () => {
  console.log(`Ghost MCP remote server running on http://127.0.0.1:${PORT}/mcp`);
});
