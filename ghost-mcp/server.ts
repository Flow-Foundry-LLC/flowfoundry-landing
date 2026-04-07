import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";

// ── Config ──────────────────────────────────────────────────────────────────

const GHOST_URL = process.env.GHOST_URL || "https://www.flowfoundry.com/blog";
const GHOST_ADMIN_API_KEY = process.env.GHOST_ADMIN_API_KEY || "";

if (!GHOST_ADMIN_API_KEY) {
  console.error("GHOST_ADMIN_API_KEY environment variable is required");
  process.exit(1);
}

const [KEY_ID, KEY_SECRET] = GHOST_ADMIN_API_KEY.split(":");
const API_BASE = `${GHOST_URL}/ghost/api/admin`;

// ── JWT Auth (no external dependency) ───────────────────────────────────────

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

// ── HTTP Helper ─────────────────────────────────────────────────────────────

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

  const headers: Record<string, string> = {
    Authorization: `Ghost ${token}`,
    "Content-Type": "application/json",
  };

  const res = await fetch(url, {
    method,
    headers,
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

  // Determine content type
  const ext = fileName.split(".").pop()?.toLowerCase();
  const mimeTypes: Record<string, string> = {
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    svg: "image/svg+xml",
    webp: "image/webp",
  };
  const contentType = mimeTypes[ext || ""] || "application/octet-stream";

  // Build multipart form data manually
  const boundary = `----GhostMCP${Date.now()}`;
  const parts: Buffer[] = [];

  // File part
  parts.push(Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: ${contentType}\r\n\r\n`
  ));
  parts.push(fileBuffer);
  parts.push(Buffer.from("\r\n"));

  // Purpose part
  parts.push(Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="purpose"\r\n\r\n${purpose}\r\n`
  ));

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

// ── MCP Server ──────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "ghost",
  version: "1.0.0",
});

// ── Read Tools ──────────────────────────────────────────────────────────────

server.tool(
  "ghost_get_site",
  "Get Ghost site information (title, description, version, URL)",
  {},
  async () => {
    const data = await ghostFetch("/site/");
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "ghost_list_posts",
  "List blog posts. Filter by status (published/draft/scheduled), tag, or search. Returns titles, slugs, IDs, dates, and status.",
  {
    status: z.enum(["published", "draft", "scheduled", "all"]).optional().describe("Filter by post status"),
    tag: z.string().optional().describe("Filter by tag slug"),
    limit: z.number().optional().describe("Number of posts to return (default 15)"),
    page: z.number().optional().describe("Page number for pagination"),
  },
  async ({ status, tag, limit, page }) => {
    const query: Record<string, string | number | undefined> = {
      limit: limit || 15,
      page,
      fields: "id,title,slug,status,published_at,updated_at,excerpt,url",
      order: "published_at desc",
    };

    const filters: string[] = [];
    if (status && status !== "all") filters.push(`status:${status}`);
    if (tag) filters.push(`tag:${tag}`);
    if (filters.length) query.filter = filters.join("+");

    const data = await ghostFetch("/posts/", { query });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "ghost_read_post",
  "Read a single post's full content by ID or slug. Returns HTML content, tags, author, and updated_at (needed for updates).",
  {
    id: z.string().optional().describe("Post ID"),
    slug: z.string().optional().describe("Post slug (alternative to ID)"),
  },
  async ({ id, slug }) => {
    if (!id && !slug) throw new Error("Provide either id or slug");

    const path = id ? `/posts/${id}/` : `/posts/slug/${slug}/`;
    const data = await ghostFetch(path, {
      query: { formats: "html", include: "tags,authors" },
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "ghost_list_tags",
  "List all tags with post counts.",
  {
    limit: z.number().optional().describe("Number of tags to return (default: all)"),
  },
  async ({ limit }) => {
    const data = await ghostFetch("/tags/", {
      query: { limit: limit || "all", include: "count.posts" },
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "ghost_list_pages",
  "List all static pages.",
  {
    status: z.enum(["published", "draft", "all"]).optional().describe("Filter by status"),
    limit: z.number().optional().describe("Number of pages to return"),
  },
  async ({ status, limit }) => {
    const query: Record<string, string | number | undefined> = {
      limit: limit || "all",
      fields: "id,title,slug,status,published_at,updated_at,url",
    };
    if (status && status !== "all") query.filter = `status:${status}`;

    const data = await ghostFetch("/pages/", { query });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ── Post Mutation Tools ─────────────────────────────────────────────────────

server.tool(
  "ghost_create_post",
  "Create a new blog post. Content should be HTML. Tags are auto-created if they don't exist. Set status to 'scheduled' and provide published_at for scheduled posts.",
  {
    title: z.string().describe("Post title"),
    html: z.string().describe("Post content as HTML"),
    status: z.enum(["published", "draft", "scheduled"]).optional().describe("Post status (default: draft)"),
    tags: z.array(z.string()).optional().describe("Array of tag names"),
    excerpt: z.string().optional().describe("Custom excerpt for post cards and SEO"),
    featured: z.boolean().optional().describe("Mark as featured post"),
    feature_image: z.string().optional().describe("URL of feature image"),
    feature_image_alt: z.string().optional().describe("Alt text for feature image"),
    published_at: z.string().optional().describe("ISO 8601 datetime for scheduling (required when status is 'scheduled')"),
    slug: z.string().optional().describe("Custom URL slug"),
  },
  async ({ title, html, status, tags, excerpt, featured, feature_image, feature_image_alt, published_at, slug }) => {
    const post: Record<string, unknown> = {
      title,
      html,
      status: status || "draft",
    };
    if (tags) post.tags = tags.map((name) => ({ name }));
    if (excerpt) post.excerpt = excerpt;
    if (featured !== undefined) post.featured = featured;
    if (feature_image) post.feature_image = feature_image;
    if (feature_image_alt) post.feature_image_alt = feature_image_alt;
    if (published_at) post.published_at = published_at;
    if (slug) post.slug = slug;

    const data = await ghostFetch("/posts/", {
      method: "POST",
      query: { source: "html" },
      body: { posts: [post] },
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "ghost_update_post",
  "Update an existing blog post. You MUST provide the current updated_at value (from ghost_read_post) to prevent overwriting concurrent changes.",
  {
    id: z.string().describe("Post ID to update"),
    updated_at: z.string().describe("Current updated_at value from ghost_read_post (required for conflict prevention)"),
    title: z.string().optional().describe("New title"),
    html: z.string().optional().describe("New HTML content"),
    status: z.enum(["published", "draft", "scheduled"]).optional().describe("New status"),
    tags: z.array(z.string()).optional().describe("Replace tags (array of tag names)"),
    excerpt: z.string().optional().describe("New excerpt"),
    featured: z.boolean().optional().describe("Mark as featured"),
    feature_image: z.string().optional().describe("Feature image URL"),
    feature_image_alt: z.string().optional().describe("Alt text for feature image"),
    published_at: z.string().optional().describe("ISO 8601 datetime (for scheduling)"),
    slug: z.string().optional().describe("New URL slug"),
  },
  async ({ id, updated_at, title, html, status, tags, excerpt, featured, feature_image, feature_image_alt, published_at, slug }) => {
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

    const data = await ghostFetch(`/posts/${id}/`, {
      method: "PUT",
      query: { source: "html" },
      body: { posts: [post] },
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "ghost_delete_post",
  "Permanently delete a blog post. This cannot be undone. Use ghost_list_posts to find valid IDs.",
  {
    id: z.string().describe("Post ID to delete"),
  },
  async ({ id }) => {
    await ghostFetch(`/posts/${id}/`, { method: "DELETE" });
    return { content: [{ type: "text", text: `Post ${id} deleted successfully.` }] };
  }
);

// ── Page Mutation Tools ─────────────────────────────────────────────────────

server.tool(
  "ghost_create_page",
  "Create a new static page. Content should be HTML.",
  {
    title: z.string().describe("Page title"),
    html: z.string().describe("Page content as HTML"),
    status: z.enum(["published", "draft"]).optional().describe("Page status (default: draft)"),
    slug: z.string().optional().describe("Custom URL slug"),
    feature_image: z.string().optional().describe("Feature image URL"),
  },
  async ({ title, html, status, slug, feature_image }) => {
    const page: Record<string, unknown> = {
      title,
      html,
      status: status || "draft",
    };
    if (slug) page.slug = slug;
    if (feature_image) page.feature_image = feature_image;

    const data = await ghostFetch("/pages/", {
      method: "POST",
      query: { source: "html" },
      body: { pages: [page] },
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "ghost_update_page",
  "Update an existing static page. Requires updated_at from ghost_list_pages or a prior read.",
  {
    id: z.string().describe("Page ID to update"),
    updated_at: z.string().describe("Current updated_at value (required for conflict prevention)"),
    title: z.string().optional().describe("New title"),
    html: z.string().optional().describe("New HTML content"),
    status: z.enum(["published", "draft"]).optional().describe("New status"),
    slug: z.string().optional().describe("New URL slug"),
    feature_image: z.string().optional().describe("Feature image URL"),
  },
  async ({ id, updated_at, title, html, status, slug, feature_image }) => {
    const page: Record<string, unknown> = { updated_at };
    if (title) page.title = title;
    if (html) page.html = html;
    if (status) page.status = status;
    if (slug) page.slug = slug;
    if (feature_image !== undefined) page.feature_image = feature_image;

    const data = await ghostFetch(`/pages/${id}/`, {
      method: "PUT",
      query: { source: "html" },
      body: { pages: [page] },
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  "ghost_delete_page",
  "Permanently delete a static page. This cannot be undone.",
  {
    id: z.string().describe("Page ID to delete"),
  },
  async ({ id }) => {
    await ghostFetch(`/pages/${id}/`, { method: "DELETE" });
    return { content: [{ type: "text", text: `Page ${id} deleted successfully.` }] };
  }
);

// ── Tag Tools ───────────────────────────────────────────────────────────────

server.tool(
  "ghost_create_tag",
  "Create a new tag. Tags can also be auto-created when creating posts.",
  {
    name: z.string().describe("Tag name"),
    slug: z.string().optional().describe("URL slug (auto-generated from name if omitted)"),
    description: z.string().optional().describe("Tag description"),
  },
  async ({ name, slug, description }) => {
    const tag: Record<string, unknown> = { name };
    if (slug) tag.slug = slug;
    if (description) tag.description = description;

    const data = await ghostFetch("/tags/", {
      method: "POST",
      body: { tags: [tag] },
    });
    return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
  }
);

// ── Image Upload ────────────────────────────────────────────────────────────

server.tool(
  "ghost_upload_image",
  "Upload a local image file to Ghost. Returns the hosted URL that can be used in posts as feature_image or in HTML content.",
  {
    file_path: z.string().describe("Absolute path to the image file on disk"),
    purpose: z.enum(["image", "profile_image", "icon"]).optional().describe("Image purpose (default: image)"),
  },
  async ({ file_path, purpose }) => {
    const data = await ghostUpload("/images/upload/", file_path, purpose || "image");
    const images = data.images as Array<{ url: string }>;
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            { url: images[0].url, message: "Image uploaded successfully. Use this URL in feature_image or HTML content." },
            null,
            2
          ),
        },
      ],
    };
  }
);

// ── Start ───────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
