import { NextResponse, type NextRequest } from "next/server";

export const dynamic = "force-dynamic";

type RouteContext = {
  params: Promise<{ path?: string[] }> | { path?: string[] };
};

async function getPath(context: RouteContext): Promise<string> {
  const resolved = await Promise.resolve(context.params);
  const segments = resolved?.path || [];
  return Array.isArray(segments) ? segments.join("/") : "";
}

async function forwardRequest(request: NextRequest, context: RouteContext) {
  const path = await getPath(context);
  const backendBaseUrl = (
    process.env.LUMEN_AWS_BACKEND_URL || "http://127.0.0.1:8080"
  ).replace(/\/$/, "");
  const search = request.nextUrl.search || "";
  const targetUrl = `${backendBaseUrl}/${path}${search}`;

  const forwardHeaders = new Headers();

  const authHeader = request.headers.get("authorization");
  if (authHeader) {
    forwardHeaders.set("Authorization", authHeader);
  }

  const contentType = request.headers.get("content-type");
  if (contentType) {
    forwardHeaders.set("Content-Type", contentType);
  }

  const acceptHeader = request.headers.get("accept");
  if (acceptHeader) {
    forwardHeaders.set("Accept", acceptHeader);
  }

  // Inject backend internal API key for AWS zero-trust validation
  if (process.env.LUMEN_INTERNAL_API_KEY) {
    forwardHeaders.set("X-Lumen-Api-Key", process.env.LUMEN_INTERNAL_API_KEY);
  }

  let body: BodyInit | null = null;
  if (request.method !== "GET" && request.method !== "HEAD") {
    body = await request.arrayBuffer();
  }

  try {
    const upstreamResponse = await fetch(targetUrl, {
      method: request.method,
      headers: forwardHeaders,
      body,
      // @ts-expect-error duplex option for Node fetch with streaming body
      duplex: "half",
    });

    const responseHeaders = new Headers();
    upstreamResponse.headers.forEach((val, key) => {
      const lower = key.toLowerCase();
      if (!["transfer-encoding", "content-encoding"].includes(lower)) {
        responseHeaders.set(key, val);
      }
    });

    const responseBuffer = await upstreamResponse.arrayBuffer();
    return new NextResponse(responseBuffer, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
  } catch (error) {
    return NextResponse.json(
      {
        error: "Gateway proxy error",
        message:
          error instanceof Error
            ? error.message
            : "Failed to connect to backend",
      },
      { status: 502 },
    );
  }
}

export async function GET(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context);
}

export async function POST(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context);
}

export async function PUT(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context);
}

export async function DELETE(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context);
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context);
}

export async function HEAD(request: NextRequest, context: RouteContext) {
  return forwardRequest(request, context);
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Lumen-Api-Key",
    },
  });
}
