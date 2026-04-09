// TrustLayer Demo — Cloudflare Worker Proxy
// Holds the Anthropic API key server-side.
// Receives requests from the demo UI and forwards to Anthropic API.
// CORS enabled for GitHub Pages deployment.

const ALLOWED_ORIGINS = [
  "https://govagentic.ai",
  "https://thedman.github.io",
  "https://davidamccrory.github.io"
];

function getAllowedOrigin(request) {
  const origin = request.headers.get("Origin");
  return ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
}

export default {
  async fetch(request, env) {

    const allowedOrigin = getAllowedOrigin(request);

    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": allowedOrigin,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    try {
      const body = await request.json();
      const { messages, tools, system } = body;

      if (!messages || !Array.isArray(messages)) {
        return new Response("Invalid request body", { status: 400 });
      }

      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": env.ANTHROPIC_API_KEY,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-haiku-4-5-20251001",
          max_tokens: 4096,
          system: system || "",
          tools: tools || [],
          messages,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        console.error("Anthropic API error:", error);
        return new Response("AI service error", {
          status: 502,
          headers: { "Access-Control-Allow-Origin": allowedOrigin }
        });
      }

      const data = await response.json();

      return new Response(JSON.stringify(data), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": allowedOrigin,
        },
      });

    } catch (err) {
      console.error("Worker error:", err);
      return new Response("Internal error", {
        status: 500,
        headers: { "Access-Control-Allow-Origin": allowedOrigin }
      });
    }
  }
};
