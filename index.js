// SPDX-License-Identifier: MIT
// MCP stdio server (JavaScript ESM) to forward Amadeus API requests.
// Node 18+ recommended.
//
// npm i @modelcontextprotocol/sdk axios zod

import axios from "axios";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const AMADEUS_TOKEN_PATH = "/v1/security/oauth2/token";

// ---- Allowlist (parity with your Express routes) ----
const ALLOWED_PATHS = new Set([
  "/v2/shopping/flight-offers",
  "/v1/shopping/flight-dates",
  "/v1/shopping/flight-offers/pricing",
  "/v1/booking/flight-orders",
  "/v1/booking/flight-orders/:flightOrderId",
  "/v1/shopping/seatmaps",
  "/v2/schedule/flights",
  "/v1/travel/predictions/flight-delay",
  "/v1/analytics/itinerary-price-metrics",
  "/v1/shopping/flight-offers/upselling",
  "/v2/shopping/flight-offers/prediction",
  "/v1/shopping/flight-destinations",
  "/v1/shopping/availability/flight-availabilities",
  "/v1/reference-data/recommended-locations",
  "/v1/airport/predictions/on-time",
  "/v1/reference-data/locations",
  "/v1/reference-data/locations/CMUC",
  "/v1/reference-data/locations/airports",
  "/v1/airport/direct-destinations",
  "/v2/reference-data/urls/checkin-links",
  "/v1/reference-data/airlines",
  "/v1/airline/destinations",
  "/v1/shopping/activities",
  "/v1/shopping/activities/4615",
  "/v1/shopping/activities/by-square",
  "/v1/reference-data/locations/cities",
  "/v1/shopping/transfer-offers",
  "/v1/ordering/transfer-orders",
  "/v1/ordering/transfer-orders/:transferOrderId/transfers/cancellation",
  "/v1/travel/analytics/air-traffic/traveled",
  "/v1/travel/analytics/air-traffic/booked",
  "/v1/travel/analytics/air-traffic/busiest-period",
  "/v1/security/oauth2/token",
  "/v1/reference-data/locations/hotels/by-city",
  "/v3/shopping/hotel-offers",
  "/v1/booking/hotel-bookings",
  "/v1/reference-data/locations/hotels/by-hotels",
  "/v1/reference-data/locations/hotels/by-geocode",
  "/v3/shopping/hotel-offers/:hotelOfferId",
  "/v2/booking/hotel-orders",
  "/v2/e-reputation/hotel-sentiments",
  "/v1/reference-data/locations/hotel",
  "/v1/travel/predictions/trip-purpose",
]);

function pathIsAllowed(requestPath) {
  if (ALLOWED_PATHS.has(requestPath)) return true;
  for (const p of ALLOWED_PATHS) {
    if (!p.includes(":")) continue;
    const regex = new RegExp(
      "^" +
        p
          .split("/")
          .map((seg) => (seg.startsWith(":") ? "[^/]+" : seg))
          .join("/") +
        "$"
    );
    if (regex.test(requestPath)) return true;
  }
  return false;
}

// ---- Auth (client credentials) ----
async function getAmadeusToken({ apiKey, apiSecret, serviceName, timeoutMs = 10000 }) {
  const tokenURL = `https://${serviceName}.api.amadeus.com${AMADEUS_TOKEN_PATH}`;
  const form = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: apiKey,
    client_secret: apiSecret,
  });
  try {
    const resp = await axios.post(tokenURL, form.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: timeoutMs,
    });
    if (!resp.data || !resp.data.access_token) {
      throw new Error("No access_token in Amadeus response");
    }
    return resp.data.access_token;
  } catch (e) {
    const detail = e?.response?.data ?? e?.message ?? "Failed to authenticate with Amadeus";
    throw new Error(
      `Amadeus auth error: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`
    );
  }
}

// ---- MCP server ----
const server = new McpServer({
  name: "amadeus-proxy-mcp",
  version: "1.0.0",
});

const RequestSchema = z.object({
  serviceName: z.string().min(2, "serviceName is required"),
  apiKey: z.string().min(1, "apiKey is required"),
  apiSecret: z.string().min(1, "apiSecret is required"),
  method: z
    .string()
    .transform((s) => s.toUpperCase())
    .refine((m) => ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(m), {
      message: "method must be one of GET, POST, PUT, PATCH, DELETE",
    }),
  path: z
    .string()
    .startsWith("/", "path must start with '/'")
    .refine(pathIsAllowed, "path is not allowed by server policy"),
  query: z.record(z.string(), z.any()).default({}),
  body: z.any().optional(),
  headers: z
    .record(z.string(), z.string())
    .default({})
    .refine((h) => {
      const lower = {};
      for (const k of Object.keys(h)) lower[k.toLowerCase()] = h[k];
      return !("authorization" in lower);
    }, "Do not send Authorization; it will be set by the server."),
  contentType: z.string().default("application/json"),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
});

server.registerTool(
  "amadeus.request",
  {
    title: "Forward an Amadeus API request",
    description:
      "Authenticates with Amadeus (OAuth2 client credentials) and forwards an HTTP request to a whitelisted Amadeus REST path.",
    inputSchema: RequestSchema,
  },
  async (input) => {
    const {
      serviceName,
      apiKey,
      apiSecret,
      method,
      path,
      query,
      body,
      headers,
      contentType,
      timeoutMs,
    } = RequestSchema.parse(input);

    const baseUrl = `https://${serviceName}.api.amadeus.com`;
    const token = await getAmadeusToken({ apiKey, apiSecret, serviceName, timeoutMs });
    const url = `${baseUrl}${path}`;

    try {
      const response = await axios.request({
        method,
        url,
        params: query,
        data: body,
        headers: {
          ...headers,
          Authorization: `Bearer ${token}`,
          "Content-Type": contentType,
        },
        timeout: timeoutMs,
        maxRedirects: 3,
        validateStatus: () => true, // surface 4xx/5xx in content
      });

      const payload =
        typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data);

      return {
        content: [{ type: "text", text: payload }],
        isError: response.status >= 400,
      };
    } catch (e) {
      const status = e?.response?.status ?? 500;
      const data = e?.response?.data ?? { error: e?.message || "Unknown error" };
      const text = typeof data === "string" ? data : JSON.stringify(data);
      return {
        content: [{ type: "text", text: `Forwarding error (${status}): ${text}` }],
        isError: true,
      };
    }
  }
);

// stdio transport
const transport = new StdioServerTransport();
server.connect(transport).catch((e) => {
  console.error("Failed to start MCP server:", e?.message || e);
  process.exit(1);
});