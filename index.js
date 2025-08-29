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

async function forwardAmadeus({
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
}) {
  const token = await getAmadeusToken({ apiKey, apiSecret, serviceName, timeoutMs });
  const url = `https://${serviceName}.api.amadeus.com${path}`;
  const response = await axios.request({
    method,
    url,
    params: query,
    data: body,
    headers: { ...headers, Authorization: `Bearer ${token}`, "Content-Type": contentType },
    timeout: timeoutMs,
    maxRedirects: 3,
    validateStatus: () => true, // pass through 4xx/5xx
  });
  const payload = typeof response.data === "string" ? response.data : JSON.stringify(response.data);
  return { payload, isError: response.status >= 400 };
}

function schemaWithParams(extraProps = {}, extraRequired = []) {
  return {
    type: "object",
    additionalProperties: true,
    properties: {
      serviceName: { type: "string", minLength: 2 },
      apiKey: { type: "string", minLength: 1 },
      apiSecret: { type: "string", minLength: 1 },
      method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
      query: { type: "object" },
      body: {},
      headers: { type: "object" },
      contentType: { type: "string" },
      timeoutMs: { type: "integer", minimum: 1, maximum: 60000 },
      ...extraProps,
    },
    required: ["serviceName", "apiKey", "apiSecret", "method", ...extraRequired],
  };
}

// ---- MCP server ----
const server = new McpServer({
  name: "amadeus-proxy-mcp",
  version: "1.0.0",
});

const RequestSchema = {
  serviceName: z.string().min(2, "serviceName is required"),
  apiKey: z.string().min(1, "apiKey is required"),
  apiSecret: z.string().min(1, "apiSecret is required"),
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
}


function ensureString(val, name) {
  if (typeof val !== "string" || val.trim() === "") {
    throw new Error(`${name} must be a non-empty string`);
  }
  return val;
}

function assertNoAuthHeader(headers) {
  if (!headers) return;
  const lower = {};
  for (const k of Object.keys(headers)) lower[k.toLowerCase()] = headers[k];
  if (Object.prototype.hasOwnProperty.call(lower, "authorization")) {
    throw new Error("Do not send Authorization; it will be set by the server.");
  }
}

function normalizeBase(input) {
  const serviceName = ensureString(input.serviceName, "serviceName"); // e.g., "test" | "production"
  const apiKey = ensureString(input.apiKey, "apiKey");
  const apiSecret = ensureString(input.apiSecret, "apiSecret");

  const query = input.query && typeof input.query === "object" ? input.query : {};
  const body = input.body === undefined ? undefined : input.body;
  const headers = input.headers && typeof input.headers === "object" ? input.headers : {};
  assertNoAuthHeader(headers);
  const contentType = typeof input.contentType === "string" ? input.contentType : "application/json";
  const timeoutMs = Number.isInteger(input.timeoutMs) ? input.timeoutMs : 15000;
  if (!(timeoutMs > 0 && timeoutMs <= 60000)) {
    throw new Error("timeoutMs must be a positive integer up to 60000");
  }
  return { serviceName, apiKey, apiSecret, query, body, headers, contentType, timeoutMs };
}


function simpleSchema(extraProps = {}, extraRequired = []) {
  return {
    serviceName: z.string().min(2, "serviceName is required"),
    apiKey: z.string().min(1, "apiKey is required"),
    apiSecret: z.string().min(1, "apiSecret is required"),
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
  };
}

function idProp(name) {
  const props = {};
  props[name] = { type: "string", minLength: 1 };
  return props;
}


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

/** *******************************
 * FLIGHTS: SEARCH, DATES, PRICING
 **********************************/

// /v2/shopping/flight-offers (GET)
server.registerTool(
  "amadeus.v2.shopping.flight-offers",
  {
    title: "Amadeus: Flight Offers Search",
    description: "Search for available flight offers.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v2/shopping/flight-offers" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/flight-dates (GET)
server.registerTool(
  "amadeus.v1.shopping.flight-dates",
  {
    title: "Amadeus: Flight Dates",
    description: "Search for the cheapest flight dates.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/shopping/flight-dates" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/flight-offers/pricing (POST)
server.registerTool(
  "amadeus.v1.shopping.flight-offers.pricing",
  {
    title: "Amadeus: Flight Offers Pricing",
    description: "Confirm pricing of a flight offer.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v1/shopping/flight-offers/pricing" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);


/** *******************************
 * FLIGHT ORDERS (BOOKING)
 **********************************/

// /v1/booking/flight-orders (POST)
server.registerTool(
  "amadeus.v1.booking.flight-orders",
  {
    title: "Amadeus: Flight Orders",
    description: "Create a new flight booking order.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v1/booking/flight-orders" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/booking/flight-orders/:flightOrderId (GET)
server.registerTool(
  "amadeus.v1.booking.flight-orders.by-id",
  {
    title: "Amadeus: Flight Order by ID",
    description: "Retrieve a specific flight booking order by ID.",
    inputSchema: simpleSchema(idProp("flightOrderId"), ["flightOrderId"]),
  },
  async (input) => {
    const args = normalizeBase(input);
    const flightOrderId = ensureString(input.flightOrderId, "flightOrderId");
    const path = `/v1/booking/flight-orders/${encodeURIComponent(flightOrderId)}`;
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path });
    return { content: [{ type: "text", text: payload }], isError };
  }
);


/** *******************************
 * SEATMAPS & SCHEDULES
 **********************************/

// /v1/shopping/seatmaps (POST — seatmaps commonly require POST with body)
server.registerTool(
  "amadeus.v1.shopping.seatmaps",
  {
    title: "Amadeus: Seatmaps",
    description: "Get seat maps for a flight offer.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v1/shopping/seatmaps" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v2/schedule/flights (GET)
server.registerTool(
  "amadeus.v2.schedule.flights",
  {
    title: "Amadeus: Schedules (Flights)",
    description: "Retrieve airline schedules for flights.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v2/schedule/flights" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);



/** *******************************
 * PREDICTIONS & ANALYTICS
 **********************************/

// /v1/travel/predictions/flight-delay (GET)
server.registerTool(
  "amadeus.v1.travel.predictions.flight-delay",
  {
    title: "Amadeus: Flight Delay Prediction",
    description: "Predict probability of a flight delay.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/travel/predictions/flight-delay" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/analytics/itinerary-price-metrics (GET)
server.registerTool(
  "amadeus.v1.analytics.itinerary-price-metrics",
  {
    title: "Amadeus: Itinerary Price Metrics",
    description: "Get itinerary price metrics.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/analytics/itinerary-price-metrics" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/flight-offers/upselling (POST)
server.registerTool(
  "amadeus.v1.shopping.flight-offers.upselling",
  {
    title: "Amadeus: Flight Offers Upselling",
    description: "Find upsell offers for a flight.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v1/shopping/flight-offers/upselling" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v2/shopping/flight-offers/prediction (POST)
server.registerTool(
  "amadeus.v2.shopping.flight-offers.prediction",
  {
    title: "Amadeus: Flight Offer Low-Price Prediction",
    description: "Predict if a flight offer is likely the lowest price.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v2/shopping/flight-offers/prediction" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/travel/predictions/trip-purpose (GET)
server.registerTool(
  "amadeus.v1.travel.predictions.trip-purpose",
  {
    title: "Amadeus: Trip Purpose Prediction",
    description: "Predict business vs leisure trip.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/travel/predictions/trip-purpose" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);


/** *******************************
 * SHOPPING: DESTINATIONS, AVAILABILITY
 **********************************/

// /v1/shopping/flight-destinations (GET)
server.registerTool(
  "amadeus.v1.shopping.flight-destinations",
  {
    title: "Amadeus: Flight Destinations",
    description: "Cheapest destinations from an origin.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/shopping/flight-destinations" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/availability/flight-availabilities (POST)
server.registerTool(
  "amadeus.v1.shopping.availability.flight-availabilities",
  {
    title: "Amadeus: Flight Availabilities",
    description: "Real-time seat availability.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v1/shopping/availability/flight-availabilities" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);


/** *******************************
 * REFERENCE DATA & AIRPORT
 **********************************/

// /v1/reference-data/recommended-locations (GET)
server.registerTool(
  "amadeus.v1.reference-data.recommended-locations",
  {
    title: "Amadeus: Recommended Locations",
    description: "Recommended locations for a city.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/recommended-locations" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/airport/predictions/on-time (GET)
server.registerTool(
  "amadeus.v1.airport.predictions.on-time",
  {
    title: "Amadeus: Airport On-Time Prediction",
    description: "Airport on-time performance prediction.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/airport/predictions/on-time" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations (GET)
server.registerTool(
  "amadeus.v1.reference-data.locations",
  {
    title: "Amadeus: Locations",
    description: "Search locations (cities/airports).",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/locations" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/CMUC (GET)
server.registerTool(
  "amadeus.v1.reference-data.locations.CMUC",
  {
    title: "Amadeus: Location by ID (CMUC)",
    description: "Details for a specific location ID.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/locations/CMUC" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/airports (GET)
server.registerTool(
  "amadeus.v1.reference-data.locations.airports",
  {
    title: "Amadeus: Airports by City",
    description: "Airports serving a city.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/locations/airports" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/airport/direct-destinations (GET)
server.registerTool(
  "amadeus.v1.airport.direct-destinations",
  {
    title: "Amadeus: Airport Direct Destinations",
    description: "Direct destinations from an airport.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/airport/direct-destinations" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v2/reference-data/urls/checkin-links (GET)
server.registerTool(
  "amadeus.v2.reference-data.urls.checkin-links",
  {
    title: "Amadeus: Airline Check-in Links",
    description: "Airline check-in links.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v2/reference-data/urls/checkin-links" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/airlines (GET)
server.registerTool(
  "amadeus.v1.reference-data.airlines",
  {
    title: "Amadeus: Airlines",
    description: "Airline information by code.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/airlines" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/airline/destinations (GET)
server.registerTool(
  "amadeus.v1.airline.destinations",
  {
    title: "Amadeus: Airline Destinations",
    description: "Destinations served by an airline.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/airline/destinations" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

/** *******************************
 * ACTIVITIES
 **********************************/

// /v1/shopping/activities (GET)
server.registerTool(
  "amadeus.v1.shopping.activities",
  {
    title: "Amadeus: Activities Search",
    description: "Search activities at a destination.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/shopping/activities" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/activities/4615 (GET)
server.registerTool(
  "amadeus.v1.shopping.activities.4615",
  {
    title: "Amadeus: Activity by ID (4615)",
    description: "Retrieve a specific activity by ID.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/shopping/activities/4615" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/activities/by-square (GET)
server.registerTool(
  "amadeus.v1.shopping.activities.by-square",
  {
    title: "Amadeus: Activities by Bounding Box",
    description: "Search activities by geographic bounding box.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/shopping/activities/by-square" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/cities (GET)
server.registerTool(
  "amadeus.v1.reference-data.locations.cities",
  {
    title: "Amadeus: Cities",
    description: "Cities information.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/locations/cities" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

/** *******************************
 * TRANSFERS
 **********************************/

// /v1/shopping/transfer-offers (GET)
server.registerTool(
  "amadeus.v1.shopping.transfer-offers",
  {
    title: "Amadeus: Transfer Offers",
    description: "Search ground transfer offers.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/shopping/transfer-offers" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/ordering/transfer-orders (POST)
server.registerTool(
  "amadeus.v1.ordering.transfer-orders",
  {
    title: "Amadeus: Transfer Orders",
    description: "Book a ground transfer order.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v1/ordering/transfer-orders" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/ordering/transfer-orders/:transferOrderId/transfers/cancellation (POST)
server.registerTool(
  "amadeus.v1.ordering.transfer-orders.cancellation",
  {
    title: "Amadeus: Cancel Transfer Order",
    description: "Cancel a transfer order.",
    inputSchema: simpleSchema(idProp("transferOrderId"), ["transferOrderId"]),
  },
  async (input) => {
    const args = normalizeBase(input);
    const transferOrderId = ensureString(input.transferOrderId, "transferOrderId");
    const path = `/v1/ordering/transfer-orders/${encodeURIComponent(transferOrderId)}/transfers/cancellation`;
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

/** *******************************
 * AIR TRAFFIC ANALYTICS
 **********************************/

// /v1/travel/analytics/air-traffic/traveled (GET)
server.registerTool(
  "amadeus.v1.travel.analytics.air-traffic.traveled",
  {
    title: "Amadeus: Air Traffic (Traveled)",
    description: "Air traffic analytics: traveled.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/travel/analytics/air-traffic/traveled" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/travel/analytics/air-traffic/booked (GET)
server.registerTool(
  "amadeus.v1.travel.analytics.air-traffic.booked",
  {
    title: "Amadeus: Air Traffic (Booked)",
    description: "Air traffic analytics: booked.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/travel/analytics/air-traffic/booked" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/travel/analytics/air-traffic/busiest-period (GET)
server.registerTool(
  "amadeus.v1.travel.analytics.air-traffic.busiest-period",
  {
    title: "Amadeus: Air Traffic (Busiest Period)",
    description: "Busiest travel period analytics.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/travel/analytics/air-traffic/busiest-period" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

/** *******************************
 * HOTELS
 **********************************/

// /v1/reference-data/locations/hotels/by-city (GET)
server.registerTool(
  "amadeus.v1.reference-data.locations.hotels.by-city",
  {
    title: "Amadeus: Hotels by City",
    description: "List hotels by city.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/locations/hotels/by-city" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v3/shopping/hotel-offers (GET)
server.registerTool(
  "amadeus.v3.shopping.hotel-offers",
  {
    title: "Amadeus: Hotel Offers",
    description: "Search hotel offers.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v3/shopping/hotel-offers" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/booking/hotel-bookings (POST)
server.registerTool(
  "amadeus.v1.booking.hotel-bookings",
  {
    title: "Amadeus: Hotel Bookings",
    description: "Book a hotel.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v1/booking/hotel-bookings" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/hotels/by-hotels (GET)
server.registerTool(
  "amadeus.v1.reference-data.locations.hotels.by-hotels",
  {
    title: "Amadeus: Hotels by IDs",
    description: "Hotel details by IDs.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/locations/hotels/by-hotels" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/hotels/by-geocode (GET)
server.registerTool(
  "amadeus.v1.reference-data.locations.hotels.by-geocode",
  {
    title: "Amadeus: Hotels by Geocode",
    description: "Hotels near coordinates.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/locations/hotels/by-geocode" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v3/shopping/hotel-offers/:hotelOfferId (GET)
server.registerTool(
  "amadeus.v3.shopping.hotel-offers.by-id",
  {
    title: "Amadeus: Hotel Offer by ID",
    description: "Retrieve a specific hotel offer by ID.",
    inputSchema: simpleSchema(idProp("hotelOfferId"), ["hotelOfferId"]),
  },
  async (input) => {
    const args = normalizeBase(input);
    const hotelOfferId = ensureString(input.hotelOfferId, "hotelOfferId");
    const path = `/v3/shopping/hotel-offers/${encodeURIComponent(hotelOfferId)}`;
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v2/booking/hotel-orders (POST)
server.registerTool(
  "amadeus.v2.booking.hotel-orders",
  {
    title: "Amadeus: Hotel Orders",
    description: "Create/manage a hotel order.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "POST", path: "/v2/booking/hotel-orders" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v2/e-reputation/hotel-sentiments (GET)
server.registerTool(
  "amadeus.v2.e-reputation.hotel-sentiments",
  {
    title: "Amadeus: Hotel Sentiments",
    description: "Hotel review sentiment analysis.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v2/e-reputation/hotel-sentiments" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/hotel (GET)
server.registerTool(
  "amadeus.v1.reference-data.locations.hotel",
  {
    title: "Amadeus: Hotel Location",
    description: "Hotel location details.",
    inputSchema: simpleSchema(),
  },
  async (input) => {
    const args = normalizeBase(input);
    const { payload, isError } = await forwardAmadeus({ ...args, method: "GET", path: "/v1/reference-data/locations/hotel" });
    return { content: [{ type: "text", text: payload }], isError };
  }
);



// stdio transport
const transport = new StdioServerTransport();
server.connect(transport).catch((e) => {
  console.error("Failed to start MCP server:", e?.message || e);
  process.exit(1);
});
