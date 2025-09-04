// SPDX-License-Identifier: MIT
// MCP stdio server (JavaScript CommonJS) to forward Amadeus API requests.
// Node 18+ recommended.
//
// npm i @modelcontextprotocol/sdk axios zod
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const axios = require("axios");
const dotenv = require("dotenv");
const { z } = require("zod");

// Load environment variables
dotenv.config();

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

function getEnvAuth() {
  const serviceName = process.env.AMADEUS_SERVICE_NAME || process.env.AMADEUS_ENV || "test";
  const apiKey = process.env.AMADEUS_API_KEY;
  const apiSecret = process.env.AMADEUS_API_SECRET;
  if (!apiKey || !apiSecret) {
    throw new Error("Missing AMADEUS_API_KEY or AMADEUS_API_SECRET in environment");
  }
  return { serviceName, apiKey, apiSecret };
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


function idProp(name) {
  const props = {};
  props[name] = { type: "string", minLength: 1 };
  return props;
}




// ---- MCP server ----
const server = new McpServer({
  name: "amadeus-proxy-mcp",
  version: "1.0.0",
});

/** *******************************
 * FLIGHTS: SEARCH, DATES, PRICING
 **********************************/

// /v2/shopping/flight-offers (GET)
// Schema based on Postman collection examples
const FlightOffersSearchSchema = {
  originLocationCode: z.string(),
  destinationLocationCode: z.string(),
  departureDate: z.string(), // YYYY-MM-DD
  returnDate: z.string().optional(),
  adults: z.union([z.number(), z.string()]),
  children: z.union([z.number(), z.string()]).optional(),
  infants: z.union([z.number(), z.string()]).optional(),
  travelClass: z.string().optional(),
  includedAirlineCodes: z.string().optional(),
  excludedAirlineCodes: z.string().optional(),
  nonStop: z.union([z.boolean(), z.string()]).optional(),
  currencyCode: z.string().optional(),
  max: z.union([z.number(), z.string()]).optional(),
  viewBy: z.enum(["DATE", "DURATION"]).optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v2.shopping.flight-offers",
  {
    title: "Amadeus: Flight Offers Search",
    description: "Search for available flight offers.",
    inputSchema: FlightOffersSearchSchema,
  },
  async (input) => {
    const { timeoutMs, ...query } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v2/shopping/flight-offers",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/flight-dates (GET)
const FlightDatesSchema = {
  originLocationCode: z.string(),
  destinationLocationCode: z.string(),
  departureDate: z.string().optional(), // YYYY-MM-DD or range "YYYY-MM-DD,YYYY-MM-DD"
  oneWay: z.union([z.boolean(), z.string()]).optional(),
  duration: z.union([z.number(), z.string()]).optional(),
  nonStop: z.union([z.boolean(), z.string()]).optional(),
  viewBy: z.enum(["DATE","DURATION"]).optional(),
  currencyCode: z.string().optional(),
  max: z.union([z.number(), z.string()]).optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
}

server.registerTool(
  "amadeus.v1.shopping.flight-dates",
  {
    title: "Amadeus: Flight Dates",
    description: "Search for the cheapest flight dates.",
    inputSchema: FlightDatesSchema,
  },
  async (input) => {
    const { timeoutMs, ...query } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/shopping/flight-dates",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/flight-offers/pricing (POST)
const FlightOffersPricingSchema = {
  flightOffers: z.array(z.any()), // array of flight offers from search response
  timeoutMs: z.number().int().positive().max(60000).default(15000),
}

server.registerTool(
  "amadeus.v1.shopping.flight-offers.pricing",
  {
    title: "Amadeus: Flight Offers Pricing",
    description: "Confirm pricing of a flight offer.",
    inputSchema: FlightOffersPricingSchema,
  },
  async (input) => {
    const { timeoutMs, flightOffers } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const body = {
      data: {
        type: "flight-offers-pricing",
        flightOffers: Array.isArray(flightOffers) ? flightOffers : [flightOffers],
      },
    };
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v1/shopping/flight-offers/pricing",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);


/** *******************************
 * FLIGHT ORDERS (BOOKING)
 **********************************/

// /v1/booking/flight-orders (POST)
const FlightOrderCreateSchema = {
  flightOffers: z.array(z.any()), // array of flight offers from search/pricing response
  travelers: z.array(z.any()), // array of travelers with personal details
  remarks: z.any().optional(),
  ticketingAgreement: z.any().optional(),
  contacts: z.any().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.booking.flight-orders",
  {
    title: "Amadeus: Flight Orders",
    description: "Create a new flight booking order.",
    inputSchema: FlightOrderCreateSchema,
  },
  async (input) => {
    const { timeoutMs, flightOffers, travelers, remarks, ticketingAgreement, contacts } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const body = {
      data: {
        type: "flight-order",
        flightOffers,
        travelers,
        ...(remarks ? { remarks } : {}),
        ...(ticketingAgreement ? { ticketingAgreement } : {}),
        ...(contacts ? { contacts } : {}),
      },
    };

    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v1/booking/flight-orders",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/booking/flight-orders/:flightOrderId (GET)
const FlightOrderByIdSchema = { flightOrderId: z.string().min(1), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.booking.flight-orders.by-id",
  {
    title: "Amadeus: Flight Order by ID",
    description: "Retrieve a specific flight booking order by ID.",
    inputSchema: FlightOrderByIdSchema,
  },
  async (input) => {
    const { timeoutMs, flightOrderId } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const path = `/v1/booking/flight-orders/${encodeURIComponent(flightOrderId)}`;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path,
      query: {},
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
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
    inputSchema: {
      // Either provide flight-orderId for GET seatmaps or provide flight offer(s) to POST
      flightOrderId: z.string().optional(),
      flightOffers: z.any().optional(),
      timeoutMs: z.number().int().positive().max(60000).default(15000),
    },
  },
  async (input) => {
    const { timeoutMs, flightOrderId, flightOffers } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    // If flightOrderId is provided, use GET with query param as per collection example
    if (typeof flightOrderId === "string" && flightOrderId.trim()) {
      const { payload, isError } = await forwardAmadeus({
        serviceName,
        apiKey,
        apiSecret,
        method: "GET",
        path: "/v1/shopping/seatmaps",
        query: { "flight-orderId": flightOrderId },
        body: undefined,
        headers: {},
        contentType: "application/json",
        timeoutMs,
      });
      return { content: [{ type: "text", text: payload }], isError };
    }

    // Otherwise expect flightOffers and POST body
    const flightOffersArray = Array.isArray(flightOffers) ? flightOffers : [flightOffers];
    const body = { data: flightOffersArray };
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v1/shopping/seatmaps",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v2/schedule/flights (GET)
server.registerTool(
  "amadeus.v2.schedule.flights",
  {
    title: "Amadeus: Schedules (Flights)",
    description: "Retrieve airline schedules for flights.",
    inputSchema: {
      carrierCode: z.string(),
      flightNumber: z.string(),
      scheduledDepartureDate: z.string(), // YYYY-MM-DD
      timeoutMs: z.number().int().positive().max(60000).default(15000),
    },
  },
  async (input) => {
    const { timeoutMs, ...query } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v2/schedule/flights",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);



/** *******************************
 * PREDICTIONS & ANALYTICS
 **********************************/

// /v1/travel/predictions/flight-delay (GET)
const FlightDelayPredictionSchema = {
  originLocationCode: z.string(),
  destinationLocationCode: z.string(),
  departureDate: z.string(), // YYYY-MM-DD
  departureTime: z.string().optional(), // HH:MM:SS
  arrivalDate: z.string().optional(), // YYYY-MM-DD
  arrivalTime: z.string().optional(), // HH:MM:SS
  aircraftCode: z.string().optional(),
  carrierCode: z.string().optional(),
  flightNumber: z.string().optional(),
  duration: z.string().optional(), // ISO 8601 e.g., PT2H
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.travel.predictions.flight-delay",
  {
    title: "Amadeus: Flight Delay Prediction",
    description: "Predict probability of a flight delay.",
    inputSchema: FlightDelayPredictionSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/travel/predictions/flight-delay",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/analytics/itinerary-price-metrics (GET)
const ItineraryPriceMetricsSchema = {
  originIataCode: z.string(),
  destinationIataCode: z.string(),
  departureDate: z.string(), // YYYY-MM-DD
  currencyCode: z.string().optional(),
  oneWay: z.union([z.boolean(), z.string()]).optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.analytics.itinerary-price-metrics",
  {
    title: "Amadeus: Itinerary Price Metrics",
    description: "Get itinerary price metrics.",
    inputSchema: ItineraryPriceMetricsSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/analytics/itinerary-price-metrics",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/flight-offers/upselling (POST)
const FlightOffersUpsellingSchema = {
  flightOffers: z.any(),
  payments: z.any().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.shopping.flight-offers.upselling",
  {
    title: "Amadeus: Flight Offers Upselling",
    description: "Find upsell offers for a flight.",
    inputSchema: FlightOffersUpsellingSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, flightOffers, payments } = input;
    const body = {
      data: {
        type: "flight-offers-upselling",
        flightOffers: Array.isArray(flightOffers) ? flightOffers : [flightOffers],
        ...(payments ? { payments } : {}),
      },
    };
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v1/shopping/flight-offers/upselling",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// Flight Offers Prediction (v2)
const FlightOffersPredictionSchema = {
  meta: {
    count: z.number().optional(),
    links: {
      self: z.string().optional()
    }
  },
  flightOffers: z.array(z.any()), // array of flight offers from search response
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v2.shopping.flight-offers.prediction",
  {
    title: "Amadeus: Flight Offers Prediction",
    description: "Get flight offers prediction based on search results.",
    inputSchema: FlightOffersPredictionSchema,
  },
  async (input) => {
    const { timeoutMs, meta, flightOffers } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    
    // Transform input to correct Amadeus format
    const body = {
      data: {
        meta,
        data: flightOffers
      }
    };
    
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v2/shopping/flight-offers/prediction",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/travel/predictions/trip-purpose (GET)
const TripPurposeSchema = { originLocationCode: z.string(), destinationLocationCode: z.string(), departureDate: z.string(), returnDate: z.string().optional(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.travel.predictions.trip-purpose",
  {
    title: "Amadeus: Trip Purpose Prediction",
    description: "Predict business vs leisure trip.",
    inputSchema: TripPurposeSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/travel/predictions/trip-purpose",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);


/** *******************************
 * SHOPPING: DESTINATIONS, AVAILABILITY
 **********************************/

// /v1/shopping/flight-destinations (GET)
const FlightDestinationsSchema = {
  origin: z.string(), // IATA code of departure city/airport (required)
  departureDate: z.string().optional(), // YYYY-MM-DD format
  oneWay: z.boolean().optional(),
  duration: z.number().optional(),
  nonStop: z.boolean().optional(),
  viewBy: z.enum(["DATE", "DURATION"]).optional(),
  maxPrice: z.number().optional(),
  currencyCode: z.string().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.shopping.flight-destinations",
  {
    title: "Amadeus: Flight Destinations",
    description: "Find the cheapest flight destinations from a specific origin with flexible search criteria including dates, duration, price limits, and viewing options.",
    inputSchema: FlightDestinationsSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/shopping/flight-destinations",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/availability/flight-availabilities (POST)
const FlightAvailabilitiesSchema = {
  // Origin Destination fields
  originDestinationId: z.string().optional(),
  originLocationCode: z.string().optional(),
  destinationLocationCode: z.string().optional(),
  departureDate: z.string().optional(), // YYYY-MM-DD format
  departureTime: z.string().optional(), // HH:MM:SS format
  arrivalDate: z.string().optional(), // YYYY-MM-DD format
  arrivalTime: z.string().optional(), // HH:MM:SS format
  
  // Traveler fields
  travelerId: z.string().optional(),
  travelerType: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  
  // Additional traveler fields for multiple travelers
  travelerId2: z.string().optional(),
  travelerType2: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  travelerId3: z.string().optional(),
  travelerType3: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  travelerId4: z.string().optional(),
  travelerType4: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  travelerId5: z.string().optional(),
  travelerType5: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  travelerId6: z.string().optional(),
  travelerType6: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  travelerId7: z.string().optional(),
  travelerType7: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  travelerId8: z.string().optional(),
  travelerType8: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  travelerId9: z.string().optional(),
  travelerType9: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional(),
  
  // Additional origin destination fields for multiple routes
  originDestinationId2: z.string().optional(),
  originLocationCode2: z.string().optional(),
  destinationLocationCode2: z.string().optional(),
  departureDate2: z.string().optional(),
  departureTime2: z.string().optional(),
  arrivalDate2: z.string().optional(),
  arrivalTime2: z.string().optional(),
  
  // API configuration
  sources: z.array(z.enum(["GDS", "LCC"])).optional(),
  currencyCode: z.string().optional(),
  maxFlightOffers: z.number().int().positive().optional(),
  excludedCarrierCodes: z.array(z.string()).optional(),
  includedCarrierCodes: z.array(z.string()).optional(),
  nonStopPreferred: z.boolean().optional(),
  airportChangeAllowed: z.boolean().optional(),
  technicalStopsAllowed: z.boolean().optional(),
  maxNumberOfConnections: z.number().int().min(0).optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.shopping.availability.flight-availabilities",
  {
    title: "Amadeus: Flight Availabilities",
    description: "Search for real-time flight availability with detailed search criteria including origin/destination, travelers, and filtering options.",
    inputSchema: FlightAvailabilitiesSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { 
      timeoutMs, 
      // Origin destination fields
      originDestinationId,
      originLocationCode,
      destinationLocationCode,
      departureDate,
      departureTime,
      arrivalDate,
      arrivalTime,
      // Second origin destination fields
      originDestinationId2,
      originLocationCode2,
      destinationLocationCode2,
      departureDate2,
      departureTime2,
      arrivalDate2,
      arrivalTime2,
      // Traveler fields
      travelerId,
      travelerType,
      travelerId2,
      travelerType2,
      travelerId3,
      travelerType3,
      travelerId4,
      travelerType4,
      travelerId5,
      travelerType5,
      travelerId6,
      travelerType6,
      travelerId7,
      travelerType7,
      travelerId8,
      travelerType8,
      travelerId9,
      travelerType9,
      // API configuration
      sources, 
      currencyCode,
      maxFlightOffers,
      excludedCarrierCodes,
      includedCarrierCodes,
      nonStopPreferred,
      airportChangeAllowed,
      technicalStopsAllowed,
      maxNumberOfConnections
    } = input;
    
    // Build originDestinations array
    const originDestinations = [];
    
    // First origin destination
    if (originLocationCode && destinationLocationCode) {
      const od = {
        id: originDestinationId || "1",
        originLocationCode,
        destinationLocationCode
      };
      
      if (departureDate) {
        od.departureDateTime = {
          date: departureDate,
          ...(departureTime ? { time: departureTime } : {})
        };
      }
      
      if (arrivalDate) {
        od.arrivalDateTime = {
          date: arrivalDate,
          ...(arrivalTime ? { time: arrivalTime } : {})
        };
      }
      
      originDestinations.push(od);
    }
    
    // Second origin destination
    if (originLocationCode2 && destinationLocationCode2) {
      const od2 = {
        id: originDestinationId2 || "2",
        originLocationCode: originLocationCode2,
        destinationLocationCode: destinationLocationCode2
      };
      
      if (departureDate2) {
        od2.departureDateTime = {
          date: departureDate2,
          ...(departureTime2 ? { time: departureTime2 } : {})
        };
      }
      
      if (arrivalDate2) {
        od2.arrivalDateTime = {
          date: arrivalDate2,
          ...(arrivalTime2 ? { time: arrivalTime2 } : {})
        };
      }
      
      originDestinations.push(od2);
    }
    
    // Build travelers array
    const travelers = [];
    const travelerFields = [
      { id: travelerId, type: travelerType },
      { id: travelerId2, type: travelerType2 },
      { id: travelerId3, type: travelerType3 },
      { id: travelerId4, type: travelerType4 },
      { id: travelerId5, type: travelerType5 },
      { id: travelerId6, type: travelerType6 },
      { id: travelerId7, type: travelerType7 },
      { id: travelerId8, type: travelerType8 },
      { id: travelerId9, type: travelerType9 }
    ];
    
    travelerFields.forEach((traveler, index) => {
      if (traveler.id && traveler.type) {
        travelers.push({
          id: traveler.id,
          travelerType: traveler.type
        });
      }
    });
    
    // Transform flat structure to correct API payload structure
    const body = {
      originDestinations,
      travelers,
      ...(sources ? { sources } : {}),
      ...(currencyCode ? { currencyCode } : {}),
    };

    // Build searchCriteria if any search parameters are provided
    const searchCriteria = {};
    if (maxFlightOffers) {
      searchCriteria.maxFlightOffers = maxFlightOffers;
    }

    // Build flightFilters if any filter parameters are provided
    const flightFilters = {};
    const carrierRestrictions = {};
    const connectionRestrictions = {};

    if (excludedCarrierCodes && excludedCarrierCodes.length > 0) {
      carrierRestrictions.excludedCarrierCodes = excludedCarrierCodes;
    }
    if (includedCarrierCodes && includedCarrierCodes.length > 0) {
      carrierRestrictions.includedCarrierCodes = includedCarrierCodes;
    }
    if (Object.keys(carrierRestrictions).length > 0) {
      flightFilters.carrierRestrictions = carrierRestrictions;
    }

    if (nonStopPreferred !== undefined) {
      connectionRestrictions.nonStopPreferred = nonStopPreferred;
    }
    if (airportChangeAllowed !== undefined) {
      connectionRestrictions.airportChangeAllowed = airportChangeAllowed;
    }
    if (technicalStopsAllowed !== undefined) {
      connectionRestrictions.technicalStopsAllowed = technicalStopsAllowed;
    }
    if (maxNumberOfConnections !== undefined) {
      connectionRestrictions.maxNumberOfConnections = maxNumberOfConnections;
    }
    if (Object.keys(connectionRestrictions).length > 0) {
      flightFilters.connectionRestrictions = connectionRestrictions;
    }

    if (Object.keys(flightFilters).length > 0) {
      searchCriteria.flightFilters = flightFilters;
    }

    if (Object.keys(searchCriteria).length > 0) {
      body.searchCriteria = searchCriteria;
    }
    
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v1/shopping/availability/flight-availabilities",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);


/** *******************************
 * REFERENCE DATA & AIRPORT
 **********************************/

// /v1/reference-data/recommended-locations (GET)
const RecommendedLocationsSchema = {
  cityCodes: z.string(), // comma-separated
  travelerCountryCode: z.string(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.reference-data.recommended-locations",
  {
    title: "Amadeus: Recommended Locations",
    description: "Recommended locations for a city.",
    inputSchema: RecommendedLocationsSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/recommended-locations",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/airport/predictions/on-time (GET)
const AirportOnTimePredictionSchema = {
  airportCode: z.string(),
  date: z.string(), // YYYY-MM-DD
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.airport.predictions.on-time",
  {
    title: "Amadeus: Airport On-Time Prediction",
    description: "Airport on-time performance prediction.",
    inputSchema: AirportOnTimePredictionSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/airport/predictions/on-time",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations (GET)
const LocationsSearchSchema = {
  keyword: z.string().optional(),
  subType: z.string().optional(), // e.g., CITY,AIRPORT
  countryCode: z.string().optional(), // ISO 3166-1 alpha-2 country code
  sort: z.string().optional(), // Sort by traveler traffic
  view: z.string().optional(), // LIGHT or FULL
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.reference-data.locations",
  {
    title: "Amadeus: Locations",
    description: "Search for cities and airports based on keyword, with optional filtering by country and sorting by traveler traffic.",
    inputSchema: LocationsSearchSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/locations",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/CMUC (GET)
const LocationByIdSchema = { locationId: z.string(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.reference-data.locations.by-id",
  {
    title: "Amadeus: Location by ID",
    description: "Details for a specific location ID.",
    inputSchema: LocationByIdSchema,
  },
  async (input) => {
    const { timeoutMs, locationId } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const path = `/v1/reference-data/locations/${encodeURIComponent(locationId)}`;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path,
      query: {},
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/airports (GET)
const AirportsByLocationSchema = { 
  latitude: z.union([z.number(), z.string()]), 
  longitude: z.union([z.number(), z.string()]), 
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.reference-data.locations.airports",
  {
    title: "Amadeus: Airports by Location",
    description: "Find airports near a specific latitude/longitude location.",
    inputSchema: AirportsByLocationSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, latitude, longitude } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/locations/airports",
      query: { latitude, longitude },
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/airport/direct-destinations (GET)
const AirportDirectDestinationsSchema = { 
  departureAirportCode: z.string(), 
  max: z.union([z.number(), z.string()]).optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.airport.direct-destinations",
  {
    title: "Amadeus: Airport Direct Destinations",
    description: "Direct destinations from an airport.",
    inputSchema: AirportDirectDestinationsSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, departureAirportCode } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/airport/direct-destinations",
      query: { departureAirportCode },
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v2/reference-data/urls/checkin-links (GET)
const CheckinLinksSchema = { airlineCode: z.string(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v2.reference-data.urls.checkin-links",
  {
    title: "Amadeus: Airline Check-in Links",
    description: "Airline check-in links.",
    inputSchema: CheckinLinksSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, airlineCode } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v2/reference-data/urls/checkin-links",
      query: { airlineCode },
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/airlines (GET)
const AirlinesSchema = { airlineCodes: z.string(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.reference-data.airlines",
  {
    title: "Amadeus: Airlines",
    description: "Airline information by code.",
    inputSchema: AirlinesSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, airlineCodes } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/airlines",
      query: { airlineCodes },
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/airline/destinations (GET)
const AirlineDestinationsSchema = { 
  airlineCode: z.string(), 
  max: z.union([z.number(), z.string()]).optional(),
  includeIndirect: z.union([z.boolean(), z.string()]).optional(), 
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.airline.destinations",
  {
    title: "Amadeus: Airline Destinations",
    description: "Destinations served by an airline.",
    inputSchema: AirlineDestinationsSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, airlineCode, includeIndirect } = input;
    const query = { airlineCode, ...(includeIndirect !== undefined ? { includeIndirect } : {}) };
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/airline/destinations",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

/** *******************************
 * ACTIVITIES
 **********************************/

// /v1/shopping/activities (GET)
const ActivitiesSearchSchema = { latitude: z.union([z.number(), z.string()]).optional(), longitude: z.union([z.number(), z.string()]).optional(), radius: z.union([z.number(), z.string()]).optional(), cityCode: z.string().optional(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.shopping.activities",
  {
    title: "Amadeus: Activities Search",
    description: "Search activities at a destination.",
    inputSchema: ActivitiesSearchSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/shopping/activities",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/activities/4615 (GET)
const ActivityByIdSchema = { activityId: z.string(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.shopping.activities.by-id",
  {
    title: "Amadeus: Activity by ID",
    description: "Retrieve a specific activity by ID.",
    inputSchema: ActivityByIdSchema,
  },
  async (input) => {
    const { timeoutMs, activityId } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const path = `/v1/shopping/activities/${encodeURIComponent(activityId)}`;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path,
      query: {},
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/shopping/activities/by-square (GET)
const ActivitiesBySquareSchema = { north: z.union([z.number(), z.string()]), south: z.union([z.number(), z.string()]), east: z.union([z.number(), z.string()]), west: z.union([z.number(), z.string()]), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.shopping.activities.by-square",
  {
    title: "Amadeus: Activities by Bounding Box",
    description: "Search activities by geographic bounding box.",
    inputSchema: ActivitiesBySquareSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/shopping/activities/by-square",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/cities (GET)
const CitiesSchema = { 
  keyword: z.string().optional(), 
  countryCode: z.string().optional(), 
  max: z.union([z.number(), z.string()]).optional(),
  include: z.string().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.reference-data.locations.cities",
  {
    title: "Amadeus: Cities",
    description: "Cities information.",
    inputSchema: CitiesSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/locations/cities",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

/** *******************************
 * TRANSFERS
 **********************************/

// /v1/shopping/transfer-offers (GET)
const TransferOffersSchema = {
  // follow the collection: POST with body
  startLocationCode: z.string().optional(),
  endAddressLine: z.string().optional(),
  endCityName: z.string().optional(),
  endZipCode: z.string().optional(),
  endCountryCode: z.string().optional(),
  endName: z.string().optional(),
  endGeoCode: z.string().optional(),
  transferType: z.string().optional(),
  startDateTime: z.string().optional(),
  passengers: z.union([z.number(), z.string()]).optional(),
  stopOvers: z.any().optional(),
  startConnectedSegment: z.any().optional(),
  endConnectedSegment: z.any().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.shopping.transfer-offers",
  {
    title: "Amadeus: Transfer Offers",
    description: "Search ground transfer offers.",
    inputSchema: TransferOffersSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...rest } = input;
    const body = { ...rest };
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v1/shopping/transfer-offers",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// Transfer Order Create
const TransferOrderCreateSchema = {
  offerId: z.string().min(1),
  note: z.string().optional(),
  passengers: z.array({
    firstName: z.string(),
    lastName: z.string(),
    title: z.string(),
    contacts: {
      phoneNumber: z.string().optional(),
      email: z.string().optional()
    },
    billingAddress: {
      line: z.string().optional(),
      zip: z.string().optional(),
      countryCode: z.string().optional(),
      cityName: z.string().optional()
    }
  }),
  agency: {
    contacts: z.array({
      email: {
        address: z.string().optional()
      }
    })
  },
  payment: {
    methodOfPayment: z.string().optional(),
    creditCard: {
      number: z.string().optional(),
      holderName: z.string().optional(),
      vendorCode: z.string().optional(),
      expiryDate: z.string().optional(),
      cvv: z.string().optional()
    }
  },
  extraServices: z.array({
    code: z.string().optional(),
    itemId: z.string().optional()
  }),
  equipment: z.array({
    code: z.string().optional()
  }),
  corporation: {
    address: {
      line: z.string().optional(),
      zip: z.string().optional(),
      countryCode: z.string().optional(),
      cityName: z.string().optional()
    },
    info: {
      AU: z.string().optional(),
      CE: z.string().optional()
    }
  },
  startConnectedSegment: {
    transportationType: z.string().optional(),
    transportationNumber: z.string().optional(),
    departure: {
      uicCode: z.string().optional(),
      iataCode: z.string().optional(),
      localDateTime: z.string().optional()
    },
    arrival: {
      uicCode: z.string().optional(),
      iataCode: z.string().optional(),
      localDateTime: z.string().optional()
    }
  },
  endConnectedSegment: {
    transportationType: z.string().optional(),
    transportationNumber: z.string().optional(),
    departure: {
      uicCode: z.string().optional(),
      iataCode: z.string().optional(),
      localDateTime: z.string().optional()
    },
    arrival: {
      uicCode: z.string().optional(),
      iataCode: z.string().optional(),
      localDateTime: z.string().optional()
    }
  },
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.ordering.transfer-orders",
  {
    title: "Amadeus: Transfer Order Create",
    description: "Create a new transfer order.",
    inputSchema: TransferOrderCreateSchema,
  },
  async (input) => {
    const { timeoutMs, offerId, ...transferData } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    
    // Transform input to correct Amadeus format
    const body = {
      data: transferData
    };
    
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: `/v1/ordering/transfer-orders?offerId=${encodeURIComponent(offerId)}`,
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/ordering/transfer-orders/:transferOrderId/transfers/cancellation (POST)
const TransferOrderCancellationSchema = { 
  transferOrderId: z.string().min(1), 
  confirmNbr: z.string().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.ordering.transfer-orders.cancellation",
  {
    title: "Amadeus: Cancel Transfer Order",
    description: "Cancel a transfer order.",
    inputSchema: TransferOrderCancellationSchema,
  },
  async (input) => {
    const { timeoutMs, transferOrderId, confirmNbr } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const path = `/v1/ordering/transfer-orders/${encodeURIComponent(transferOrderId)}/transfers/cancellation`;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path,
      query: { ...(confirmNbr ? { confirmNbr } : {}) },
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

/** *******************************
 * AIR TRAFFIC ANALYTICS
 **********************************/

// /v1/travel/analytics/air-traffic/traveled (GET)
const AirTrafficTraveledSchema = { 
  originCityCode: z.string(), 
  period: z.string(), 
  sort: z.string().optional(),
  max: z.union([z.number(), z.string()]).optional(),
  direction: z.string().optional(), 
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.travel.analytics.air-traffic.traveled",
  {
    title: "Amadeus: Air Traffic (Traveled)",
    description: "Air traffic analytics: traveled.",
    inputSchema: AirTrafficTraveledSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/travel/analytics/air-traffic/traveled",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/travel/analytics/air-traffic/booked (GET)
const AirTrafficBookedSchema = { 
  originCityCode: z.string(), 
  period: z.string(), 
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.travel.analytics.air-traffic.booked",
  {
    title: "Amadeus: Air Traffic (Booked)",
    description: "Air traffic analytics: booked.",
    inputSchema: AirTrafficBookedSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/travel/analytics/air-traffic/booked",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/travel/analytics/air-traffic/busiest-period (GET)
const AirTrafficBusiestPeriodSchema = { 
  cityCode: z.string().optional(), 
  period: z.string(), 
  direction: z.string().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.travel.analytics.air-traffic.busiest-period",
  {
    title: "Amadeus: Air Traffic (Busiest Period)",
    description: "Busiest travel period analytics.",
    inputSchema: AirTrafficBusiestPeriodSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/travel/analytics/air-traffic/busiest-period",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

/** *******************************
 * HOTELS
 **********************************/

// /v1/reference-data/locations/hotels/by-city (GET)
const HotelsByCitySchema = { cityCode: z.string(), radius: z.union([z.number(), z.string()]).optional(), radiusUnit: z.string().optional(), chainCodes: z.string().optional(), amenities: z.string().optional(), ratings: z.string().optional(), hotelSource: z.string().optional(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.reference-data.locations.hotels.by-city",
  {
    title: "Amadeus: Hotels by City",
    description: "List hotels by city.",
    inputSchema: HotelsByCitySchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/locations/hotels/by-city",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v3/shopping/hotel-offers (GET)
const HotelOffersSearchSchema = { hotelIds: z.string().optional(), cityCode: z.string().optional(), latitude: z.union([z.number(), z.string()]).optional(), longitude: z.union([z.number(), z.string()]).optional(), radius: z.union([z.number(), z.string()]).optional(), radiusUnit: z.string().optional(), checkInDate: z.string().optional(), checkOutDate: z.string().optional(), adults: z.union([z.number(), z.string()]).optional(), roomQuantity: z.union([z.number(), z.string()]).optional(), priceRange: z.string().optional(), currency: z.string().optional(), paymentPolicy: z.string().optional(), includeClosed: z.union([z.boolean(), z.string()]).optional(), bestRateOnly: z.union([z.boolean(), z.string()]).optional(), boardType: z.string().optional(), amenities: z.string().optional(), ratings: z.string().optional(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v3.shopping.hotel-offers",
  {
    title: "Amadeus: Hotel Offers",
    description: "Search hotel offers.",
    inputSchema: HotelOffersSearchSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v3/shopping/hotel-offers",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/booking/hotel-bookings (POST)
const HotelBookingSchema = {
  offerId: z.string(),
  guests: z.array({
    id: z.number(),
    name: {
      title: z.string(),
      firstName: z.string(),
      lastName: z.string()
    },
    contact: {
      phone: z.string().optional(),
      email: z.string().optional()
    }
  }),
  payments: z.array({
    id: z.number(),
    method: z.string(),
    card: {
      vendorCode: z.string(),
      cardNumber: z.string(),
      expiryDate: z.string()
    }
  }),
  rooms: z.array({
    guestIds: z.array(z.number()),
    paymentId: z.number(),
    specialRequest: z.string().optional()
  }),
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v1.booking.hotel-bookings",
  {
    title: "Amadeus: Hotel Booking",
    description: "Book a hotel room.",
    inputSchema: HotelBookingSchema,
  },
  async (input) => {
    const { timeoutMs, offerId, guests, payments, rooms } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    
    // Transform input to correct Amadeus format
    const body = {
      data: {
        offerId,
        guests,
        payments,
        rooms
      }
    };
    
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v1/booking/hotel-bookings",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/hotels/by-hotels (GET)
const HotelsByIdsSchema = { hotelIds: z.string(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.reference-data.locations.hotels.by-hotels",
  {
    title: "Amadeus: Hotels by IDs",
    description: "Hotel details by IDs.",
    inputSchema: HotelsByIdsSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, hotelIds } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/locations/hotels/by-hotels",
      query: { hotelIds },
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/hotels/by-geocode (GET)
const HotelsByGeocodeSchema = { latitude: z.union([z.number(), z.string()]), longitude: z.union([z.number(), z.string()]), radius: z.union([z.number(), z.string()]).optional(), radiusUnit: z.string().optional(), hotelSource: z.string().optional(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v1.reference-data.locations.hotels.by-geocode",
  {
    title: "Amadeus: Hotels by Geocode",
    description: "Hotels near coordinates.",
    inputSchema: HotelsByGeocodeSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/locations/hotels/by-geocode",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v3/shopping/hotel-offers/:hotelOfferId (GET)
const HotelOfferByIdSchema = { hotelOfferId: z.string(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v3.shopping.hotel-offers.by-id",
  {
    title: "Amadeus: Hotel Offer by ID",
    description: "Retrieve a specific hotel offer by ID.",
    inputSchema: HotelOfferByIdSchema,
  },
  async (input) => {
    const { timeoutMs, hotelOfferId } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const path = `/v3/shopping/hotel-offers/${encodeURIComponent(hotelOfferId)}`;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path,
      query: {},
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// Hotel Orders
const HotelOrdersSchema = {
  type: z.string(),
  guests: z.array({
    tid: z.number(),
    title: z.string(),
    firstName: z.string(),
    lastName: z.string(),
    phone: z.string().optional(),
    email: z.string().optional()
  }),
  travelAgent: {
    contact: {
      email: z.string().optional()
    }
  },
  roomAssociations: z.array({
    guestReferences: z.array({
      guestReference: z.string()
    }),
    hotelOfferId: z.string()
  }),
  payment: {
    method: z.string(),
    paymentCard: {
      paymentCardInfo: {
        vendorCode: z.string(),
        cardNumber: z.string(),
        expiryDate: z.string(),
        holderName: z.string()
      }
    }
  },
  timeoutMs: z.number().int().positive().max(60000).default(15000),
};

server.registerTool(
  "amadeus.v2.booking.hotel-orders",
  {
    title: "Amadeus: Hotel Orders",
    description: "Create/manage a hotel order.",
    inputSchema: HotelOrdersSchema,
  },
  async (input) => {
    const { timeoutMs, type, guests, travelAgent, roomAssociations, payment } = input;
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    
    // Transform input to correct Amadeus format
    const body = {
      data: {
        type,
        guests,
        travelAgent,
        roomAssociations,
        payment
      }
    };
    
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v2/booking/hotel-orders",
      query: {},
      body,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v2/e-reputation/hotel-sentiments (GET)
const HotelSentimentsSchema = { hotelIds: z.string(), timeoutMs: z.number().int().positive().max(60000).default(15000) };

server.registerTool(
  "amadeus.v2.e-reputation.hotel-sentiments",
  {
    title: "Amadeus: Hotel Sentiments",
    description: "Hotel review sentiment analysis.",
    inputSchema: HotelSentimentsSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, hotelIds } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v2/e-reputation/hotel-sentiments",
      query: { hotelIds },
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);

// /v1/reference-data/locations/hotel (GET)
const HotelLocationSchema = { 
  keyword: z.string().optional(), 
  hotelId: z.string().optional(),
  subType: z.string().optional(),
  timeoutMs: z.number().int().positive().max(60000).default(15000) 
};

server.registerTool(
  "amadeus.v1.reference-data.locations.hotel",
  {
    title: "Amadeus: Hotel Location",
    description: "Hotel location details.",
    inputSchema: HotelLocationSchema,
  },
  async (input) => {
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    const { timeoutMs, ...query } = input;
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "GET",
      path: "/v1/reference-data/locations/hotel",
      query,
      body: undefined,
      headers: {},
      contentType: "application/json",
      timeoutMs,
    });
    return { content: [{ type: "text", text: payload }], isError };
  }
);



// stdio transport
const transport = new StdioServerTransport();
server.connect(transport).catch((e) => {
  console.error("Failed to start MCP server:", e?.message || e);
  process.exit(1);
});
