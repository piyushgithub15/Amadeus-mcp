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

// ---- Helper Functions ----

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
  // Core search parameters
  originLocationCode: z.string().describe("IATA code of the departure airport or city (e.g., 'NYC', 'LAX'). Required for flight search."),
  destinationLocationCode: z.string().describe("IATA code of the arrival airport or city (e.g., 'LHR', 'CDG'). Required for flight search."),
  departureDate: z.string().describe("Departure date in YYYY-MM-DD format. Required for flight search."),
  returnDate: z.string().optional().describe("Return date in YYYY-MM-DD format. Optional for round-trip searches."),
  
  // Passenger counts
  adults: z.number().describe("Number of adult passengers (12+ years). Required parameter for booking."),
  children: z.number().optional().describe("Number of child passengers (2-11 years). Optional parameter."),
  infants: z.number().optional().describe("Number of infant passengers (0-1 years). Optional parameter."),
  
  // Flight preferences
  travelClass: z.string().optional().describe("Travel class preference: 'ECONOMY', 'PREMIUM_ECONOMY', 'BUSINESS', 'FIRST'. Optional parameter."),
  includedAirlineCodes: z.string().optional().describe("Comma-separated list of airline codes to include in search (e.g., 'BA,AF'). Optional filter."),
  excludedAirlineCodes: z.string().optional().describe("Comma-separated list of airline codes to exclude from search (e.g., 'UA,DL'). Optional filter."),
  nonStop: z.boolean().optional().describe("If true, only return non-stop flights. Optional filter for direct flights only."),
  
  // Display and pricing options
  currencyCode: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Optional, defaults to USD."),
  max: z.number().optional().describe("Maximum number of results to return. Optional limit on search results."),
  viewBy: z.enum(["DATE", "DURATION"]).optional().describe("Sort results by 'DATE' (chronological) or 'DURATION' (shortest first). Optional sorting."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  // Core search parameters
  originLocationCode: z.string().describe("IATA code of the departure airport or city (e.g., 'NYC', 'LAX'). Required for date search."),
  destinationLocationCode: z.string().describe("IATA code of the arrival airport or city (e.g., 'LHR', 'CDG'). Required for date search."),
  departureDate: z.string().optional().describe("Departure date in YYYY-MM-DD format or date range as 'YYYY-MM-DD,YYYY-MM-DD'. Optional for flexible date search."),
  
  // Trip configuration
  oneWay: z.boolean().optional().describe("If true, search for one-way flights only. If false or omitted, includes round-trip options."),
  duration: z.number().optional().describe("Trip duration in days. Used to find return dates for round-trip searches."),
  
  // Flight preferences
  nonStop: z.boolean().optional().describe("If true, only return non-stop flights. Optional filter for direct flights only."),
  viewBy: z.enum(["DATE","DURATION"]).optional().describe("Sort results by 'DATE' (chronological) or 'DURATION' (shortest first). Optional sorting."),
  
  // Display and pricing options
  currencyCode: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Optional, defaults to USD."),
  max: z.number().optional().describe("Maximum number of results to return. Optional limit on search results."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  // Flight offer metadata (flattened from nested structure)
  flightOfferType: z.string().optional().describe("Type of flight offer, typically 'flight-offer'. Used to identify the offer structure."),
  flightOfferId: z.string().optional().describe("Unique identifier for the flight offer. Used to reference specific offers."),
  flightOfferSource: z.string().optional().describe("Source of the flight offer (e.g., 'GDS', 'LCC'). Indicates where the offer originated."),
  instantTicketingRequired: z.boolean().optional().describe("If true, the offer requires immediate ticketing. Used for time-sensitive bookings."),
  nonHomogeneous: z.boolean().optional().describe("If true, the offer contains mixed fare types. Used for complex pricing scenarios."),
  oneWay: z.boolean().optional().describe("If true, this is a one-way flight. Used to determine pricing structure."),
  isUpsellOffer: z.boolean().optional().describe("If true, this is an upsell offer. Used for premium upgrade options."),
  lastTicketingDate: z.string().optional().describe("Last date when this offer can be ticketed (YYYY-MM-DD). Used for booking deadlines."),
  numberOfBookableSeats: z.number().optional().describe("Number of seats available for booking. Used for availability checking."),
  
  // Itinerary information
  itineraryDuration: z.string().optional().describe("Total duration of the itinerary (e.g., 'PT2H30M'). Used for trip planning."),
  
  // Flight segment details (flattened from nested structure)
  segmentDepartureIataCode: z.string().optional().describe("IATA code of departure airport for the segment. Required for segment identification."),
  segmentDepartureTerminal: z.string().optional().describe("Terminal at departure airport. Used for airport navigation."),
  segmentDepartureAt: z.string().optional().describe("Departure time in ISO 8601 format. Used for scheduling."),
  segmentArrivalIataCode: z.string().optional().describe("IATA code of arrival airport for the segment. Required for segment identification."),
  segmentArrivalTerminal: z.string().optional().describe("Terminal at arrival airport. Used for airport navigation."),
  segmentArrivalAt: z.string().optional().describe("Arrival time in ISO 8601 format. Used for scheduling."),
  segmentCarrierCode: z.string().optional().describe("IATA code of the operating airline. Used for airline identification."),
  segmentNumber: z.string().optional().describe("Flight number for the segment. Used for flight identification."),
  segmentAircraftCode: z.string().optional().describe("IATA code of the aircraft type. Used for aircraft information."),
  segmentOperatingCarrierCode: z.string().optional().describe("IATA code of the actual operating carrier (for codeshare flights). Used for carrier identification."),
  segmentDuration: z.string().optional().describe("Duration of the segment (e.g., 'PT2H30M'). Used for flight planning."),
  segmentId: z.string().optional().describe("Unique identifier for the segment. Used for segment reference."),
  segmentNumberOfStops: z.number().optional().describe("Number of stops in the segment. Used for connection information."),
  segmentBlacklistedInEU: z.boolean().optional().describe("If true, segment is blacklisted in EU. Used for regulatory compliance."),
  
  // Pricing information
  priceCurrency: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Used for price display."),
  priceTotal: z.string().optional().describe("Total price including all taxes and fees. Used for final pricing."),
  priceBase: z.string().optional().describe("Base fare price before taxes and fees. Used for fare breakdown."),
  priceGrandTotal: z.string().optional().describe("Grand total price including all charges. Used for final pricing."),
  
  // Pricing options and preferences
  pricingOptionsFareType: z.string().optional().describe("Type of fare (e.g., 'PUBLISHED', 'NEGOTIATED'). Used for fare classification."),
  pricingOptionsIncludedCheckedBagsOnly: z.boolean().optional().describe("If true, only include checked bags in pricing. Used for baggage pricing."),
  
  // Airline validation
  validatingAirlineCodes: z.string().optional().describe("Comma-separated list of validating airline codes. Used for fare validation."),
  
  // Traveler-specific pricing (flattened from nested structure)
  travelerPricingTravelerId: z.string().optional().describe("Unique identifier for the traveler. Used for traveler-specific pricing."),
  travelerPricingFareOption: z.string().optional().describe("Fare option for the traveler. Used for fare selection."),
  travelerPricingTravelerType: z.string().optional().describe("Type of traveler (e.g., 'ADULT', 'CHILD', 'INFANT'). Used for age-based pricing."),
  travelerPricingPriceCurrency: z.string().optional().describe("Currency for traveler-specific pricing. Used for individual pricing."),
  travelerPricingPriceTotal: z.string().optional().describe("Total price for this traveler. Used for individual pricing."),
  travelerPricingPriceBase: z.string().optional().describe("Base price for this traveler. Used for individual fare breakdown."),
  
  // Fare details by segment (flattened from nested structure)
  fareDetailsSegmentId: z.string().optional().describe("Segment ID for fare details. Used to link fare details to specific segments."),
  fareDetailsCabin: z.string().optional().describe("Cabin class for the fare (e.g., 'ECONOMY', 'BUSINESS'). Used for cabin-specific pricing."),
  fareDetailsFareBasis: z.string().optional().describe("Fare basis code for the segment. Used for fare identification."),
  fareDetailsBrandedFare: z.string().optional().describe("Branded fare identifier. Used for branded fare pricing."),
  fareDetailsClass: z.string().optional().describe("Booking class for the segment. Used for class-specific pricing."),
  fareDetailsIncludedCheckedBagsQuantity: z.number().optional().describe("Number of included checked bags. Used for baggage allowance."),
  fareDetailsIncludedCabinBagsQuantity: z.number().optional().describe("Number of included cabin bags. Used for baggage allowance."),
  
  // API configuration parameters
  include: z.string().optional().describe("Comma-separated values: 'detailed-fare-rules', 'credit-card-fees', 'bags', 'other-services'. Used to include additional pricing details."),
  forceClass: z.boolean().optional().describe("Force usage of specific booking class. Used for class-specific pricing requests."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
}

server.registerTool(
  "amadeus.v1.shopping.flight-offers.pricing",
  {
    title: "Amadeus: Flight Offers Pricing",
    description: "Confirm pricing of flight offers obtained from search results. Returns detailed pricing information including taxes, fees, and ancillary services. Use flight offers from the flight search API as input.",
    inputSchema: FlightOffersPricingSchema,
  },
  async (input) => {
    const { 
      timeoutMs, 
      include, 
      forceClass,
      // Flight offer data
      flightOfferType,
      flightOfferId,
      flightOfferSource,
      instantTicketingRequired,
      nonHomogeneous,
      oneWay,
      isUpsellOffer,
      lastTicketingDate,
      numberOfBookableSeats,
      // Itinerary data
      itineraryDuration,
      // Segment data
      segmentDepartureIataCode,
      segmentDepartureTerminal,
      segmentDepartureAt,
      segmentArrivalIataCode,
      segmentArrivalTerminal,
      segmentArrivalAt,
      segmentCarrierCode,
      segmentNumber,
      segmentAircraftCode,
      segmentOperatingCarrierCode,
      segmentDuration,
      segmentId,
      segmentNumberOfStops,
      segmentBlacklistedInEU,
      // Price data
      priceCurrency,
      priceTotal,
      priceBase,
      priceGrandTotal,
      // Pricing options
      pricingOptionsFareType,
      pricingOptionsIncludedCheckedBagsOnly,
      // Validating airline codes
      validatingAirlineCodes,
      // Traveler pricing data
      travelerPricingTravelerId,
      travelerPricingFareOption,
      travelerPricingTravelerType,
      travelerPricingPriceCurrency,
      travelerPricingPriceTotal,
      travelerPricingPriceBase,
      // Fare details by segment
      fareDetailsSegmentId,
      fareDetailsCabin,
      fareDetailsFareBasis,
      fareDetailsBrandedFare,
      fareDetailsClass,
      fareDetailsIncludedCheckedBagsQuantity,
      fareDetailsIncludedCabinBagsQuantity
    } = input;
    
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    
    // Build query parameters
    const query = {};
    if (include) {
      query.include = include;
    }
    if (forceClass !== undefined) {
      query.forceClass = forceClass;
    }
    
    // Transform flat input to nested API format
    const flightOffer = {};
    
    if (flightOfferType) flightOffer.type = flightOfferType;
    if (flightOfferId) flightOffer.id = flightOfferId;
    if (flightOfferSource) flightOffer.source = flightOfferSource;
    if (instantTicketingRequired !== undefined) flightOffer.instantTicketingRequired = instantTicketingRequired;
    if (nonHomogeneous !== undefined) flightOffer.nonHomogeneous = nonHomogeneous;
    if (oneWay !== undefined) flightOffer.oneWay = oneWay;
    if (isUpsellOffer !== undefined) flightOffer.isUpsellOffer = isUpsellOffer;
    if (lastTicketingDate) flightOffer.lastTicketingDate = lastTicketingDate;
    if (numberOfBookableSeats !== undefined) flightOffer.numberOfBookableSeats = numberOfBookableSeats;
    
    // Build itinerary if segment data is provided
    if (segmentDepartureIataCode && segmentArrivalIataCode) {
      const segment = {
        departure: {
          iataCode: segmentDepartureIataCode
        },
        arrival: {
          iataCode: segmentArrivalIataCode
        },
        carrierCode: segmentCarrierCode,
        number: segmentNumber,
        duration: segmentDuration,
        id: segmentId,
        numberOfStops: segmentNumberOfStops || 0
      };
      
      if (segmentDepartureTerminal) segment.departure.terminal = segmentDepartureTerminal;
      if (segmentDepartureAt) segment.departure.at = segmentDepartureAt;
      if (segmentArrivalTerminal) segment.arrival.terminal = segmentArrivalTerminal;
      if (segmentArrivalAt) segment.arrival.at = segmentArrivalAt;
      if (segmentAircraftCode) segment.aircraft = { code: segmentAircraftCode };
      if (segmentOperatingCarrierCode) segment.operating = { carrierCode: segmentOperatingCarrierCode };
      if (segmentBlacklistedInEU !== undefined) segment.blacklistedInEU = segmentBlacklistedInEU;
      
      flightOffer.itineraries = [{
        duration: itineraryDuration || segmentDuration,
        segments: [segment]
      }];
    }
    
    // Build price if provided
    if (priceCurrency && priceTotal) {
      flightOffer.price = {
        currency: priceCurrency,
        total: priceTotal,
        base: priceBase || priceTotal
      };
      if (priceGrandTotal) flightOffer.price.grandTotal = priceGrandTotal;
    }
    
    // Build pricing options if provided
    if (pricingOptionsFareType || pricingOptionsIncludedCheckedBagsOnly !== undefined) {
      flightOffer.pricingOptions = {};
      if (pricingOptionsFareType) flightOffer.pricingOptions.fareType = [pricingOptionsFareType];
      if (pricingOptionsIncludedCheckedBagsOnly !== undefined) flightOffer.pricingOptions.includedCheckedBagsOnly = pricingOptionsIncludedCheckedBagsOnly;
    }
    
    // Build validating airline codes if provided
    if (validatingAirlineCodes) {
      flightOffer.validatingAirlineCodes = validatingAirlineCodes.split(',').map(code => code.trim());
    }
    
    // Build traveler pricing if provided
    if (travelerPricingTravelerId && travelerPricingTravelerType) {
      const travelerPricing = {
        travelerId: travelerPricingTravelerId,
        travelerType: travelerPricingTravelerType
      };
      
      if (travelerPricingFareOption) travelerPricing.fareOption = travelerPricingFareOption;
      if (travelerPricingPriceCurrency && travelerPricingPriceTotal) {
        travelerPricing.price = {
          currency: travelerPricingPriceCurrency,
          total: travelerPricingPriceTotal,
          base: travelerPricingPriceBase || travelerPricingPriceTotal
        };
      }
      
      // Build fare details by segment if provided
      if (fareDetailsSegmentId) {
        const fareDetails = {
          segmentId: fareDetailsSegmentId
        };
        
        if (fareDetailsCabin) fareDetails.cabin = fareDetailsCabin;
        if (fareDetailsFareBasis) fareDetails.fareBasis = fareDetailsFareBasis;
        if (fareDetailsBrandedFare) fareDetails.brandedFare = fareDetailsBrandedFare;
        if (fareDetailsClass) fareDetails.class = fareDetailsClass;
        if (fareDetailsIncludedCheckedBagsQuantity !== undefined) {
          fareDetails.includedCheckedBags = { quantity: fareDetailsIncludedCheckedBagsQuantity };
        }
        if (fareDetailsIncludedCabinBagsQuantity !== undefined) {
          fareDetails.includedCabinBags = { quantity: fareDetailsIncludedCabinBagsQuantity };
        }
        
        travelerPricing.fareDetailsBySegment = [fareDetails];
      }
      
      flightOffer.travelerPricings = [travelerPricing];
    }
    
    const body = {
      data: {
        type: "flight-offers-pricing",
        flightOffers: [flightOffer]
      },
    };
    
    const { payload, isError } = await forwardAmadeus({
      serviceName,
      apiKey,
      apiSecret,
      method: "POST",
      path: "/v1/shopping/flight-offers/pricing",
      query,
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
  // Flight offer metadata (flattened from nested structure)
  flightOfferType: z.string().optional().describe("Type of flight offer, typically 'flight-offer'. Used to identify the offer structure."),
  flightOfferId: z.string().optional().describe("Unique identifier for the flight offer. Used to reference specific offers."),
  flightOfferSource: z.string().optional().describe("Source of the flight offer (e.g., 'GDS', 'LCC'). Indicates where the offer originated."),
  instantTicketingRequired: z.boolean().optional().describe("If true, the offer requires immediate ticketing. Used for time-sensitive bookings."),
  nonHomogeneous: z.boolean().optional().describe("If true, the offer contains mixed fare types. Used for complex pricing scenarios."),
  oneWay: z.boolean().optional().describe("If true, this is a one-way flight. Used to determine pricing structure."),
  isUpsellOffer: z.boolean().optional().describe("If true, this is an upsell offer. Used for premium upgrade options."),
  lastTicketingDate: z.string().optional().describe("Last date when this offer can be ticketed (YYYY-MM-DD). Used for booking deadlines."),
  numberOfBookableSeats: z.number().optional().describe("Number of seats available for booking. Used for availability checking."),
  
  // Itinerary information
  itineraryDuration: z.string().optional().describe("Total duration of the itinerary (e.g., 'PT2H30M'). Used for trip planning."),
  
  // Flight segment details (flattened from nested structure)
  segmentDepartureIataCode: z.string().optional().describe("IATA code of departure airport for the segment. Required for segment identification."),
  segmentDepartureTerminal: z.string().optional().describe("Terminal at departure airport. Used for airport navigation."),
  segmentDepartureAt: z.string().optional().describe("Departure time in ISO 8601 format. Used for scheduling."),
  segmentArrivalIataCode: z.string().optional().describe("IATA code of arrival airport for the segment. Required for segment identification."),
  segmentArrivalTerminal: z.string().optional().describe("Terminal at arrival airport. Used for airport navigation."),
  segmentArrivalAt: z.string().optional().describe("Arrival time in ISO 8601 format. Used for scheduling."),
  segmentCarrierCode: z.string().optional().describe("IATA code of the operating airline. Used for airline identification."),
  segmentNumber: z.string().optional().describe("Flight number for the segment. Used for flight identification."),
  segmentAircraftCode: z.string().optional().describe("IATA code of the aircraft type. Used for aircraft information."),
  segmentOperatingCarrierCode: z.string().optional().describe("IATA code of the actual operating carrier (for codeshare flights). Used for carrier identification."),
  segmentDuration: z.string().optional().describe("Duration of the segment (e.g., 'PT2H30M'). Used for flight planning."),
  segmentId: z.string().optional().describe("Unique identifier for the segment. Used for segment reference."),
  segmentNumberOfStops: z.number().optional().describe("Number of stops in the segment. Used for connection information."),
  segmentBlacklistedInEU: z.boolean().optional().describe("If true, segment is blacklisted in EU. Used for regulatory compliance."),
  
  // Pricing information
  priceCurrency: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Used for price display."),
  priceTotal: z.string().optional().describe("Total price including all taxes and fees. Used for final pricing."),
  priceBase: z.string().optional().describe("Base fare price before taxes and fees. Used for fare breakdown."),
  priceGrandTotal: z.string().optional().describe("Grand total price including all charges. Used for final pricing."),
  
  // Traveler information (flattened from nested structure)
  travelerId: z.string().optional().describe("Unique identifier for the traveler. Used for traveler identification."),
  travelerDateOfBirth: z.string().optional().describe("Traveler's date of birth in YYYY-MM-DD format. Required for age verification."),
  travelerGender: z.string().optional().describe("Traveler's gender ('MALE', 'FEMALE', 'OTHER'). Used for passenger information."),
  travelerFirstName: z.string().optional().describe("Traveler's first name. Required for booking and identification."),
  travelerLastName: z.string().optional().describe("Traveler's last name. Required for booking and identification."),
  travelerPhoneNumber: z.string().optional().describe("Traveler's phone number. Used for contact information."),
  travelerEmail: z.string().optional().describe("Traveler's email address. Used for contact and booking confirmation."),
  
  // Travel document information (flattened from nested structure)
  documentType: z.string().optional().describe("Type of travel document ('PASSPORT', 'ID_CARD', 'VISA'). Required for international travel."),
  documentNumber: z.string().optional().describe("Document number. Required for travel document verification."),
  documentExpiryDate: z.string().optional().describe("Document expiry date in YYYY-MM-DD format. Required for document validation."),
  documentIssuanceCountry: z.string().optional().describe("Country code where the document was issued. Required for document validation."),
  documentValidityCountry: z.string().optional().describe("Country code where the document is valid. Used for document validation."),
  documentNationality: z.string().optional().describe("Nationality of the document holder. Used for passenger information."),
  documentHolder: z.boolean().optional().describe("If true, this traveler is the document holder. Used for document association."),
  
  // Billing address information (flattened from nested structure)
  billingAddressLine: z.string().optional().describe("Billing address line. Used for payment processing."),
  billingAddressZip: z.string().optional().describe("Billing address postal code. Used for payment processing."),
  billingAddressCountryCode: z.string().optional().describe("Billing address country code. Used for payment processing."),
  billingAddressCityName: z.string().optional().describe("Billing address city name. Used for payment processing."),
  
  // Booking remarks (flattened from nested structure)
  remarksGeneralSubType: z.string().optional().describe("Subtype of general remarks. Used for special requests."),
  remarksGeneralText: z.string().optional().describe("General remarks text. Used for special requests and notes."),
  
  // Ticketing agreement (flattened from nested structure)
  ticketingAgreementOption: z.string().optional().describe("Ticketing agreement option. Used for ticketing terms."),
  ticketingAgreementDelay: z.string().optional().describe("Ticketing agreement delay period. Used for ticketing terms."),
  
  // Contact information (flattened from nested structure)
  contactAddresseeFirstName: z.string().optional().describe("Contact person's first name. Used for booking contact."),
  contactAddresseeLastName: z.string().optional().describe("Contact person's last name. Used for booking contact."),
  contactCompanyName: z.string().optional().describe("Contact person's company name. Used for business bookings."),
  contactPurpose: z.string().optional().describe("Purpose of the contact. Used for contact classification."),
  contactPhoneDeviceType: z.string().optional().describe("Type of phone device ('MOBILE', 'LANDLINE'). Used for contact information."),
  contactPhoneCountryCallingCode: z.string().optional().describe("Country calling code for phone number. Used for international contact."),
  contactPhoneNumber: z.string().optional().describe("Contact phone number. Used for booking contact."),
  contactEmail: z.string().optional().describe("Contact email address. Used for booking contact."),
  contactAddressLines: z.string().optional().describe("Contact address lines (comma-separated). Used for contact information."),
  contactAddressPostalCode: z.string().optional().describe("Contact address postal code. Used for contact information."),
  contactAddressCityName: z.string().optional().describe("Contact address city name. Used for contact information."),
  contactAddressCountryCode: z.string().optional().describe("Contact address country code. Used for contact information."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
};

server.registerTool(
  "amadeus.v1.booking.flight-orders",
  {
    title: "Amadeus: Flight Orders",
    description: "Create a new flight booking order.",
    inputSchema: FlightOrderCreateSchema,
  },
  async (input) => {
    const { 
      timeoutMs,
      // Flight offer data
      flightOfferType,
      flightOfferId,
      flightOfferSource,
      instantTicketingRequired,
      nonHomogeneous,
      oneWay,
      isUpsellOffer,
      lastTicketingDate,
      numberOfBookableSeats,
      // Itinerary data
      itineraryDuration,
      // Segment data
      segmentDepartureIataCode,
      segmentDepartureTerminal,
      segmentDepartureAt,
      segmentArrivalIataCode,
      segmentArrivalTerminal,
      segmentArrivalAt,
      segmentCarrierCode,
      segmentNumber,
      segmentAircraftCode,
      segmentOperatingCarrierCode,
      segmentDuration,
      segmentId,
      segmentNumberOfStops,
      segmentBlacklistedInEU,
      // Price data
      priceCurrency,
      priceTotal,
      priceBase,
      priceGrandTotal,
      // Traveler data
      travelerId,
      travelerDateOfBirth,
      travelerGender,
      travelerFirstName,
      travelerLastName,
      travelerPhoneNumber,
      travelerEmail,
      // Document data
      documentType,
      documentNumber,
      documentExpiryDate,
      documentIssuanceCountry,
      documentValidityCountry,
      documentNationality,
      documentHolder,
      // Billing address
      billingAddressLine,
      billingAddressZip,
      billingAddressCountryCode,
      billingAddressCityName,
      // Remarks
      remarksGeneralSubType,
      remarksGeneralText,
      // Ticketing agreement
      ticketingAgreementOption,
      ticketingAgreementDelay,
      // Contacts
      contactAddresseeFirstName,
      contactAddresseeLastName,
      contactCompanyName,
      contactPurpose,
      contactPhoneDeviceType,
      contactPhoneCountryCallingCode,
      contactPhoneNumber,
      contactEmail,
      contactAddressLines,
      contactAddressPostalCode,
      contactAddressCityName,
      contactAddressCountryCode
    } = input;
    
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    
    // Transform flat input to nested API format
    const flightOffer = {};
    
    if (flightOfferType) flightOffer.type = flightOfferType;
    if (flightOfferId) flightOffer.id = flightOfferId;
    if (flightOfferSource) flightOffer.source = flightOfferSource;
    if (instantTicketingRequired !== undefined) flightOffer.instantTicketingRequired = instantTicketingRequired;
    if (nonHomogeneous !== undefined) flightOffer.nonHomogeneous = nonHomogeneous;
    if (oneWay !== undefined) flightOffer.oneWay = oneWay;
    if (isUpsellOffer !== undefined) flightOffer.isUpsellOffer = isUpsellOffer;
    if (lastTicketingDate) flightOffer.lastTicketingDate = lastTicketingDate;
    if (numberOfBookableSeats !== undefined) flightOffer.numberOfBookableSeats = numberOfBookableSeats;
    
    // Build itinerary if segment data is provided
    if (segmentDepartureIataCode && segmentArrivalIataCode) {
      const segment = {
        departure: {
          iataCode: segmentDepartureIataCode
        },
        arrival: {
          iataCode: segmentArrivalIataCode
        },
        carrierCode: segmentCarrierCode,
        number: segmentNumber,
        duration: segmentDuration,
        id: segmentId,
        numberOfStops: segmentNumberOfStops || 0
      };
      
      if (segmentDepartureTerminal) segment.departure.terminal = segmentDepartureTerminal;
      if (segmentDepartureAt) segment.departure.at = segmentDepartureAt;
      if (segmentArrivalTerminal) segment.arrival.terminal = segmentArrivalTerminal;
      if (segmentArrivalAt) segment.arrival.at = segmentArrivalAt;
      if (segmentAircraftCode) segment.aircraft = { code: segmentAircraftCode };
      if (segmentOperatingCarrierCode) segment.operating = { carrierCode: segmentOperatingCarrierCode };
      if (segmentBlacklistedInEU !== undefined) segment.blacklistedInEU = segmentBlacklistedInEU;
      
      flightOffer.itineraries = [{
        duration: itineraryDuration || segmentDuration,
        segments: [segment]
      }];
    }
    
    // Build price if provided
    if (priceCurrency && priceTotal) {
      flightOffer.price = {
        currency: priceCurrency,
        total: priceTotal,
        base: priceBase || priceTotal
      };
      if (priceGrandTotal) flightOffer.price.grandTotal = priceGrandTotal;
    }
    
    // Build traveler if provided
    const traveler = {};
    if (travelerId) traveler.id = travelerId;
    if (travelerDateOfBirth) traveler.dateOfBirth = travelerDateOfBirth;
    if (travelerGender) traveler.gender = travelerGender;
    if (travelerFirstName && travelerLastName) {
      traveler.name = {
        firstName: travelerFirstName,
        lastName: travelerLastName
      };
    }
    if (travelerPhoneNumber || travelerEmail) {
      traveler.contact = {};
      if (travelerPhoneNumber) traveler.contact.phoneNumber = travelerPhoneNumber;
      if (travelerEmail) traveler.contact.email = travelerEmail;
    }
    
    // Build document if provided
    if (documentType && documentNumber) {
      traveler.documents = [{
        documentType,
        number: documentNumber,
        issuanceCountry: documentIssuanceCountry
      }];
      if (documentExpiryDate) traveler.documents[0].expiryDate = documentExpiryDate;
      if (documentValidityCountry) traveler.documents[0].validityCountry = documentValidityCountry;
      if (documentNationality) traveler.documents[0].nationality = documentNationality;
      if (documentHolder !== undefined) traveler.documents[0].holder = documentHolder;
    }
    
    // Build billing address if provided
    if (billingAddressLine || billingAddressCityName) {
      traveler.billingAddress = {};
      if (billingAddressLine) traveler.billingAddress.line = billingAddressLine;
      if (billingAddressZip) traveler.billingAddress.zip = billingAddressZip;
      if (billingAddressCountryCode) traveler.billingAddress.countryCode = billingAddressCountryCode;
      if (billingAddressCityName) traveler.billingAddress.cityName = billingAddressCityName;
    }
    
    // Build remarks if provided
    const remarks = {};
    if (remarksGeneralText) {
      remarks.general = [{
        text: remarksGeneralText
      }];
      if (remarksGeneralSubType) remarks.general[0].subType = remarksGeneralSubType;
    }
    
    // Build ticketing agreement if provided
    const ticketingAgreement = {};
    if (ticketingAgreementOption) {
      ticketingAgreement.option = ticketingAgreementOption;
      if (ticketingAgreementDelay) ticketingAgreement.delay = ticketingAgreementDelay;
    }
    
    // Build contacts if provided
    const contacts = [];
    if (contactAddresseeFirstName && contactAddresseeLastName && contactPurpose) {
      const contact = {
        addresseeName: {
          firstName: contactAddresseeFirstName,
          lastName: contactAddresseeLastName
        },
        purpose: contactPurpose
      };
      
      if (contactCompanyName) contact.companyName = contactCompanyName;
      if (contactPhoneNumber) {
        contact.phones = [{
          deviceType: contactPhoneDeviceType || "MOBILE",
          countryCallingCode: contactPhoneCountryCallingCode || "1",
          number: contactPhoneNumber
        }];
      }
      if (contactEmail) contact.emails = [contactEmail];
      if (contactAddressCityName) {
        contact.address = {
          lines: contactAddressLines ? contactAddressLines.split(',') : [contactAddressLines],
          cityName: contactAddressCityName,
          countryCode: contactAddressCountryCode
        };
        if (contactAddressPostalCode) contact.address.postalCode = contactAddressPostalCode;
      }
      
      contacts.push(contact);
    }
    
    const body = {
      data: {
        type: "flight-order",
        flightOffers: [flightOffer],
        travelers: [traveler],
        ...(Object.keys(remarks).length > 0 ? { remarks } : {}),
        ...(Object.keys(ticketingAgreement).length > 0 ? { ticketingAgreement } : {}),
        ...(contacts.length > 0 ? { contacts } : {}),
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
const FlightOrderByIdSchema = { 
  flightOrderId: z.string().min(1).describe("Unique identifier of the flight order to retrieve. Required parameter for order lookup."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
      // Either provide flight-orderId for GET seatmaps or provide flight offer data to POST
      flightOrderId: z.string().optional().describe("Unique identifier of an existing flight order. Used to retrieve seat maps for booked flights."),
      
      // Flight offer metadata (flattened from nested structure)
      flightOfferType: z.string().optional().describe("Type of flight offer, typically 'flight-offer'. Used to identify the offer structure."),
      flightOfferId: z.string().optional().describe("Unique identifier for the flight offer. Used to reference specific offers."),
      flightOfferSource: z.string().optional().describe("Source of the flight offer (e.g., 'GDS', 'LCC'). Indicates where the offer originated."),
      instantTicketingRequired: z.boolean().optional().describe("If true, the offer requires immediate ticketing. Used for time-sensitive bookings."),
      nonHomogeneous: z.boolean().optional().describe("If true, the offer contains mixed fare types. Used for complex pricing scenarios."),
      oneWay: z.boolean().optional().describe("If true, this is a one-way flight. Used to determine pricing structure."),
      isUpsellOffer: z.boolean().optional().describe("If true, this is an upsell offer. Used for premium upgrade options."),
      lastTicketingDate: z.string().optional().describe("Last date when this offer can be ticketed (YYYY-MM-DD). Used for booking deadlines."),
      numberOfBookableSeats: z.number().optional().describe("Number of seats available for booking. Used for availability checking."),
      
      // Itinerary information
      itineraryDuration: z.string().optional().describe("Total duration of the itinerary (e.g., 'PT2H30M'). Used for trip planning."),
      
      // Flight segment details (flattened from nested structure)
      segmentDepartureIataCode: z.string().optional().describe("IATA code of departure airport for the segment. Required for segment identification."),
      segmentDepartureTerminal: z.string().optional().describe("Terminal at departure airport. Used for airport navigation."),
      segmentDepartureAt: z.string().optional().describe("Departure time in ISO 8601 format. Used for scheduling."),
      segmentArrivalIataCode: z.string().optional().describe("IATA code of arrival airport for the segment. Required for segment identification."),
      segmentArrivalTerminal: z.string().optional().describe("Terminal at arrival airport. Used for airport navigation."),
      segmentArrivalAt: z.string().optional().describe("Arrival time in ISO 8601 format. Used for scheduling."),
      segmentCarrierCode: z.string().optional().describe("IATA code of the operating airline. Used for airline identification."),
      segmentNumber: z.string().optional().describe("Flight number for the segment. Used for flight identification."),
      segmentAircraftCode: z.string().optional().describe("IATA code of the aircraft type. Used for aircraft information."),
      segmentOperatingCarrierCode: z.string().optional().describe("IATA code of the actual operating carrier (for codeshare flights). Used for carrier identification."),
      segmentDuration: z.string().optional().describe("Duration of the segment (e.g., 'PT2H30M'). Used for flight planning."),
      segmentId: z.string().optional().describe("Unique identifier for the segment. Used for segment reference."),
      segmentNumberOfStops: z.number().optional().describe("Number of stops in the segment. Used for connection information."),
      segmentBlacklistedInEU: z.boolean().optional().describe("If true, segment is blacklisted in EU. Used for regulatory compliance."),
      
      // Pricing information
      priceCurrency: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Used for price display."),
      priceTotal: z.string().optional().describe("Total price including all taxes and fees. Used for final pricing."),
      priceBase: z.string().optional().describe("Base fare price before taxes and fees. Used for fare breakdown."),
      priceGrandTotal: z.string().optional().describe("Grand total price including all charges. Used for final pricing."),
      
      // API configuration
      timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
    },
  },
  async (input) => {
    const { 
      timeoutMs, 
      flightOrderId,
      // Flight offer data
      flightOfferType,
      flightOfferId,
      flightOfferSource,
      instantTicketingRequired,
      nonHomogeneous,
      oneWay,
      isUpsellOffer,
      lastTicketingDate,
      numberOfBookableSeats,
      // Itinerary data
      itineraryDuration,
      // Segment data
      segmentDepartureIataCode,
      segmentDepartureTerminal,
      segmentDepartureAt,
      segmentArrivalIataCode,
      segmentArrivalTerminal,
      segmentArrivalAt,
      segmentCarrierCode,
      segmentNumber,
      segmentAircraftCode,
      segmentOperatingCarrierCode,
      segmentDuration,
      segmentId,
      segmentNumberOfStops,
      segmentBlacklistedInEU,
      // Price data
      priceCurrency,
      priceTotal,
      priceBase,
      priceGrandTotal
    } = input;
    
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

    // Otherwise build flight offer from flattened data and POST
    const flightOffer = {};
    
    if (flightOfferType) flightOffer.type = flightOfferType;
    if (flightOfferId) flightOffer.id = flightOfferId;
    if (flightOfferSource) flightOffer.source = flightOfferSource;
    if (instantTicketingRequired !== undefined) flightOffer.instantTicketingRequired = instantTicketingRequired;
    if (nonHomogeneous !== undefined) flightOffer.nonHomogeneous = nonHomogeneous;
    if (oneWay !== undefined) flightOffer.oneWay = oneWay;
    if (isUpsellOffer !== undefined) flightOffer.isUpsellOffer = isUpsellOffer;
    if (lastTicketingDate) flightOffer.lastTicketingDate = lastTicketingDate;
    if (numberOfBookableSeats !== undefined) flightOffer.numberOfBookableSeats = numberOfBookableSeats;
    
    // Build itinerary if segment data is provided
    if (segmentDepartureIataCode && segmentArrivalIataCode) {
      const segment = {
        departure: {
          iataCode: segmentDepartureIataCode
        },
        arrival: {
          iataCode: segmentArrivalIataCode
        },
        carrierCode: segmentCarrierCode,
        number: segmentNumber,
        duration: segmentDuration,
        id: segmentId,
        numberOfStops: segmentNumberOfStops || 0
      };
      
      if (segmentDepartureTerminal) segment.departure.terminal = segmentDepartureTerminal;
      if (segmentDepartureAt) segment.departure.at = segmentDepartureAt;
      if (segmentArrivalTerminal) segment.arrival.terminal = segmentArrivalTerminal;
      if (segmentArrivalAt) segment.arrival.at = segmentArrivalAt;
      if (segmentAircraftCode) segment.aircraft = { code: segmentAircraftCode };
      if (segmentOperatingCarrierCode) segment.operating = { carrierCode: segmentOperatingCarrierCode };
      if (segmentBlacklistedInEU !== undefined) segment.blacklistedInEU = segmentBlacklistedInEU;
      
      flightOffer.itineraries = [{
        duration: itineraryDuration || segmentDuration,
        segments: [segment]
      }];
    }
    
    // Build price if provided
    if (priceCurrency && priceTotal) {
      flightOffer.price = {
        currency: priceCurrency,
        total: priceTotal,
        base: priceBase || priceTotal
      };
      if (priceGrandTotal) flightOffer.price.grandTotal = priceGrandTotal;
    }
    
    const body = { data: [flightOffer] };
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
      carrierCode: z.string().describe("IATA code of the airline carrier (e.g., 'BA', 'AF', 'LH'). Required for flight schedule lookup."),
      flightNumber: z.string().describe("Flight number (e.g., '123', '4567'). Required for flight schedule lookup."),
      scheduledDepartureDate: z.string().describe("Scheduled departure date in YYYY-MM-DD format. Required for flight schedule lookup."),
      timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  // Core route information
  originLocationCode: z.string().describe("IATA code of the departure airport or city (e.g., 'NYC', 'LAX'). Required for delay prediction."),
  destinationLocationCode: z.string().describe("IATA code of the arrival airport or city (e.g., 'LHR', 'CDG'). Required for delay prediction."),
  departureDate: z.string().describe("Departure date in YYYY-MM-DD format. Required for delay prediction."),
  
  // Optional timing details
  departureTime: z.string().optional().describe("Departure time in HH:MM:SS format. Used for more accurate delay prediction."),
  arrivalDate: z.string().optional().describe("Arrival date in YYYY-MM-DD format. Used for round-trip delay prediction."),
  arrivalTime: z.string().optional().describe("Arrival time in HH:MM:SS format. Used for more accurate delay prediction."),
  
  // Flight-specific details
  aircraftCode: z.string().optional().describe("IATA code of the aircraft type. Used for aircraft-specific delay patterns."),
  carrierCode: z.string().optional().describe("IATA code of the airline carrier. Used for airline-specific delay patterns."),
  flightNumber: z.string().optional().describe("Flight number. Used for specific flight delay prediction."),
  duration: z.string().optional().describe("Flight duration in ISO 8601 format (e.g., 'PT2H30M'). Used for delay calculation."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  // Core route information
  originIataCode: z.string().describe("IATA code of the departure airport or city (e.g., 'NYC', 'LAX'). Required for price metrics analysis."),
  destinationIataCode: z.string().describe("IATA code of the arrival airport or city (e.g., 'LHR', 'CDG'). Required for price metrics analysis."),
  departureDate: z.string().describe("Departure date in YYYY-MM-DD format. Required for price metrics analysis."),
  
  // Pricing and trip configuration
  currencyCode: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Optional, defaults to USD."),
  oneWay: z.boolean().optional().describe("If true, analyze one-way flights only. If false or omitted, includes round-trip analysis."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  // Flight offer metadata (flattened from nested structure)
  flightOfferType: z.string().optional().describe("Type of flight offer, typically 'flight-offer'. Used to identify the offer structure."),
  flightOfferId: z.string().optional().describe("Unique identifier for the flight offer. Used to reference specific offers."),
  flightOfferSource: z.string().optional().describe("Source of the flight offer (e.g., 'GDS', 'LCC'). Indicates where the offer originated."),
  instantTicketingRequired: z.boolean().optional().describe("If true, the offer requires immediate ticketing. Used for time-sensitive bookings."),
  nonHomogeneous: z.boolean().optional().describe("If true, the offer contains mixed fare types. Used for complex pricing scenarios."),
  oneWay: z.boolean().optional().describe("If true, this is a one-way flight. Used to determine pricing structure."),
  isUpsellOffer: z.boolean().optional().describe("If true, this is an upsell offer. Used for premium upgrade options."),
  lastTicketingDate: z.string().optional().describe("Last date when this offer can be ticketed (YYYY-MM-DD). Used for booking deadlines."),
  numberOfBookableSeats: z.number().optional().describe("Number of seats available for booking. Used for availability checking."),
  
  // Itinerary information
  itineraryDuration: z.string().optional().describe("Total duration of the itinerary (e.g., 'PT2H30M'). Used for trip planning."),
  
  // Flight segment details (flattened from nested structure)
  segmentDepartureIataCode: z.string().optional().describe("IATA code of departure airport for the segment. Required for segment identification."),
  segmentDepartureTerminal: z.string().optional().describe("Terminal at departure airport. Used for airport navigation."),
  segmentDepartureAt: z.string().optional().describe("Departure time in ISO 8601 format. Used for scheduling."),
  segmentArrivalIataCode: z.string().optional().describe("IATA code of arrival airport for the segment. Required for segment identification."),
  segmentArrivalTerminal: z.string().optional().describe("Terminal at arrival airport. Used for airport navigation."),
  segmentArrivalAt: z.string().optional().describe("Arrival time in ISO 8601 format. Used for scheduling."),
  segmentCarrierCode: z.string().optional().describe("IATA code of the operating airline. Used for airline identification."),
  segmentNumber: z.string().optional().describe("Flight number for the segment. Used for flight identification."),
  segmentAircraftCode: z.string().optional().describe("IATA code of the aircraft type. Used for aircraft information."),
  segmentOperatingCarrierCode: z.string().optional().describe("IATA code of the actual operating carrier (for codeshare flights). Used for carrier identification."),
  segmentDuration: z.string().optional().describe("Duration of the segment (e.g., 'PT2H30M'). Used for flight planning."),
  segmentId: z.string().optional().describe("Unique identifier for the segment. Used for segment reference."),
  segmentNumberOfStops: z.number().optional().describe("Number of stops in the segment. Used for connection information."),
  segmentBlacklistedInEU: z.boolean().optional().describe("If true, segment is blacklisted in EU. Used for regulatory compliance."),
  
  // Pricing information
  priceCurrency: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Used for price display."),
  priceTotal: z.string().optional().describe("Total price including all taxes and fees. Used for final pricing."),
  priceBase: z.string().optional().describe("Base fare price before taxes and fees. Used for fare breakdown."),
  priceGrandTotal: z.string().optional().describe("Grand total price including all charges. Used for final pricing."),
  
  // Payment information (flattened from nested structure)
  paymentId: z.string().optional().describe("Unique identifier for the payment. Used for payment tracking."),
  paymentMethod: z.string().optional().describe("Payment method (e.g., 'CREDIT_CARD', 'DEBIT_CARD'). Used for payment processing."),
  paymentCardVendorCode: z.string().optional().describe("Card vendor code (e.g., 'VI', 'MC', 'AX'). Used for card validation."),
  paymentCardNumber: z.string().optional().describe("Card number (masked). Used for payment processing."),
  paymentCardExpiryDate: z.string().optional().describe("Card expiry date in MM/YY format. Used for card validation."),
  paymentCardHolderName: z.string().optional().describe("Card holder's name. Used for payment verification."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
};

server.registerTool(
  "amadeus.v1.shopping.flight-offers.upselling",
  {
    title: "Amadeus: Flight Offers Upselling",
    description: "Find upsell offers for a flight.",
    inputSchema: FlightOffersUpsellingSchema,
  },
  async (input) => {
    const { 
      timeoutMs,
      // Flight offer data
      flightOfferType,
      flightOfferId,
      flightOfferSource,
      instantTicketingRequired,
      nonHomogeneous,
      oneWay,
      isUpsellOffer,
      lastTicketingDate,
      numberOfBookableSeats,
      // Itinerary data
      itineraryDuration,
      // Segment data
      segmentDepartureIataCode,
      segmentDepartureTerminal,
      segmentDepartureAt,
      segmentArrivalIataCode,
      segmentArrivalTerminal,
      segmentArrivalAt,
      segmentCarrierCode,
      segmentNumber,
      segmentAircraftCode,
      segmentOperatingCarrierCode,
      segmentDuration,
      segmentId,
      segmentNumberOfStops,
      segmentBlacklistedInEU,
      // Price data
      priceCurrency,
      priceTotal,
      priceBase,
      priceGrandTotal,
      // Payment data
      paymentId,
      paymentMethod,
      paymentCardVendorCode,
      paymentCardNumber,
      paymentCardExpiryDate,
      paymentCardHolderName
    } = input;
    
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    
    // Transform flat input to nested API format
    const flightOffer = {};
    
    if (flightOfferType) flightOffer.type = flightOfferType;
    if (flightOfferId) flightOffer.id = flightOfferId;
    if (flightOfferSource) flightOffer.source = flightOfferSource;
    if (instantTicketingRequired !== undefined) flightOffer.instantTicketingRequired = instantTicketingRequired;
    if (nonHomogeneous !== undefined) flightOffer.nonHomogeneous = nonHomogeneous;
    if (oneWay !== undefined) flightOffer.oneWay = oneWay;
    if (isUpsellOffer !== undefined) flightOffer.isUpsellOffer = isUpsellOffer;
    if (lastTicketingDate) flightOffer.lastTicketingDate = lastTicketingDate;
    if (numberOfBookableSeats !== undefined) flightOffer.numberOfBookableSeats = numberOfBookableSeats;
    
    // Build itinerary if segment data is provided
    if (segmentDepartureIataCode && segmentArrivalIataCode) {
      const segment = {
        departure: {
          iataCode: segmentDepartureIataCode
        },
        arrival: {
          iataCode: segmentArrivalIataCode
        },
        carrierCode: segmentCarrierCode,
        number: segmentNumber,
        duration: segmentDuration,
        id: segmentId,
        numberOfStops: segmentNumberOfStops || 0
      };
      
      if (segmentDepartureTerminal) segment.departure.terminal = segmentDepartureTerminal;
      if (segmentDepartureAt) segment.departure.at = segmentDepartureAt;
      if (segmentArrivalTerminal) segment.arrival.terminal = segmentArrivalTerminal;
      if (segmentArrivalAt) segment.arrival.at = segmentArrivalAt;
      if (segmentAircraftCode) segment.aircraft = { code: segmentAircraftCode };
      if (segmentOperatingCarrierCode) segment.operating = { carrierCode: segmentOperatingCarrierCode };
      if (segmentBlacklistedInEU !== undefined) segment.blacklistedInEU = segmentBlacklistedInEU;
      
      flightOffer.itineraries = [{
        duration: itineraryDuration || segmentDuration,
        segments: [segment]
      }];
    }
    
    // Build price if provided
    if (priceCurrency && priceTotal) {
      flightOffer.price = {
        currency: priceCurrency,
        total: priceTotal,
        base: priceBase || priceTotal
      };
      if (priceGrandTotal) flightOffer.price.grandTotal = priceGrandTotal;
    }
    
    // Build payments if provided
    const payments = [];
    if (paymentId && paymentMethod) {
      const payment = {
        id: paymentId,
        method: paymentMethod
      };
      
      if (paymentCardVendorCode && paymentCardNumber) {
        payment.card = {
          vendorCode: paymentCardVendorCode,
          cardNumber: paymentCardNumber,
          expiryDate: paymentCardExpiryDate,
          holderName: paymentCardHolderName
        };
      }
      
      payments.push(payment);
    }
    
    const body = {
      data: {
        type: "flight-offers-upselling",
        flightOffers: [flightOffer],
        ...(payments.length > 0 ? { payments } : {}),
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
  // Meta data (flattened from nested structure)
  metaCount: z.number().optional().describe("Total count of results available. Used for pagination and result counting."),
  metaLinksSelf: z.string().optional().describe("Self-referencing link for the current page. Used for API navigation."),
  
  // Flight offer metadata (flattened from nested structure)
  flightOfferType: z.string().optional().describe("Type of flight offer, typically 'flight-offer'. Used to identify the offer structure."),
  flightOfferId: z.string().optional().describe("Unique identifier for the flight offer. Used to reference specific offers."),
  flightOfferSource: z.string().optional().describe("Source of the flight offer (e.g., 'GDS', 'LCC'). Indicates where the offer originated."),
  instantTicketingRequired: z.boolean().optional().describe("If true, the offer requires immediate ticketing. Used for time-sensitive bookings."),
  nonHomogeneous: z.boolean().optional().describe("If true, the offer contains mixed fare types. Used for complex pricing scenarios."),
  oneWay: z.boolean().optional().describe("If true, this is a one-way flight. Used to determine pricing structure."),
  isUpsellOffer: z.boolean().optional().describe("If true, this is an upsell offer. Used for premium upgrade options."),
  lastTicketingDate: z.string().optional().describe("Last date when this offer can be ticketed (YYYY-MM-DD). Used for booking deadlines."),
  numberOfBookableSeats: z.number().optional().describe("Number of seats available for booking. Used for availability checking."),
  
  // Itinerary information
  itineraryDuration: z.string().optional().describe("Total duration of the itinerary (e.g., 'PT2H30M'). Used for trip planning."),
  
  // Flight segment details (flattened from nested structure)
  segmentDepartureIataCode: z.string().optional().describe("IATA code of departure airport for the segment. Required for segment identification."),
  segmentDepartureTerminal: z.string().optional().describe("Terminal at departure airport. Used for airport navigation."),
  segmentDepartureAt: z.string().optional().describe("Departure time in ISO 8601 format. Used for scheduling."),
  segmentArrivalIataCode: z.string().optional().describe("IATA code of arrival airport for the segment. Required for segment identification."),
  segmentArrivalTerminal: z.string().optional().describe("Terminal at arrival airport. Used for airport navigation."),
  segmentArrivalAt: z.string().optional().describe("Arrival time in ISO 8601 format. Used for scheduling."),
  segmentCarrierCode: z.string().optional().describe("IATA code of the operating airline. Used for airline identification."),
  segmentNumber: z.string().optional().describe("Flight number for the segment. Used for flight identification."),
  segmentAircraftCode: z.string().optional().describe("IATA code of the aircraft type. Used for aircraft information."),
  segmentOperatingCarrierCode: z.string().optional().describe("IATA code of the actual operating carrier (for codeshare flights). Used for carrier identification."),
  segmentDuration: z.string().optional().describe("Duration of the segment (e.g., 'PT2H30M'). Used for flight planning."),
  segmentId: z.string().optional().describe("Unique identifier for the segment. Used for segment reference."),
  segmentNumberOfStops: z.number().optional().describe("Number of stops in the segment. Used for connection information."),
  segmentBlacklistedInEU: z.boolean().optional().describe("If true, segment is blacklisted in EU. Used for regulatory compliance."),
  
  // Pricing information
  priceCurrency: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Used for price display."),
  priceTotal: z.string().optional().describe("Total price including all taxes and fees. Used for final pricing."),
  priceBase: z.string().optional().describe("Base fare price before taxes and fees. Used for fare breakdown."),
  priceGrandTotal: z.string().optional().describe("Grand total price including all charges. Used for final pricing."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
};

server.registerTool(
  "amadeus.v2.shopping.flight-offers.prediction",
  {
    title: "Amadeus: Flight Offers Prediction",
    description: "Get flight offers prediction based on search results.",
    inputSchema: FlightOffersPredictionSchema,
  },
  async (input) => {
    const { 
      timeoutMs,
      // Meta data
      metaCount,
      metaLinksSelf,
      // Flight offer data
      flightOfferType,
      flightOfferId,
      flightOfferSource,
      instantTicketingRequired,
      nonHomogeneous,
      oneWay,
      isUpsellOffer,
      lastTicketingDate,
      numberOfBookableSeats,
      // Itinerary data
      itineraryDuration,
      // Segment data
      segmentDepartureIataCode,
      segmentDepartureTerminal,
      segmentDepartureAt,
      segmentArrivalIataCode,
      segmentArrivalTerminal,
      segmentArrivalAt,
      segmentCarrierCode,
      segmentNumber,
      segmentAircraftCode,
      segmentOperatingCarrierCode,
      segmentDuration,
      segmentId,
      segmentNumberOfStops,
      segmentBlacklistedInEU,
      // Price data
      priceCurrency,
      priceTotal,
      priceBase,
      priceGrandTotal
    } = input;
    
    const { serviceName, apiKey, apiSecret } = getEnvAuth();
    
    // Build meta if provided
    const meta = {};
    if (metaCount !== undefined) meta.count = metaCount;
    if (metaLinksSelf) meta.links = { self: metaLinksSelf };
    
    // Transform flat input to nested API format
    const flightOffer = {};
    
    if (flightOfferType) flightOffer.type = flightOfferType;
    if (flightOfferId) flightOffer.id = flightOfferId;
    if (flightOfferSource) flightOffer.source = flightOfferSource;
    if (instantTicketingRequired !== undefined) flightOffer.instantTicketingRequired = instantTicketingRequired;
    if (nonHomogeneous !== undefined) flightOffer.nonHomogeneous = nonHomogeneous;
    if (oneWay !== undefined) flightOffer.oneWay = oneWay;
    if (isUpsellOffer !== undefined) flightOffer.isUpsellOffer = isUpsellOffer;
    if (lastTicketingDate) flightOffer.lastTicketingDate = lastTicketingDate;
    if (numberOfBookableSeats !== undefined) flightOffer.numberOfBookableSeats = numberOfBookableSeats;
    
    // Build itinerary if segment data is provided
    if (segmentDepartureIataCode && segmentArrivalIataCode) {
      const segment = {
        departure: {
          iataCode: segmentDepartureIataCode
        },
        arrival: {
          iataCode: segmentArrivalIataCode
        },
        carrierCode: segmentCarrierCode,
        number: segmentNumber,
        duration: segmentDuration,
        id: segmentId,
        numberOfStops: segmentNumberOfStops || 0
      };
      
      if (segmentDepartureTerminal) segment.departure.terminal = segmentDepartureTerminal;
      if (segmentDepartureAt) segment.departure.at = segmentDepartureAt;
      if (segmentArrivalTerminal) segment.arrival.terminal = segmentArrivalTerminal;
      if (segmentArrivalAt) segment.arrival.at = segmentArrivalAt;
      if (segmentAircraftCode) segment.aircraft = { code: segmentAircraftCode };
      if (segmentOperatingCarrierCode) segment.operating = { carrierCode: segmentOperatingCarrierCode };
      if (segmentBlacklistedInEU !== undefined) segment.blacklistedInEU = segmentBlacklistedInEU;
      
      flightOffer.itineraries = [{
        duration: itineraryDuration || segmentDuration,
        segments: [segment]
      }];
    }
    
    // Build price if provided
    if (priceCurrency && priceTotal) {
      flightOffer.price = {
        currency: priceCurrency,
        total: priceTotal,
        base: priceBase || priceTotal
      };
      if (priceGrandTotal) flightOffer.price.grandTotal = priceGrandTotal;
    }
    
    // Transform input to correct Amadeus format
    const body = {
      data: {
        ...(Object.keys(meta).length > 0 ? { meta } : {}),
        data: [flightOffer]
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
const TripPurposeSchema = { 
  originLocationCode: z.string().describe("IATA code of the departure airport or city (e.g., 'NYC', 'LAX'). Required for trip purpose prediction."),
  destinationLocationCode: z.string().describe("IATA code of the arrival airport or city (e.g., 'LHR', 'CDG'). Required for trip purpose prediction."),
  departureDate: z.string().describe("Departure date in YYYY-MM-DD format. Required for trip purpose prediction."),
  returnDate: z.string().optional().describe("Return date in YYYY-MM-DD format. Optional for round-trip trip purpose prediction."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.")
};

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
  // Core search parameters
  origin: z.string().describe("IATA code of departure city or airport (e.g., 'NYC', 'LAX'). Required for destination search."),
  departureDate: z.string().optional().describe("Departure date in YYYY-MM-DD format. Optional for flexible date search."),
  
  // Trip configuration
  oneWay: z.boolean().optional().describe("If true, search for one-way flights only. If false or omitted, includes round-trip options."),
  duration: z.number().optional().describe("Trip duration in days. Used to find return dates for round-trip searches."),
  
  // Flight preferences
  nonStop: z.boolean().optional().describe("If true, only return non-stop flights. Optional filter for direct flights only."),
  viewBy: z.enum(["DATE", "DURATION"]).optional().describe("Sort results by 'DATE' (chronological) or 'DURATION' (shortest first). Optional sorting."),
  
  // Price filtering
  maxPrice: z.number().optional().describe("Maximum price limit for destinations. Used to filter results by budget."),
  currencyCode: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Optional, defaults to USD."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  // Origin Destination fields (first route)
  originDestinationId: z.string().optional().describe("Unique identifier for the origin-destination pair. Used for multi-route searches."),
  originLocationCode: z.string().optional().describe("IATA code of departure airport or city (e.g., 'NYC', 'LAX'). Required for availability search."),
  destinationLocationCode: z.string().optional().describe("IATA code of arrival airport or city (e.g., 'LHR', 'CDG'). Required for availability search."),
  departureDate: z.string().optional().describe("Departure date in YYYY-MM-DD format. Required for availability search."),
  departureTime: z.string().optional().describe("Departure time in HH:MM:SS format. Used for time-specific availability."),
  arrivalDate: z.string().optional().describe("Arrival date in YYYY-MM-DD format. Used for round-trip availability."),
  arrivalTime: z.string().optional().describe("Arrival time in HH:MM:SS format. Used for time-specific availability."),
  
  // Traveler fields (first traveler)
  travelerId: z.string().optional().describe("Unique identifier for the traveler. Used for traveler-specific pricing."),
  travelerType: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of traveler. Used for age-based pricing and availability."),
  
  // Additional traveler fields for multiple travelers (2-9)
  travelerId2: z.string().optional().describe("Unique identifier for the second traveler. Used for multi-traveler bookings."),
  travelerType2: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of the second traveler. Used for age-based pricing."),
  travelerId3: z.string().optional().describe("Unique identifier for the third traveler. Used for multi-traveler bookings."),
  travelerType3: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of the third traveler. Used for age-based pricing."),
  travelerId4: z.string().optional().describe("Unique identifier for the fourth traveler. Used for multi-traveler bookings."),
  travelerType4: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of the fourth traveler. Used for age-based pricing."),
  travelerId5: z.string().optional().describe("Unique identifier for the fifth traveler. Used for multi-traveler bookings."),
  travelerType5: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of the fifth traveler. Used for age-based pricing."),
  travelerId6: z.string().optional().describe("Unique identifier for the sixth traveler. Used for multi-traveler bookings."),
  travelerType6: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of the sixth traveler. Used for age-based pricing."),
  travelerId7: z.string().optional().describe("Unique identifier for the seventh traveler. Used for multi-traveler bookings."),
  travelerType7: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of the seventh traveler. Used for age-based pricing."),
  travelerId8: z.string().optional().describe("Unique identifier for the eighth traveler. Used for multi-traveler bookings."),
  travelerType8: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of the eighth traveler. Used for age-based pricing."),
  travelerId9: z.string().optional().describe("Unique identifier for the ninth traveler. Used for multi-traveler bookings."),
  travelerType9: z.enum(["ADULT", "CHILD", "INFANT", "SENIOR", "YOUTH", "HELD_INFANT", "SEATED_INFANT", "STUDENT"]).optional().describe("Type of the ninth traveler. Used for age-based pricing."),
  
  // Additional origin destination fields for multiple routes (second route)
  originDestinationId2: z.string().optional().describe("Unique identifier for the second origin-destination pair. Used for multi-route searches."),
  originLocationCode2: z.string().optional().describe("IATA code of departure airport for the second route. Used for multi-route searches."),
  destinationLocationCode2: z.string().optional().describe("IATA code of arrival airport for the second route. Used for multi-route searches."),
  departureDate2: z.string().optional().describe("Departure date for the second route in YYYY-MM-DD format. Used for multi-route searches."),
  departureTime2: z.string().optional().describe("Departure time for the second route in HH:MM:SS format. Used for multi-route searches."),
  arrivalDate2: z.string().optional().describe("Arrival date for the second route in YYYY-MM-DD format. Used for multi-route searches."),
  arrivalTime2: z.string().optional().describe("Arrival time for the second route in HH:MM:SS format. Used for multi-route searches."),
  
  // API configuration and filtering
  sources: z.array(z.enum(["GDS", "LCC"])).optional().describe("Data sources to search: 'GDS' (Global Distribution System) or 'LCC' (Low Cost Carrier). Used to filter search sources."),
  currencyCode: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Optional, defaults to USD."),
  maxFlightOffers: z.number().int().positive().optional().describe("Maximum number of flight offers to return. Used to limit search results."),
  excludedCarrierCodes: z.array(z.string()).optional().describe("Array of airline codes to exclude from search. Used to filter out specific airlines."),
  includedCarrierCodes: z.array(z.string()).optional().describe("Array of airline codes to include in search. Used to filter for specific airlines."),
  nonStopPreferred: z.boolean().optional().describe("If true, prefer non-stop flights. Used for direct flight preference."),
  airportChangeAllowed: z.boolean().optional().describe("If true, allow airport changes during connections. Used for connection flexibility."),
  technicalStopsAllowed: z.boolean().optional().describe("If true, allow technical stops. Used for flight routing flexibility."),
  maxNumberOfConnections: z.number().int().min(0).optional().describe("Maximum number of connections allowed. Used to limit flight complexity."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  cityCodes: z.string().describe("Comma-separated list of city IATA codes (e.g., 'NYC,LAX,LHR'). Required for location recommendations."),
  travelerCountryCode: z.string().describe("ISO 3166-1 alpha-2 country code of the traveler (e.g., 'US', 'GB'). Required for personalized recommendations."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  airportCode: z.string().describe("IATA code of the airport (e.g., 'JFK', 'LAX', 'LHR'). Required for on-time prediction."),
  date: z.string().describe("Date in YYYY-MM-DD format. Required for on-time prediction."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  keyword: z.string().optional().describe("Search keyword for location name (e.g., 'New York', 'London'). Used for location search."),
  subType: z.string().optional().describe("Location sub-type filter: 'CITY', 'AIRPORT', or comma-separated list. Used to filter location types."),
  countryCode: z.string().optional().describe("ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB'). Used to filter locations by country."),
  sort: z.string().optional().describe("Sort order for results: 'RELEVANCE', 'TRAVELER_TRAFFIC'. Used for result ordering."),
  view: z.string().optional().describe("Response detail level: 'LIGHT' (basic info) or 'FULL' (complete info). Used to control response size."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
const LocationByIdSchema = { 
  locationId: z.string().describe("Unique identifier of the location (e.g., 'CMUC', 'NYC'). Required for location details lookup."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
  latitude: z.number().describe("Latitude coordinate (e.g., 40.7128, -74.0060). Required for airport search by location."), 
  longitude: z.number().describe("Longitude coordinate (e.g., 40.7128, -74.0060). Required for airport search by location."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
  departureAirportCode: z.string().describe("IATA code of the departure airport (e.g., 'JFK', 'LAX'). Required for direct destinations lookup."), 
  max: z.number().optional().describe("Maximum number of destinations to return. Used to limit search results."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
const CheckinLinksSchema = { 
  airlineCode: z.string().describe("IATA code of the airline (e.g., 'BA', 'AF', 'LH'). Required for check-in links lookup."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
const AirlinesSchema = { 
  airlineCodes: z.string().describe("Comma-separated list of airline IATA codes (e.g., 'BA,AF,LH'). Required for airline information lookup."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
  airlineCode: z.string().describe("IATA code of the airline (e.g., 'BA', 'AF', 'LH'). Required for airline destinations lookup."), 
  max: z.number().optional().describe("Maximum number of destinations to return. Used to limit search results."),
  includeIndirect: z.boolean().optional().describe("If true, include indirect destinations (via connections). Used for comprehensive destination search."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
const ActivitiesSearchSchema = { 
  latitude: z.number().optional().describe("Latitude coordinate for location-based search (e.g., 40.7128). Used for geographic activity search."), 
  longitude: z.number().optional().describe("Longitude coordinate for location-based search (e.g., -74.0060). Used for geographic activity search."), 
  radius: z.number().optional().describe("Search radius in kilometers from the specified location. Used to limit search area."), 
  cityCode: z.string().optional().describe("IATA city code for city-based search (e.g., 'NYC', 'LON'). Used for city-specific activity search."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
const ActivityByIdSchema = { 
  activityId: z.string().describe("Unique identifier of the activity (e.g., '4615'). Required for activity details lookup."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
const ActivitiesBySquareSchema = { 
  north: z.number().describe("Northern boundary latitude coordinate. Required for bounding box search."), 
  south: z.number().describe("Southern boundary latitude coordinate. Required for bounding box search."), 
  east: z.number().describe("Eastern boundary longitude coordinate. Required for bounding box search."), 
  west: z.number().describe("Western boundary longitude coordinate. Required for bounding box search."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
  keyword: z.string().optional().describe("Search keyword for city name (e.g., 'New York', 'London'). Used for city search."), 
  countryCode: z.string().optional().describe("ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB'). Used to filter cities by country."), 
  max: z.number().optional().describe("Maximum number of cities to return. Used to limit search results."),
  include: z.string().optional().describe("Additional data to include in response. Used to control response detail level."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
  // Core transfer parameters
  startLocationCode: z.string().optional().describe("IATA code of the starting location (e.g., 'JFK', 'LAX'). Used for transfer origin."),
  endAddressLine: z.string().optional().describe("Address line of the destination. Used for specific address transfers."),
  endCityName: z.string().optional().describe("City name of the destination. Used for city-based transfers."),
  endZipCode: z.string().optional().describe("Postal code of the destination. Used for address-based transfers."),
  endCountryCode: z.string().optional().describe("Country code of the destination. Used for international transfers."),
  endName: z.string().optional().describe("Name of the destination (e.g., hotel name). Used for specific location transfers."),
  endGeoCode: z.string().optional().describe("Geographic code of the destination. Used for location identification."),
  transferType: z.string().optional().describe("Type of transfer (e.g., 'AIRPORT', 'HOTEL'). Used for transfer classification."),
  startDateTime: z.string().optional().describe("Start date and time in ISO 8601 format. Used for transfer scheduling."),
  passengers: z.number().optional().describe("Number of passengers. Used for capacity planning."),
  
  // Stopover information (flattened from nested structure)
  stopOverDuration: z.string().optional().describe("Duration of stopover (e.g., 'PT2H30M'). Used for multi-leg transfers."),
  stopOverLocationCode: z.string().optional().describe("IATA code of stopover location. Used for multi-leg transfers."),
  
  // Connected segments - start segment (flattened from nested structure)
  startConnectedSegmentTransportationType: z.string().optional().describe("Type of transportation for start segment (e.g., 'FLIGHT', 'TRAIN'). Used for multi-modal transfers."),
  startConnectedSegmentTransportationNumber: z.string().optional().describe("Transportation number for start segment. Used for multi-modal transfers."),
  startConnectedSegmentDepartureUicCode: z.string().optional().describe("UIC code of departure station for start segment. Used for train connections."),
  startConnectedSegmentDepartureIataCode: z.string().optional().describe("IATA code of departure airport for start segment. Used for flight connections."),
  startConnectedSegmentDepartureLocalDateTime: z.string().optional().describe("Local departure date and time for start segment. Used for scheduling."),
  startConnectedSegmentArrivalUicCode: z.string().optional().describe("UIC code of arrival station for start segment. Used for train connections."),
  startConnectedSegmentArrivalIataCode: z.string().optional().describe("IATA code of arrival airport for start segment. Used for flight connections."),
  startConnectedSegmentArrivalLocalDateTime: z.string().optional().describe("Local arrival date and time for start segment. Used for scheduling."),
  
  // Connected segments - end segment (flattened from nested structure)
  endConnectedSegmentTransportationType: z.string().optional().describe("Type of transportation for end segment (e.g., 'FLIGHT', 'TRAIN'). Used for multi-modal transfers."),
  endConnectedSegmentTransportationNumber: z.string().optional().describe("Transportation number for end segment. Used for multi-modal transfers."),
  endConnectedSegmentDepartureUicCode: z.string().optional().describe("UIC code of departure station for end segment. Used for train connections."),
  endConnectedSegmentDepartureIataCode: z.string().optional().describe("IATA code of departure airport for end segment. Used for flight connections."),
  endConnectedSegmentDepartureLocalDateTime: z.string().optional().describe("Local departure date and time for end segment. Used for scheduling."),
  endConnectedSegmentArrivalUicCode: z.string().optional().describe("UIC code of arrival station for end segment. Used for train connections."),
  endConnectedSegmentArrivalIataCode: z.string().optional().describe("IATA code of arrival airport for end segment. Used for flight connections."),
  endConnectedSegmentArrivalLocalDateTime: z.string().optional().describe("Local arrival date and time for end segment. Used for scheduling."),
  
  // API configuration
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  offerId: z.string().min(1).describe("Unique identifier of the transfer offer. Required for transfer order creation."),
  note: z.string().optional().describe("Additional notes for the transfer order. Used for special requests."),
  passengers: z.array(z.any()).describe("Array of passenger information. Used for passenger details in transfer orders."),
  agency: z.any().describe("Agency information. Used for travel agency details."),
  payment: z.any().describe("Payment information. Used for payment processing."),
  extraServices: z.array(z.any()).describe("Array of extra services. Used for additional service requests."),
  equipment: z.array(z.any()).describe("Array of equipment information. Used for vehicle/equipment details."),
  corporation: z.any().describe("Corporation information. Used for corporate bookings."),
  startConnectedSegment: z.any().describe("Start connected segment information. Used for multi-modal transfers."),
  endConnectedSegment: z.any().describe("End connected segment information. Used for multi-modal transfers."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
  transferOrderId: z.string().min(1).describe("Unique identifier of the transfer order to cancel. Required for cancellation."), 
  confirmNbr: z.string().optional().describe("Confirmation number for the transfer order. Used for order verification."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
  originCityCode: z.string().describe("IATA code of the origin city (e.g., 'NYC', 'LAX'). Required for air traffic analytics."), 
  period: z.string().describe("Time period for analytics (e.g., '2017-01,2017-02'). Required for traffic analysis."), 
  sort: z.string().optional().describe("Sort order for results. Used for result ordering."),
  max: z.number().optional().describe("Maximum number of results to return. Used to limit search results."),
  direction: z.string().optional().describe("Direction of travel ('ARRIVING', 'DEPARTING'). Used for traffic direction analysis."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
  originCityCode: z.string().describe("IATA code of the origin city (e.g., 'NYC', 'LAX'). Required for air traffic analytics."), 
  period: z.string().describe("Time period for analytics (e.g., '2017-01,2017-02'). Required for traffic analysis."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
  cityCode: z.string().optional().describe("IATA code of the city (e.g., 'NYC', 'LAX'). Optional for city-specific analysis."), 
  period: z.string().describe("Time period for analytics (e.g., '2017-01,2017-02'). Required for traffic analysis."), 
  direction: z.string().optional().describe("Direction of travel ('ARRIVING', 'DEPARTING'). Used for traffic direction analysis."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
const HotelsByCitySchema = { 
  cityCode: z.string().describe("IATA code of the city (e.g., 'NYC', 'LON'). Required for hotel search by city."), 
  radius: z.number().optional().describe("Search radius from city center. Used to limit search area."), 
  radiusUnit: z.string().optional().describe("Unit for radius measurement ('KM', 'MILE'). Used for radius specification."), 
  chainCodes: z.string().optional().describe("Comma-separated list of hotel chain codes. Used to filter by hotel chains."), 
  amenities: z.string().optional().describe("Comma-separated list of amenity codes. Used to filter by hotel amenities."), 
  ratings: z.string().optional().describe("Comma-separated list of rating levels. Used to filter by hotel ratings."), 
  hotelSource: z.string().optional().describe("Hotel data source filter. Used to specify data source."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
const HotelOffersSearchSchema = { 
  hotelIds: z.string().optional().describe("Comma-separated list of hotel IDs. Used to search specific hotels."), 
  cityCode: z.string().optional().describe("IATA code of the city (e.g., 'NYC', 'LON'). Used for city-based hotel search."), 
  latitude: z.number().optional().describe("Latitude coordinate for location-based search. Used for geographic hotel search."), 
  longitude: z.number().optional().describe("Longitude coordinate for location-based search. Used for geographic hotel search."), 
  radius: z.number().optional().describe("Search radius from specified location. Used to limit search area."), 
  radiusUnit: z.string().optional().describe("Unit for radius measurement ('KM', 'MILE'). Used for radius specification."), 
  checkInDate: z.string().optional().describe("Check-in date in YYYY-MM-DD format. Used for availability search."), 
  checkOutDate: z.string().optional().describe("Check-out date in YYYY-MM-DD format. Used for availability search."), 
  adults: z.number().optional().describe("Number of adult guests. Used for occupancy-based pricing."), 
  roomQuantity: z.number().optional().describe("Number of rooms required. Used for room quantity specification."), 
  priceRange: z.string().optional().describe("Price range filter (e.g., '100-200'). Used for budget filtering."), 
  currency: z.string().optional().describe("Currency code for pricing (e.g., 'USD', 'EUR'). Used for price display."), 
  paymentPolicy: z.string().optional().describe("Payment policy filter. Used for payment requirement filtering."), 
  includeClosed: z.boolean().optional().describe("If true, include closed hotels. Used for comprehensive search."), 
  bestRateOnly: z.boolean().optional().describe("If true, return only best rates. Used for rate optimization."), 
  boardType: z.string().optional().describe("Board type filter (e.g., 'ROOM_ONLY', 'BREAKFAST'). Used for meal plan filtering."), 
  amenities: z.string().optional().describe("Comma-separated list of amenity codes. Used to filter by hotel amenities."), 
  ratings: z.string().optional().describe("Comma-separated list of rating levels. Used to filter by hotel ratings."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
  offerId: z.string().describe("Unique identifier of the hotel offer. Required for hotel booking."),
  guests: z.array(z.any()).describe("Array of guest information. Used for guest details in hotel bookings."),
  payments: z.array(z.any()).describe("Array of payment information. Used for payment processing."),
  rooms: z.array(z.any()).describe("Array of room information. Used for room details in hotel bookings."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
const HotelsByIdsSchema = { 
  hotelIds: z.string().describe("Comma-separated list of hotel IDs. Required for hotel details lookup."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
const HotelsByGeocodeSchema = { 
  latitude: z.number().describe("Latitude coordinate (e.g., 40.7128). Required for geographic hotel search."), 
  longitude: z.number().describe("Longitude coordinate (e.g., -74.0060). Required for geographic hotel search."), 
  radius: z.number().optional().describe("Search radius from coordinates. Used to limit search area."), 
  radiusUnit: z.string().optional().describe("Unit for radius measurement ('KM', 'MILE'). Used for radius specification."), 
  hotelSource: z.string().optional().describe("Hotel data source filter. Used to specify data source."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
const HotelOfferByIdSchema = { 
  hotelOfferId: z.string().describe("Unique identifier of the hotel offer. Required for hotel offer details lookup."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
  type: z.string().describe("Type of hotel order. Required for hotel order creation."),
  guests: z.array(z.any()).describe("Array of guest information. Used for guest details in hotel orders."),
  travelAgent: z.any().describe("Travel agent information. Used for agency bookings."),
  roomAssociations: z.array(z.any()).describe("Array of room association information. Used for room assignments."),
  payment: z.any().describe("Payment information. Used for payment processing."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms."),
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
const HotelSentimentsSchema = { 
  hotelIds: z.string().describe("Comma-separated list of hotel IDs. Required for hotel sentiment analysis."), 
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
};

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
  keyword: z.string().optional().describe("Search keyword for hotel name or location. Used for hotel search."), 
  hotelId: z.string().optional().describe("Unique identifier of the hotel. Used for specific hotel lookup."),
  subType: z.string().optional().describe("Hotel sub-type filter. Used to filter hotel types."),
  timeoutMs: z.number().int().positive().max(60000).default(15000).describe("Request timeout in milliseconds (1-60000). Defaults to 15000ms.") 
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
