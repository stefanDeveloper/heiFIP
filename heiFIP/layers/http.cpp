#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <map>

#include "transport.cpp"
#include "PcapPlusPlusVersion.h"
#include "HttpLayer.h"

/**
 * @class HTTPPacket
 * @brief Base class for HTTP-specific packet handling, inheriting from TransportPacket.
 *
 * Responsibilities:
 *   - Inherits all Ethernet, IP, and transport-layer rewriting and hashing logic.
 *   - Provides a placeholder for HTTP-level preprocessing in derived classes.
 */
class HTTPPacket : public TransportPacket {
public:
    /**
     * @brief Constructor: delegates raw-packet ownership and layer maps to TransportPacket.
     *
     * @param rawPacketPointer  unique_ptr to the raw pcpp::RawPacket containing all bytes.
     * @param addressMapping    Mapping of original→new MAC/IP addresses (populated previously).
     * @param layerMap          Map of protocol layers present (Ethernet, IP, TCP/UDP, HTTP).
     *
     * Workflow:
     *   1. Calls TransportPacket’s constructor, which in turn:
     *        - Rewrites Ethernet MAC addresses (EtherPacket).
     *        - Rewrites IP addresses and computes IP-header hash (IPPacket).
     *        - Computes transport-layer hash and optionally strips payload (TransportPacket).
     *   2. No extra HTTP-specific work is done here; derived classes override header_preprocessing().
     */
    HTTPPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
               std::unordered_map<std::string, std::string> addressMapping = {},
               std::unordered_map<std::string, bool> layerMap = {})
        : TransportPacket(std::move(rawPacketPointer), addressMapping, layerMap)
    {
    }

    /**
     * @brief Placeholder for HTTP-level header preprocessing.
     *
     * Derived classes (HTTPRequestPacket, HTTPResponsePacket) override this to:
     *   - Extract the existing HTTP layer (request or response).
     *   - Build a custom HTTP layer (CustomHTTPRequest or CustomHTTPResponse).
     *   - Copy relevant fields (method, URI, headers, status code).
     *   - Remove the original HttpRequestLayer/HttpResponseLayer and insert the custom one.
     *   - Recompute checksums/lengths after replacement.
     *
     * By default, simply calls TransportPacket’s header_preprocessing() to preserve earlier logic.
     */
    void header_preprocessing() override {
        TransportPacket::header_preprocessing();
    }
};

/**
 * @class HTTPRequestPacket
 * @brief Handles HTTP request–specific hashing and custom-layer replacement.
 *
 * Responsibilities:
 *   - Compute a request-specific SHA-256 hash based on URI, method, and Accept header.
 *   - Optionally strip raw payload if certain layers (TLS without TCP/UDP or Raw without HTTP) exist.
 *   - In header_preprocessing(), replace the pcpp::HttpRequestLayer with CustomHTTPRequest.
 */
class HTTPRequestPacket : public HTTPPacket {
public:
    /// Stores the SHA-256 hex digest of request-specific fields
    std::string hash;

    /**
     * @brief Constructor: compute an HTTP-request hash and possibly strip payload.
     *
     * @param rawPacketPointer  unique_ptr to the raw pcpp::RawPacket.
     * @param addressMapping    Inherited address-mapping from lower layers.
     * @param layerMap          Inherited layer-presence map (includes "HTTP" if request layer exists).
     *
     * Workflow:
     *   1. Call HTTPPacket constructor (and thus all base-class logic).
     *   2. Invoke generateHash(), which:
     *        - Retrieves the HttpRequestLayer (if present).
     *        - Extracts URI, HTTP method, and Accept header.
     *        - Builds a comma-separated string: "<URI>,<method>,<acceptValue>".
     *        - Computes SHA-256 over that string and stores it in `hash`.
     *   3. Call removeRawPayloadIfPresent(), which:
     *        - If "Raw" is in layerMap, find the HttpRequestLayer.
     *        - Remove all layers after it (thus stripping any payload).
     *        - Recompute checksums/lengths.
     */
    HTTPRequestPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
                      std::unordered_map<std::string, std::string> addressMapping = {},
                      std::unordered_map<std::string, bool> layerMap = {})
        : HTTPPacket(std::move(rawPacketPointer), addressMapping, layerMap)
    {
        generateHash();
        removeRawPayloadIfPresent();
    }

    /**
     * @brief Replace the original HttpRequestLayer with a CustomHTTPRequest, copying key fields.
     *
     * Workflow:
     *   1. Call TransportPacket::header_preprocessing() to ensure all lower-layer logic has run.
     *   2. Locate the existing HttpRequestLayer (Packet.getLayerOfType<HttpRequestLayer>).
     *   3. Create a new CustomHTTPRequest instance (allocates on heap via make_unique).
     *   4. Copy:
     *        - Method (GET, POST, etc.) into fields[0].
     *        - URI path into fields[1].
     *        - Common headers (User-Agent, Content-Type, Connection, Accept, Accept-Charset,
     *          Accept-Encoding, Cookie, TE) into corresponding indices of CustomHTTPRequest.fields.
     *   5. Remove the original HTTPRequestLayer from Packet (Packet.removeLayer(HttpRequest)).
     *   6. Add the custom layer (Packet.addLayer(customReq.release())).
     *   7. Recompute checksums/lengths (Packet.computeCalculateFields()).
     */
    void header_preprocessing() override {
        // First, perform any transport-layer substitutions
        HTTPPacket::header_preprocessing();

        // Extract the original HTTP request layer
        pcpp::HttpRequestLayer* origLayer = Packet.getLayerOfType<pcpp::HttpRequestLayer>();
        if (origLayer) {
            // Allocate a new CustomHTTPRequest to hold rewritten header fields
            std::unique_ptr<CustomHTTPRequest> customReq = std::make_unique<CustomHTTPRequest>();

            // 1) Copy HTTP method (GET, POST, etc.)
            std::string method = httpMethodEnumToString(origLayer->getFirstLine()->getMethod());
            customReq->fields[0].value = method;

            // 2) Copy request URI
            std::string uri = origLayer->getFirstLine()->getUri();
            customReq->fields[1].value = uri;

            // 3) Copy common headers by name into designated indices
            auto copyHeader = [&](const std::string& name, int idx) {
                pcpp::HeaderField* fld = origLayer->getFieldByName(name);
                if (fld) {
                    customReq->fields[idx].value = fld->getFieldValue();
                }
            };
            copyHeader("User-Agent",      2);
            copyHeader("Content-Type",    3);
            copyHeader("Connection",      4);
            copyHeader("Accept",          5);
            copyHeader("Accept-Charset",  6);
            copyHeader("Accept-Encoding", 7);
            copyHeader("Cookie",          8);
            copyHeader("TE",              9);

            // 4) Remove the original HTTP request layer
            Packet.removeLayer(pcpp::HTTPRequest);

            // 5) Insert the CustomHTTPRequest layer into the packet
            Packet.addLayer(customReq.release());

            // 6) Recompute checksums and length fields for all affected headers
            Packet.computeCalculateFields();
        }

        // No further HTTP-specific preprocessing; return to caller
    }

private:
    /**
     * @brief Build a SHA-256 hash from selected HTTP request fields (URI, method, Accept).
     *
     * Steps:
     *   1. Locate the HttpRequestLayer via getLayerOfType<HttpRequestLayer>().
     *   2. Extract the URI path, HTTP method enum converted to string, and the Accept header (if present).
     *   3. Concatenate them: "<path>,<method>,<acceptValue>".
     *   4. Call SHA256(input.c_str(), length, digest), then hex-encode digest into `hash`.
     *
     * Why:
     *   - Create a concise fingerprint of the request’s most important identifying fields.
     */
    void generateHash() {
        pcpp::HttpRequestLayer* httpRequestLayer = Packet.getLayerOfType<pcpp::HttpRequestLayer>();
        if (httpRequestLayer != nullptr) {
            std::string path = httpRequestLayer->getFirstLine()->getUri();
            std::string method = httpMethodEnumToString(httpRequestLayer->getFirstLine()->getMethod());
            std::string accept = "";
            if (auto* fld = httpRequestLayer->getFieldByName("Accept")) {
                accept = fld->getFieldValue();
            }

            std::string input = path + "," + method + "," + accept;
            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), digest);

            std::ostringstream oss;
            oss << std::hex << std::setw(2) << std::setfill('0');
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                oss << (int)digest[i];
            }
            hash = oss.str();
        }
    }

    /**
     * @brief Convert an HttpMethod enum to its string representation (e.g., HttpGET → "GET").
     *
     * @param method  The HttpMethod enum value from PcapPlusPlus.
     * @return std::string  Uppercase string of the HTTP method name, or "UNKNOWN" if not recognized.
     */
    std::string httpMethodEnumToString(pcpp::HttpRequestLayer::HttpMethod method) {
        switch (method) {
            case pcpp::HttpRequestLayer::HttpMethod::HttpGET:     return "GET";
            case pcpp::HttpRequestLayer::HttpMethod::HttpHEAD:    return "HEAD";
            case pcpp::HttpRequestLayer::HttpMethod::HttpPOST:    return "POST";
            case pcpp::HttpRequestLayer::HttpMethod::HttpPUT:     return "PUT";
            case pcpp::HttpRequestLayer::HttpMethod::HttpDELETE:  return "DELETE";
            case pcpp::HttpRequestLayer::HttpMethod::HttpTRACE:   return "TRACE";
            case pcpp::HttpRequestLayer::HttpMethod::HttpOPTIONS: return "OPTIONS";
            case pcpp::HttpRequestLayer::HttpMethod::HttpCONNECT: return "CONNECT";
            case pcpp::HttpRequestLayer::HttpMethod::HttpPATCH:   return "PATCH";
            default:                                              return "UNKNOWN";
        }
    }

    /**
     * @brief If a "Raw" payload layer is present (and no higher protocol like HTTP is acting on it),
     *        strip all layers that follow the HttpRequestLayer.
     *
     * Workflow:
     *   1. Check if "Raw" is present in layer_map.
     *   2. Locate the HttpRequestLayer.
     *   3. Call Packet.removeAllLayersAfter(httpRequestLayer) to drop downstream payload layers.
     *   4. Recompute checksums/lengths.
     *
     * Why:
     *   - When an HTTP request is encapsulated in TLS or other layers, the raw payload is not
     *     relevant for higher-level analysis; stripping it prevents extraneous data from persisting.
     */
    void removeRawPayloadIfPresent() {
        if (layer_map.find("Raw") != layer_map.end()) {
            pcpp::HttpRequestLayer* httpRequestLayer = Packet.getLayerOfType<pcpp::HttpRequestLayer>();
            if (httpRequestLayer != nullptr) {
                Packet.removeAllLayersAfter(httpRequestLayer);
            }
            Packet.computeCalculateFields();
        }
    }
};

/**
 * @class HTTPResponsePacket
 * @brief Handles HTTP response–specific hashing and custom-layer replacement.
 *
 * Responsibilities:
 *   - Compute a response-specific SHA-256 hash based on Server, status code, and Connection header.
 *   - Optionally strip raw payload if a "Raw" layer is present.
 *   - In header_preprocessing(), replace pcpp::HttpResponseLayer with CustomHTTPResponse.
 */
class HTTPResponsePacket : public HTTPPacket {
public:
    /// Stores the SHA-256 hex digest of response-specific fields
    std::string hash;

    /**
     * @brief Constructor: compute an HTTP-response hash and possibly strip payload.
     *
     * @param rawPacketPointer  unique_ptr to the raw pcpp::RawPacket.
     * @param addressMapping    Inherited address-mapping from lower layers.
     * @param layerMap          Inherited layer-presence map (includes "HTTP" if response layer exists).
     *
     * Workflow:
     *   1. Call HTTPPacket constructor (and all base-class logic).
     *   2. generateHash():
     *        - Locate HttpResponseLayer.
     *        - Extract Server header (if present), status code, and Connection header.
     *        - Build input string "<serverValue>,<statusCode>,<connectionValue>".
     *        - Compute SHA-256 over that string and store in `hash`.
     *   3. removeHttpPayloadIfPresent():
     *        - If "Raw" is in layerMap, locate HttpResponseLayer.
     *        - Call Packet.removeAllLayersAfter(httpResponseLayer), stripping payload.
     *        - Recompute checksums/lengths.
     */
    HTTPResponsePacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
                       std::unordered_map<std::string, std::string> addressMapping = {},
                       std::unordered_map<std::string, bool> layerMap = {})
        : HTTPPacket(std::move(rawPacketPointer), addressMapping, layerMap)
    {
        generateHash();
        removeHttpPayloadIfPresent();
    }

    /**
     * @brief Replace the original HttpResponseLayer with a CustomHTTPResponse, copying key fields.
     *
     * Workflow:
     *   1. Call TransportPacket/HTTPPacket header_preprocessing to ensure lower-layer logic is done.
     *   2. Locate the existing HttpResponseLayer (Packet.getLayerOfType<HttpResponseLayer>).
     *   3. Allocate a new CustomHTTPResponse.
     *   4. Copy:
     *        - Status code from firstLine into fields[0].
     *        - Common headers (Connection, Content-Encoding, Content-Type, Server, Set-Cookie, Transfer-Encoding)
     *          into designated indices of CustomHTTPResponse.fields.
     *   5. Remove the original HTTPResponseLayer (Packet.removeLayer(HTTPResponse)).
     *   6. Add the custom layer (Packet.addLayer(customResp)), then recompute checksums/lengths.
     */
    void header_preprocessing() override {
        // First, perform any transport-layer and IP/Ethernet substitutions
        HTTPPacket::header_preprocessing();

        // Extract the original HTTP response layer
        pcpp::HttpResponseLayer* origLayer = Packet.getLayerOfType<pcpp::HttpResponseLayer>();
        if (origLayer) {
            // Allocate a new CustomHTTPResponse to hold rewritten header fields
            CustomHTTPResponse* customResp = new CustomHTTPResponse();

            // 1) Copy status code from the first line
            auto* firstLine = origLayer->getFirstLine();
            std::string status = firstLine ? std::to_string(firstLine->getStatusCode()) : std::string();
            customResp->fields[0].value = status;

            // 2) Copy common response headers by name into designated indices
            auto copyHeader = [&](const std::string& name, int idx) {
                pcpp::HeaderField* fld = origLayer->getFieldByName(name);
                if (fld) {
                    customResp->fields[idx].value = fld->getFieldValue();
                }
            };
            copyHeader("Connection",        1);
            copyHeader("Content-Encoding",  2);
            copyHeader("Content-Type",      3);
            copyHeader("Server",            4);
            copyHeader("Set-Cookie",        5);
            copyHeader("Transfer-Encoding", 6);

            // 3) Remove the original HTTP response layer
            Packet.removeLayer(pcpp::HTTPResponse);

            // 4) Insert the CustomHTTPResponse layer
            Packet.addLayer(customResp);

            // 5) Recompute checksums and lengths for all affected headers
            Packet.computeCalculateFields();
        }
    }

private:
    /**
     * @brief Build a SHA-256 hash from selected HTTP response fields (Server, status code, Connection).
     *
     * Steps:
     *   1. Locate the HttpResponseLayer via getLayerOfType<HttpResponseLayer>().
     *   2. Extract the "Server" header value (if present), the status code from firstLine, and the "Connection" header.
     *   3. Concatenate them: "<serverValue>,<statusCode>,<connectionValue>".
     *   4. Compute SHA-256 over that string and store in `hash`.
     *
     * Why:
     *   - Create a unique fingerprint of the response’s core identifying fields for indexing or deduplication.
     */
    void generateHash() {
        pcpp::HttpResponseLayer* respLayer = Packet.getLayerOfType<pcpp::HttpResponseLayer>();
        if (!respLayer) {
            return;
        }

        // Extract "Server" header (if it exists)
        std::string server;
        if (auto* fld = respLayer->getFieldByName("Server")) {
            server = fld->getFieldValue();
        }

        // Extract status code from the first line
        auto* firstLine = respLayer->getFirstLine();
        std::string statusCode = firstLine ? std::to_string(firstLine->getStatusCode()) : std::string();

        // Extract "Connection" header (if it exists)
        std::string connection;
        if (auto* fld = respLayer->getFieldByName("Connection")) {
            connection = fld->getFieldValue();
        }

        // Build the input string and compute SHA-256
        std::string input = server + "," + statusCode + "," + connection;
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), digest);

        std::ostringstream oss;
        oss << std::hex << std::setw(2) << std::setfill('0');
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            oss << static_cast<int>(digest[i]);
        }
        hash = oss.str();
    }

    /**
     * @brief If a "Raw" payload layer is present, strip all layers that follow the HttpResponseLayer.
     *
     * Workflow:
     *   1. Check if "Raw" is in layer_map.
     *   2. Locate the HttpResponseLayer via getLayerOfType<HttpResponseLayer>().
     *   3. Call Packet.removeAllLayersAfter(httpResponseLayer) to drop downstream payload.
     *   4. Recompute checksums/lengths (Packet.computeCalculateFields()).
     *
     * Why:
     *   - When an HTTP response is encapsulated in TLS or another higher-layer format, the raw data
     *     is not needed for HTTP-layer analysis; removing it prevents irrelevant bytes from persisting.
     */
    void removeHttpPayloadIfPresent() {
        if (layer_map.find("Raw") != layer_map.end()) {
            pcpp::HttpResponseLayer* httpResponseLayer = Packet.getLayerOfType<pcpp::HttpResponseLayer>();
            if (httpResponseLayer != nullptr) {
                Packet.removeAllLayersAfter(httpResponseLayer);
            }
            Packet.computeCalculateFields();
        }
    }
};