#pragma once

#include "transport.cpp" 
#include "PcapPlusPlusVersion.h"
#include "HttpLayer.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <map>

class HTTPPacket : public TransportPacket {
public:
    HTTPPacket(const pcpp::RawPacket& packet,
        std::unordered_map<std::string, std::string> addressMapping = {},
        std::unordered_map<std::string, bool> layerMap = {})
        : TransportPacket(packet, addressMapping, layerMap)
    {
    }

    void header_preprocessing() override
    {
        TransportPacket::header_preprocessing();
    }
};

class HTTPRequestPacket : public HTTPPacket {
    public:
        std::string hash;

        HTTPRequestPacket(const pcpp::RawPacket& packet,
                std::unordered_map<std::string, std::string> addressMapping = {},
                std::unordered_map<std::string, bool> layerMap = {})
                : HTTPPacket(packet, addressMapping, layerMap)
        {
            generateHash();
            removeRawPayloadIfPresent();
        }

        void header_preprocessing() override {
            // Extract the original HTTP request layer
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::HttpRequestLayer* origLayer = temporaryPacket.getLayerOfType<pcpp::HttpRequestLayer>();
            if (origLayer) {
                // Build a new CustomHTTPRequest and copy fields
                CustomHTTPRequest* customReq = new CustomHTTPRequest();
    
                // Copy Method and Path
                std::string method = httpMethodEnumToString(origLayer->getFirstLine()->getMethod());
                std::string uri    = origLayer->getFirstLine()->getUri();
                customReq->fields[0].value = method;
                customReq->fields[1].value = uri;
    
                // Copy other headers by name & index in CustomHTTPRequest.fields
                auto copyHeader = [&](const std::string& name, int idx) {
                    pcpp::HeaderField* fld = origLayer->getFieldByName(name);
                    if (fld)
                        customReq->fields[idx].value = fld->getFieldValue();
                };
                copyHeader("User-Agent",      2);
                copyHeader("Content-Type",    3);
                copyHeader("Connection",      4);
                copyHeader("Accept",          5);
                copyHeader("Accept-Charset",  6);
                copyHeader("Accept-Encoding", 7);
                copyHeader("Cookie",          8);
                copyHeader("TE",              9);
    
                // Replace the original HTTP layer with our custom one
                temporaryPacket.removeLayer(pcpp::HTTPRequest);
                temporaryPacket.addLayer(customReq);
                const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
                int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
                timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
                pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

                uint8_t* dataCopy = new uint8_t[modifiedDataLen];
                std::memcpy(dataCopy, modifiedData, modifiedDataLen);

                setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
            }
    
            // Continue base preprocessing
            HTTPPacket::header_preprocessing();
        }
    
    
    private:
        void generateHash()
        {
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::HttpRequestLayer* httpRequestLayer = temporaryPacket.getLayerOfType<pcpp::HttpRequestLayer>();
            if (httpRequestLayer != nullptr)
            {
                std::string path = httpRequestLayer->getFirstLine()->getUri();
                std::string method = httpMethodEnumToString(httpRequestLayer->getFirstLine()->getMethod());
                std::string accept = httpRequestLayer->getFieldByName("Accept") != nullptr ? httpRequestLayer->getFieldByName("Accept")->getFieldValue() : "";

                std::string input = path + "," + method + "," + accept;

                unsigned char digest[SHA256_DIGEST_LENGTH];
                SHA256((unsigned char*)input.c_str(), input.size(), digest);

                std::ostringstream oss;
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

                hash = oss.str();
            }
        }

        std::string httpMethodEnumToString(pcpp::HttpRequestLayer::HttpMethod method)
        {
            switch (method)
            {
                case pcpp::HttpRequestLayer::HttpMethod::HttpGET: return "GET";
                case pcpp::HttpRequestLayer::HttpMethod::HttpHEAD: return "HEAD";
                case pcpp::HttpRequestLayer::HttpMethod::HttpPOST: return "POST";
                case pcpp::HttpRequestLayer::HttpMethod::HttpPUT: return "PUT";
                case pcpp::HttpRequestLayer::HttpMethod::HttpDELETE: return "DELETE";
                case pcpp::HttpRequestLayer::HttpMethod::HttpTRACE: return "TRACE";
                case pcpp::HttpRequestLayer::HttpMethod::HttpOPTIONS: return "OPTIONS";
                case pcpp::HttpRequestLayer::HttpMethod::HttpCONNECT: return "CONNECT";
                case pcpp::HttpRequestLayer::HttpMethod::HttpPATCH: return "PATCH";
                default: return "UNKNOWN";
            }
        }

        void removeRawPayloadIfPresent()
        {
            if (layer_map.find("Raw") != layer_map.end())
            {
                pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
                pcpp::HttpRequestLayer* httpRequestLayer = temporaryPacket.getLayerOfType<pcpp::HttpRequestLayer>();
                if (httpRequestLayer != nullptr)
                {
                    temporaryPacket.removeAllLayersAfter(httpRequestLayer); // Simplified; depends on what you mean by "remove payload"
                }
            }
        }
};

class HTTPResponsePacket : public HTTPPacket {
    public:
        std::string hash;
    
        HTTPResponsePacket(const pcpp::RawPacket& packet,
                            std::unordered_map<std::string, std::string> addressMapping = {},
                            std::unordered_map<std::string, bool> layerMap = {})
            : HTTPPacket(packet, addressMapping, layerMap) {
            generateHash();
            removeHttpPayloadIfPresent();
        }

        void header_preprocessing() override {
            // Extract the original HTTP response layer
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::HttpResponseLayer* origLayer = temporaryPacket.getLayerOfType<pcpp::HttpResponseLayer>();
            if (origLayer) {
                // Instantiate CustomHTTPResponse and copy fields
                CustomHTTPResponse* customResp = new CustomHTTPResponse();
    
                // Copy Status_Code from the first line
                auto* firstLine = origLayer->getFirstLine();
                std::string status = firstLine ? std::to_string(firstLine->getStatusCode()) : std::string();
                customResp->fields[0].value = status;
    
                // Copy other headers by name & index
                auto copyHeader = [&](const std::string& name, int idx) {
                    pcpp::HeaderField* fld = origLayer->getFieldByName(name);
                    if (fld)
                        customResp->fields[idx].value = fld->getFieldValue();
                };
                copyHeader("Connection",           1);
                copyHeader("Content-Encoding",     2);
                copyHeader("Content-Type",         3);
                copyHeader("Server",               4);
                copyHeader("Set-Cookie",           5);
                copyHeader("Transfer-Encoding",    6);
    
                // Replace the original HTTP layer with our custom one
                temporaryPacket.removeLayer(pcpp::HTTPResponse);
                temporaryPacket.addLayer(customResp);
                const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
                int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
                timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
                pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

                uint8_t* dataCopy = new uint8_t[modifiedDataLen];
                std::memcpy(dataCopy, modifiedData, modifiedDataLen);

                // 4. Replace the RawPacket in FIPPacket
                setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
            }
    
            // Continue base preprocessing
            HTTPPacket::header_preprocessing();
    }
    
    private:
        void generateHash() {
            // Locate the HTTP response layer
            pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
            pcpp::HttpResponseLayer* respLayer = temporaryPacket.getLayerOfType<pcpp::HttpResponseLayer>();
            if (!respLayer) return;
    
            // Extract fields for hashing
            std::string server;
            if (auto* fld = respLayer->getFieldByName("Server"))
                server = fld->getFieldValue();
    
            // Status code from the first line
            auto* firstLine = respLayer->getFirstLine();
            std::string statusCode = firstLine ? std::to_string(firstLine->getStatusCode()) : std::string();
    
            std::string connection;
            if (auto* fld = respLayer->getFieldByName("Connection"))
                connection = fld->getFieldValue();
    
            // Build input string and compute MD5
            std::string input = server + "," + statusCode + "," + connection;
            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), digest);
    
            std::ostringstream oss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    
            hash = oss.str();
        }
    
        void removeHttpPayloadIfPresent() {
            // If the Raw layer is indicated in layerMap, strip whatever payload follows the HTTP layer
            if (layer_map.find("Raw") != layer_map.end()) {
                pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
                pcpp::HttpResponseLayer* httpRequestLayer = temporaryPacket.getLayerOfType<pcpp::HttpResponseLayer>();
                if (httpRequestLayer != nullptr) {
                    temporaryPacket.removeAllLayersAfter(httpRequestLayer); // Simplified; depends on what you mean by "remove payload"
                }
                const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
                int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
                timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
                pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

                uint8_t* dataCopy = new uint8_t[modifiedDataLen];
                std::memcpy(dataCopy, modifiedData, modifiedDataLen);

                setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
            }
        }
 };