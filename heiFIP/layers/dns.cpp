#pragma once

#include "transport.cpp"
#include <map>
#include <string>
#include <DnsLayer.h>

/**
 * DNSPacket wraps a raw packet into a TransportPacket and prepares
 * for DNS header and resource record manipulation using custom layers.
 */
class DNSPacket : public TransportPacket {
public:
    /**
     * Constructor: initializes base TransportPacket with given pcap Packet,
     * address mapping, and layer map.
     */
    DNSPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
        std::unordered_map<std::string, std::string> addressMapping = {},
        std::unordered_map<std::string, bool> layerMap = {})
        : TransportPacket(std::move(rawPacketPointer), addressMapping, layerMap)
    {
        // Base constructor handles transport-layer setup.
    }

    /**
     * Override this method to insert CustomDNS, CustomDNSQR, and
     * CustomDNSRR layers as needed before lower-layer checks.
     */
    void header_preprocessing() override {

         // 1) Find the DNS layer first for DNS preprocessing
        pcpp::DnsLayer* oldDNSForMessageProcessing = Packet.getLayerOfType<pcpp::DnsLayer>();
        if (!oldDNSForMessageProcessing) {
            return;
        }

        // Preprocess each section if present
        if (oldDNSForMessageProcessing->getQueryCount() > 0) {
            headerPreprocessingMessageType(oldDNSForMessageProcessing, "qd");
        }

        if (oldDNSForMessageProcessing->getAnswerCount() > 0) {
            headerPreprocessingMessageType(oldDNSForMessageProcessing, "an");
        }

        if (oldDNSForMessageProcessing->getAuthorityCount() >0) {
            headerPreprocessingMessageType(oldDNSForMessageProcessing, "ns");
        }

        if (oldDNSForMessageProcessing->getAdditionalRecordCount() > 0) {
            headerPreprocessingMessageType(oldDNSForMessageProcessing, "ar");
        }

        // 2) Create a second temporary packet now on the manipulated rawPacket where the new CustomDNS layer is swapped in
        pcpp::DnsLayer* oldDNS = Packet.getLayerOfType<pcpp::DnsLayer>();
        pcpp::dnshdr* dnsHeader =  oldDNS->getDnsHeader();

        // Build new CustomDNS header
        std::unique_ptr<CustomDNS> customDns = std::make_unique<CustomDNS>();
        customDns->qr      = dnsHeader->queryOrResponse;
        customDns->opcode  = static_cast<uint8_t>(dnsHeader->opcode);
        customDns->aa      = dnsHeader->authoritativeAnswer;
        customDns->tc      = dnsHeader->truncation;
        customDns->rd      = dnsHeader->recursionDesired;
        customDns->ra      = dnsHeader->recursionAvailable;
        customDns->z       = dnsHeader->zero;
        customDns->ad      = dnsHeader->authenticData;
        customDns->cd      = dnsHeader->checkingDisabled;
        customDns->rcode   = static_cast<uint8_t>(dnsHeader->responseCode);
        customDns->qdCount = oldDNS->getQueryCount();
        customDns->anCount = oldDNS->getAnswerCount();
        customDns->nsCount = oldDNS->getAuthorityCount();
        customDns->arCount = oldDNS->getAdditionalRecordCount();

        // 3) Insert your custom TCP layer right after whatever came before the old one
        pcpp::Layer* prev = oldDNS->getPrevLayer();
        Packet.insertLayer(prev, customDns.release());

        // 4) Now safely remove the old TCP layer object
        Packet.detachLayer(oldDNS);
        delete oldDNS;

        // 5) If your new layer changed any length/checksum fields upstream,
        //    recompute them on the packet
        Packet.computeCalculateFields();                    
    }
    private:

    void headerPreprocessingMessageType(pcpp::DnsLayer* origDns, const std::string& messageType) {
        if (messageType == "qd") {
            // Questions: use first and next query functions
            pcpp::DnsQuery* q = origDns->getFirstQuery();
            while (q) {
                std::unique_ptr<CustomDNSQR> qrLayer = std::make_unique<CustomDNSQR>(q->getName(), q->getDnsType());
                Packet.addLayer(qrLayer.release());
                q = origDns->getNextQuery(q);
                Packet.computeCalculateFields();
            }
        }
        else {
            // Resource records: answers, authority, additional
            pcpp::DnsResource* r = nullptr;
            if (messageType == "an")
                r = origDns->getFirstAnswer();
            else if (messageType == "ns")
                r = origDns->getFirstAuthority();
            else if (messageType == "ar")
                r = origDns->getFirstAdditionalRecord();

            while (r) {
                std::unique_ptr<CustomDNSRR> rrLayer = std::make_unique<CustomDNSRR>(r->getName(), r->getDnsType(), r->getTTL());
                Packet.addLayer(rrLayer.release());
                if (messageType == "an") {
                    r = origDns->getNextAnswer(r);
                } else if (messageType == "ns") {
                    r = origDns->getNextAuthority(r);
                } else { // "ar"
                    r = origDns->getNextAdditionalRecord(r);
                }
                Packet.computeCalculateFields();
            }
        }
    }
};