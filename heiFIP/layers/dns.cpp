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
    DNSPacket(const pcpp::RawPacket& packet,
        std::unordered_map<std::string, std::string> addressMapping = {},
        std::unordered_map<std::string, bool> layerMap = {})
        : TransportPacket(packet, addressMapping, layerMap)
    {
        // Base constructor handles transport-layer setup.
    }

    /**
     * Override this method to insert CustomDNS, CustomDNSQR, and
     * CustomDNSRR layers as needed before lower-layer checks.
     */
    void header_preprocessing() override {
        // Locate original DNS layer
        pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
        pcpp::DnsLayer* origDns = temporaryPacket.getLayerOfType<pcpp::DnsLayer>();
        pcpp::dnshdr* dnsHeader =  origDns->getDnsHeader();
        if (!origDns) {
            TransportPacket::header_preprocessing();
            return;
        }

        // Preprocess each section if present
        if (origDns->getQueryCount() > 0)        headerPreprocessingMessageType(origDns, "qd");
        if (origDns->getAnswerCount() > 0)          headerPreprocessingMessageType(origDns, "an");
        if (origDns->getAuthorityCount() >0) headerPreprocessingMessageType(origDns, "ns");
        if (origDns->getAdditionalRecordCount() > 0) headerPreprocessingMessageType(origDns, "ar");

        // Build new CustomDNS header
        CustomDNS* customDns = new CustomDNS();
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
        customDns->qdCount = origDns->getQueryCount();
        customDns->anCount = origDns->getAnswerCount();
        customDns->nsCount = origDns->getAuthorityCount();
        customDns->arCount = origDns->getAdditionalRecordCount();

        // Replace original DNS layer with custom header
        temporaryPacket.removeLayer(pcpp::DNS);
        temporaryPacket.addLayer(customDns);
        const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
        int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
        timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
        pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

        uint8_t* dataCopy = new uint8_t[modifiedDataLen];
        std::memcpy(dataCopy, modifiedData, modifiedDataLen);

        setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
        // Continue up the chain
        TransportPacket::header_preprocessing();
    }
    private:

    void headerPreprocessingMessageType(pcpp::DnsLayer* origDns, const std::string& messageType) {
        if (messageType == "qd") {
            // Questions: use first and next query functions
            pcpp::DnsQuery* q = origDns->getFirstQuery();
            while (q) {
                CustomDNSQR* qrLayer = new CustomDNSQR(q->getName(), q->getDnsType());
                pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
                temporaryPacket.addLayer(qrLayer);
                q = origDns->getNextQuery(q);
                const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
                int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
                timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
                pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

                uint8_t* dataCopy = new uint8_t[modifiedDataLen];
                std::memcpy(dataCopy, modifiedData, modifiedDataLen);

                // 4. Replace the RawPacket in FIPPacket
                setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
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
                pcpp::Packet temporaryPacket = pcpp::Packet(getRawPacket().get());
                CustomDNSRR* rrLayer = new CustomDNSRR(r->getName(), r->getDnsType(), r->getTTL());
                temporaryPacket.addLayer(rrLayer);
                const uint8_t* modifiedData = temporaryPacket.getRawPacket()->getRawData();
                int modifiedDataLen = temporaryPacket.getRawPacket()->getRawDataLen();
                timespec ts = temporaryPacket.getRawPacket()->getPacketTimeStamp();
                pcpp::LinkLayerType linkType = temporaryPacket.getRawPacket()->getLinkLayerType();

                uint8_t* dataCopy = new uint8_t[modifiedDataLen];
                std::memcpy(dataCopy, modifiedData, modifiedDataLen);

                // 4. Replace the RawPacket in FIPPacket
                setRawPacket(std::make_unique<pcpp::RawPacket>(dataCopy, modifiedDataLen, ts, false, linkType));
                if (messageType == "an")
                    r = origDns->getNextAnswer(r);
                else if (messageType == "ns")
                    r = origDns->getNextAuthority(r);
                else // "ar"
                    r = origDns->getNextAdditionalRecord(r);
            }
        }
    }
};