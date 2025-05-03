#pragma onces

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
    DNSPacket(pcpp::Packet& packet,
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
        pcpp::DnsLayer* origDns = packet.getLayerOfType<pcpp::DnsLayer>();
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
        packet.removeLayer(pcpp::DNS);
        packet.addLayer(customDns);

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
                packet.addLayer(qrLayer);
                q = origDns->getNextQuery(q);
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
                CustomDNSRR* rrLayer = new CustomDNSRR(r->getName(), r->getDnsType(), r->getTTL());
                packet.addLayer(rrLayer);
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