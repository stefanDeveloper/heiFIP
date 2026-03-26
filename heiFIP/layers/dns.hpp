#pragma once

#include <map>
#include <string>
#include <DnsLayer.h>

#include "transport.hpp"

/**
 * @class DNSPacket
 * @brief Extends TransportPacket to handle DNS-specific header and resource-record manipulation.
 *
 * Responsibilities:
 *   - Inherit all Ethernet, IP, and transport-level rewriting and hashing logic.
 *   - Locate the pcpp::DnsLayer, inspect query/answer/authority/additional sections.
 *   - Insert CustomDNS header and individual CustomDNSQR/CustomDNSRR layers for each record.
 *   - Remove the original DnsLayer and recompute checksums/lengths.
 */
class DNSPacket : public TransportPacket {
public:
    /**
     * @brief Constructor: delegates raw-packet ownership and layer maps to TransportPacket.
     *
     * @param rawPacketPointer  unique_ptr to the raw pcpp::RawPacket containing full packet bytes.
     * @param addressMapping    Mapping of original→new MAC/IP addresses (populated previously).
     * @param layerMap          Map of protocol layers present (Ethernet, IP, TCP/UDP, DNS).
     *
     * Workflow:
     *   1. Calls TransportPacket’s constructor, which in turn:
     *        - Rewrites Ethernet MACs (EtherPacket).
     *        - Rewrites IP addresses and computes IP-header hash (IPPacket).
     *        - Computes transport-layer hash and optionally strips payload (TransportPacket).
     *   2. No DNS-specific work is done here; header_preprocessing() does the heavy lifting.
     */
    DNSPacket(std::unique_ptr<pcpp::RawPacket> rawPacketPointer,
              std::unordered_map<std::string, std::string> addressMapping = {},
              std::unordered_map<std::string, bool> layerMap = {})
        : TransportPacket(std::move(rawPacketPointer), addressMapping, layerMap)
    {
        // Base constructor handles transport-layer setup; DNS logic in header_preprocessing().
    }

    /**
     * @brief Insert CustomDNS, CustomDNSQR, and CustomDNSRR layers as needed.
     *
     * Workflow:
     *   1. Locate the existing DnsLayer via Packet.getLayerOfType<pcpp::DnsLayer>().
     *      If none, return immediately.
     *   2. For each DNS section (question, answer, authority, additional):
     *        a. If the section count > 0, call headerPreprocessingMessageType() with the DnsLayer and
     *           the section code ("qd" for questions, "an" for answers, "ns" for authority, "ar" for additional).
     *        b. headerPreprocessingMessageType() will iterate through each record in that section,
     *           create a new CustomDNSQR (for questions) or CustomDNSRR (for resource records), and add it.
     *        c. After adding each CustomDNSQR/CustomDNSRR, call Packet.computeCalculateFields() to update checksums.
     *
     *   3. After populating individual record layers, rebuild the DNS header itself:
     *        a. Retrieve the (possibly updated) DnsLayer via Packet.getLayerOfType<pcpp::DnsLayer>().
     *        b. Read fields from its dnshdr (queryOrResponse, opcode, aa, tc, rd, ra, z, ad, cd, rcode, and section counts).
     *        c. Build a new CustomDNS instance with those header fields.
     *        d. Insert CustomDNS into the packet just before the old DnsLayer’s position.
     *        e. Detach and delete the original DnsLayer.
     *        f. Call Packet.computeCalculateFields() to recalculate lengths and checksums upstream of the new DNS header.
     */
    void header_preprocessing() override {
        // First, perform any transport-layer and IP/Ethernet substitutions
        TransportPacket::header_preprocessing();

        // 1) Find the existing DnsLayer for preprocessing
        pcpp::DnsLayer* oldDNSForMessageProcessing = Packet.getLayerOfType<pcpp::DnsLayer>();
        if (!oldDNSForMessageProcessing) {
            // No DNS layer present; nothing to do
            return;
        }

        // 2) Process each DNS section individually: question (qd), answer (an), authority (ns), additional (ar)
        if (oldDNSForMessageProcessing->getQueryCount() > 0) {
            headerPreprocessingMessageType(oldDNSForMessageProcessing, "qd");
        }
        if (oldDNSForMessageProcessing->getAnswerCount() > 0) {
            headerPreprocessingMessageType(oldDNSForMessageProcessing, "an");
        }
        if (oldDNSForMessageProcessing->getAuthorityCount() > 0) {
            headerPreprocessingMessageType(oldDNSForMessageProcessing, "ns");
        }
        if (oldDNSForMessageProcessing->getAdditionalRecordCount() > 0) {
            headerPreprocessingMessageType(oldDNSForMessageProcessing, "ar");
        }

        // 3) After processing individual records, replace the DNS header itself
        pcpp::DnsLayer* oldDNS = Packet.getLayerOfType<pcpp::DnsLayer>();
        pcpp::dnshdr* dnsHeader = oldDNS->getDnsHeader();

        // Build a new CustomDNS header using fields from the old DNS header
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

        // Insert the new CustomDNS layer immediately before the old DNS layer
        pcpp::Layer* prev = oldDNS->getPrevLayer();
        Packet.insertLayer(prev, customDns.release());

        // Detach and delete the old DNS layer
        Packet.detachLayer(oldDNS);
        delete oldDNS;

        // Recompute checksums and lengths for all layers upstream of the new DNS header
        Packet.computeCalculateFields();
    }

private:
    /**
     * @brief Process DNS “question” or “resource-record” sections by inserting custom layers.
     *
     * @param origDns      Pointer to the original pcpp::DnsLayer being processed.
     * @param messageType  One of:
     *                      - "qd" : question section
     *                      - "an" : answer section
     *                      - "ns" : authority section
     *                      - "ar" : additional section
     *
     * Workflow for "qd" (question):
     *   1. Call origDns->getFirstQuery() to retrieve the first DnsQuery.
     *   2. While query != nullptr:
     *        a. Create CustomDNSQR(name, type) using q->getName(), q->getDnsType().
     *        b. Add it as a new layer: Packet.addLayer(qrLayer.release()).
     *        c. Recompute checksums/lengths (Packet.computeCalculateFields()).
     *        d. Move to the next query: origDns->getNextQuery(q).
     *
     * Workflow for "an"/"ns"/"ar" (resource records):
     *   1. Depending on messageType, call:
     *        - getFirstAnswer() for "an"
     *        - getFirstAuthority() for "ns"
     *        - getFirstAdditionalRecord() for "ar"
     *   2. While resource record != nullptr:
     *        a. Create CustomDNSRR(name, type, TTL) using r->getName(), r->getDnsType(), r->getTTL().
     *        b. Add the custom RR layer: Packet.addLayer(rrLayer.release()).
     *        c. Recompute checksums/lengths (Packet.computeCalculateFields()).
     *        d. Advance to next record:
     *            • getNextAnswer(r) if messageType == "an"
     *            • getNextAuthority(r) if messageType == "ns"
     *            • getNextAdditionalRecord(r) if messageType == "ar"
     */
    void headerPreprocessingMessageType(pcpp::DnsLayer* origDns, const std::string& messageType) {
        if (messageType == "qd") {
            // Process question section
            pcpp::DnsQuery* q = origDns->getFirstQuery();
            while (q) {
                // Insert a CustomDNSQR for each question name/type
                std::unique_ptr<CustomDNSQR> qrLayer = std::make_unique<CustomDNSQR>(q->getName(), q->getDnsType());
                Packet.addLayer(qrLayer.release());
                Packet.computeCalculateFields();  // Update lengths/checksums after adding

                // Advance to next question
                q = origDns->getNextQuery(q);
            }
        } 
        else {
            // Process resource-record sections (answer, authority, additional)
            pcpp::DnsResource* r = nullptr;
            if (messageType == "an") {
                r = origDns->getFirstAnswer();
            } else if (messageType == "ns") {
                r = origDns->getFirstAuthority();
            } else { // messageType == "ar"
                r = origDns->getFirstAdditionalRecord();
            }
            while (r) {
                // Insert a CustomDNSRR(name, type, TTL) for each resource record
                std::unique_ptr<CustomDNSRR> rrLayer = std::make_unique<CustomDNSRR>(
                    r->getName(),
                    r->getDnsType(),
                    r->getTTL()
                );
                Packet.addLayer(rrLayer.release());
                Packet.computeCalculateFields();  // Update lengths/checksums after adding

                // Advance to next record in the respective section
                if (messageType == "an") {
                    r = origDns->getNextAnswer(r);
                } else if (messageType == "ns") {
                    r = origDns->getNextAuthority(r);
                } else { // "ar"
                    r = origDns->getNextAdditionalRecord(r);
                }
            }
        }
    }
};