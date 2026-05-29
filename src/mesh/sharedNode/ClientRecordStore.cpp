#ifdef MODE_SHARED_NODE
#include "ClientRecordStore.h"

#include "configuration.h"

#include <algorithm>

namespace SharedNode::ClientRecordStore
{

void reset(Records &records)
{
    records = {};
    for (ClientRecord &record : records) {
        record.connectionState = ConnectionState::EMPTY;
    }
}

void copyForPolicy(const Records &source, ClientRecord *dest, size_t maxRecords)
{
    if (!dest) {
        return;
    }

    const size_t count = std::min(maxRecords, source.size());
    for (size_t i = 0; i < count; i++) {
        dest[i] = source[i];
        if (dest[i].connectionState == ConnectionState::ACTIVE) {
            dest[i].connectionState = ConnectionState::NOT_ACTIVE;
        }
        dest[i].connHandle = 0;
    }
    for (size_t i = count; i < maxRecords; i++) {
        dest[i] = ClientRecord{};
        dest[i].connectionState = ConnectionState::EMPTY;
    }
}

void replaceFromPolicy(Records &dest, const ClientRecord *source, size_t recordCount)
{
    reset(dest);
    if (!source) {
        return;
    }

    const size_t count = std::min(recordCount, dest.size());
    for (size_t i = 0; i < count; i++) {
        dest[i] = source[i];
    }
}

void loadFromProto(Records &records, const meshtastic_SharedNodeClientStore &store)
{
    reset(records);

    for (pb_size_t i = 0; i < store.clients_count && i < records.size(); ++i) {
        const meshtastic_SharedNodeClient &raw = store.clients[i];
        ClientRecord &record = records[i];
        loadClientRecordFromProto(record, raw);

        const bool hasPeerIdentity = raw.peer_identity[0] != '\0';
        if (record.connectionState == ConnectionState::ACTIVE) {
            record.connectionState = ConnectionState::NOT_ACTIVE;
        }
        if (!hasPeerIdentity &&
            (record.connectionState == ConnectionState::NOT_ACTIVE || record.connectionState == ConnectionState::ACTIVE)) {
            record.connectionState = ConnectionState::EMPTY;
        }
        if (record.connectionState == ConnectionState::EMPTY) {
            record = ClientRecord{};
            record.connectionState = ConnectionState::EMPTY;
        } else if (!hasPeerIdentity) {
            record.peerIdentity.clear();
        }
    }
}

void saveToProto(const Records &records, meshtastic_SharedNodeClientStore &store)
{
    store = meshtastic_SharedNodeClientStore_init_zero;
    for (const ClientRecord &record : records) {
        if (store.clients_count >= sizeof(store.clients) / sizeof(store.clients[0])) {
            LOG_WARN("Client record count exceeds protobuf capacity, truncating");
            break;
        }

        meshtastic_SharedNodeClient &raw = store.clients[store.clients_count++];
        const bool hasVirtualClientIdentity = record.virtualNodeId != 0;
        saveClientRecordToProto(raw, record, hasVirtualClientIdentity);
    }
}

} // namespace SharedNode::ClientRecordStore
#endif
