#ifdef MODE_SHARED_NODE
#pragma once

/**
 * @file SharedNodeRecordProto.h
 * @brief Conversion helpers for persisted shared-node client records.
 */

#include "Types.h"
#include "meshtastic/deviceonly.pb.h"

#include <cstring>

namespace SharedNode
{

inline void loadClientRecordFromProto(ClientRecord &record, const meshtastic_SharedNodeClient &raw)
{
    record = ClientRecord{};
    record.connHandle = 0;
    record.virtualNodeId = raw.virtual_node_id;
    strncpy(record.shortName, raw.short_name, sizeof(record.shortName) - 1);
    strncpy(record.longName, raw.long_name, sizeof(record.longName) - 1);
    record.peerIdentity = raw.peer_identity;
    record.registerTime = raw.register_time;
    record.lastSeen = raw.last_seen;
    record.connectionState = connectionStateFromValue(raw.connection_state);

    if (raw.public_key.size == PKI_KEY_SIZE && raw.private_key.size == PKI_KEY_SIZE) {
        memcpy(record.publicKey, raw.public_key.bytes, PKI_KEY_SIZE);
        memcpy(record.privateKey, raw.private_key.bytes, PKI_KEY_SIZE);
    }
}

inline void saveClientRecordToProto(meshtastic_SharedNodeClient &raw, const ClientRecord &record, bool saveVirtualClientKeys = true)
{
    memset(&raw, 0, sizeof(raw));
    raw.virtual_node_id = record.virtualNodeId;
    strncpy(raw.short_name, record.shortName, sizeof(raw.short_name) - 1);
    strncpy(raw.long_name, record.longName, sizeof(raw.long_name) - 1);
    strncpy(raw.peer_identity, record.peerIdentity.c_str(), sizeof(raw.peer_identity) - 1);
    raw.register_time = record.registerTime;
    raw.last_seen = record.lastSeen;
    if (saveVirtualClientKeys) {
        raw.public_key.size = PKI_KEY_SIZE;
        memcpy(raw.public_key.bytes, record.publicKey, PKI_KEY_SIZE);
        raw.private_key.size = PKI_KEY_SIZE;
        memcpy(raw.private_key.bytes, record.privateKey, PKI_KEY_SIZE);
    }

    const ConnectionState storedState =
        (record.connectionState == ConnectionState::ACTIVE) ? ConnectionState::NOT_ACTIVE : record.connectionState;
    raw.connection_state = static_cast<uint32_t>(storedState);
}

} // namespace SharedNode
#endif
