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

/**
 * @brief Restores an in-memory shared-node client record from its persisted protobuf form.
 *
 * Runtime-only fields, such as the live BLE connection handle, are reset while
 * durable identity fields are copied from storage. Invalid or incomplete key
 * material is ignored and left zeroed in the destination record.
 *
 * @param record Destination client record to overwrite.
 * @param raw Persisted protobuf record loaded from device state.
 */
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

/**
 * @brief Stores an in-memory shared-node client record into its persisted protobuf form.
 *
 * ACTIVE runtime state is persisted as NOT_ACTIVE because live connection
 * handles are valid only until reboot or BLE disconnect. Virtual client key
 * material can be omitted when callers need to persist slot metadata without
 * writing identity keys.
 *
 * @param raw Destination protobuf record to overwrite.
 * @param record Source client record.
 * @param saveVirtualClientKeys true to persist the virtual client's public and private keys.
 */
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
