#ifdef MODE_SHARED_NODE
#pragma once

/**
 * @file ClientRecordStore.h
 * @brief Helpers for loading and saving persisted SharedNode client records.
 */

#include "RecordProto.h"

#include <array>
#include <cstddef>

namespace SharedNode::ClientRecordStore
{

/**
 * @brief Fixed-size persisted SharedNode client table.
 */
using Records = std::array<ClientRecord, MAX_CLIENTS>;

/**
 * @brief Resets all client records to the empty state.
 *
 * @param records Table to reset.
 */
void reset(Records &records);

/**
 * @brief Copies records for PairingPolicy and strips runtime-only connection state.
 *
 * @param source Stored records owned by NodeDB.
 * @param dest Destination buffer.
 * @param maxRecords Number of entries available in @p dest.
 */
void copyForPolicy(const Records &source, ClientRecord *dest, size_t maxRecords);

/**
 * @brief Replaces stored records with a policy-owned snapshot.
 *
 * @param dest Stored records owned by NodeDB.
 * @param source Source records supplied by PairingPolicy.
 * @param recordCount Number of entries available in @p source.
 */
void replaceFromPolicy(Records &dest, const ClientRecord *source, size_t recordCount);

/**
 * @brief Loads records from the persisted protobuf store.
 *
 * @param records Destination table to replace.
 * @param store Decoded protobuf store.
 */
void loadFromProto(Records &records, const meshtastic_SharedNodeClientStore &store);

/**
 * @brief Builds a protobuf store from the in-memory record table.
 *
 * @param records Source table.
 * @param store Destination protobuf store to overwrite.
 */
void saveToProto(const Records &records, meshtastic_SharedNodeClientStore &store);

} // namespace SharedNode::ClientRecordStore
#endif
