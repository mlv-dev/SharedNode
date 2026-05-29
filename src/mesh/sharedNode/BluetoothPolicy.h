#ifdef MODE_SHARED_NODE
#pragma once

/**
 * @file BluetoothPolicy.h
 * @brief SharedNode-specific Bluetooth pairing and client-clear policy.
 */

#include "PairingPolicy.h"

namespace SharedNode::BluetoothPolicy
{

/**
 * @brief Call-site policy for clearing known SharedNode/BLE clients.
 */
enum class KnownClientClearMode : uint8_t {
    /**
     * @brief Clear request must come from an active SharedNode admin app session.
     */
    REQUIRE_ACTIVE_ADMIN = 0,

    /**
     * @brief Local recovery/factory-reset path may clear without an app session.
     */
    LOCAL_RECOVERY = 1,
};

/**
 * @brief Chooses the SharedNode pairing slot and passkey.
 *
 * @return Pairing decision for the Bluetooth backend.
 */
Pairing beginPairing();

/**
 * @brief Attaches a known peer identity to its stored slot for a live connection.
 *
 * @param connHandle Live Bluetooth connection handle.
 * @param identity Stable peer bond identity reported by the backend.
 */
void rememberKnownConnection(uint16_t connHandle, const PeerIdentity &identity);

/**
 * @brief Resolves and stores the slot for an authenticated connection.
 *
 * @param connHandle Live Bluetooth connection handle.
 * @param identity Stable peer bond identity reported by the backend.
 * @return SharedNode slot assigned to the connection, or SharedNode::INVALID_SLOT.
 */
uint8_t resolveConnectionSlot(uint16_t connHandle, const PeerIdentity &identity);

/**
 * @brief Looks up the SharedNode slot currently bound to a live connection.
 *
 * @param connHandle Live Bluetooth connection handle.
 * @return SharedNode slot, or INVALID_SLOT when unresolved.
 */
uint8_t slotForConnection(uint16_t connHandle);

/**
 * @brief Clears the live SharedNode binding for a disconnected BLE handle.
 *
 * @param connHandle Bluetooth connection handle that closed.
 */
void clearConnection(uint16_t connHandle);

/**
 * @brief Logs the shared-node role associated with a resolved pairing slot.
 *
 * @param slot SharedNode slot returned by resolveConnectionSlot().
 */
void logResolvedPairingSlot(uint8_t slot);

/**
 * @brief Drops any passkey-reserved shared-node slot after pairing failure.
 */
void consumePendingPairingSlot();

/**
 * @brief Checks whether known shared-node/BLE client state may be cleared.
 *
 * @param operationName Human-readable operation name for logging.
 * @param mode Authorization mode for the call site.
 * @return true when the clear operation is allowed.
 */
bool canClearKnownClients(const char *operationName, KnownClientClearMode mode);

/**
 * @brief Clears known shared-node clients from the pairing policy.
 */
void clearKnownClients();

} // namespace SharedNode::BluetoothPolicy
#endif
