#pragma once

/**
 * @file BluetoothShared.h
 * @brief BLE helpers shared by platform-specific Bluetooth backends.
 */

#include <Arduino.h>

#ifdef MODE_SHARED_NODE
#include "mesh/sharedNode/BluetoothPolicy.h"
#endif

namespace bluetooth
{

/**
 * @brief Chooses the passkey for the next secure pairing attempt.
 *
 * In shared-node mode this delegates to SharedNode::PairingPolicy. In normal
 * mode it mirrors the configured fixed/random Bluetooth PIN behavior.
 *
 * @return Six-digit passkey value to present to the peer.
 */
uint32_t choosePairingPasskey();

/**
 * @brief Returns whether Bluetooth must require authenticated/encrypted access.
 *
 * @return true when BLE characteristics should require secure pairing.
 */
bool requiresSecurePairing();

/**
 * @brief Publishes pairing state to power/UI/status observers.
 *
 * @param passkey Numeric passkey to format as six digits.
 */
void showPairingPrompt(uint32_t passkey);

/**
 * @brief Publishes pairing state to power/UI/status observers.
 *
 * The string overload preserves leading zeroes from BLE stacks that provide
 * passkeys as ASCII digits.
 *
 * @param passkeyText Six-digit passkey text to show.
 */
void showPairingPrompt(const char *passkeyText);

/**
 * @brief Clears any active pairing prompt from the display.
 */
void clearPairingPrompt();

/**
 * @brief Publishes a connected Bluetooth status update.
 */
void notifyConnected();

/**
 * @brief Publishes a disconnected Bluetooth status update and clears pairing UI.
 */
void notifyDisconnected();

#ifdef MODE_SHARED_NODE
using KnownClientClearMode = SharedNode::BluetoothPolicy::KnownClientClearMode;

/**
 * @brief Forces shared-node Bluetooth config to the required random PIN mode.
 *
 * SharedNode pairing uses random admin PINs and fixed guest PINs from the
 * pairing policy, so the user-visible Bluetooth mode must stay random.
 */
void enforceSharedNodePairingMode();

/**
 * @brief Attaches a known peer identity to its stored slot for a live connection.
 *
 * This reconnect path is used before a new pairing flow when the backend can
 * already resolve the peer's durable bond identity.
 *
 * @param connHandle Live Bluetooth connection handle.
 * @param identity Stable peer bond identity reported by the backend.
 */
void rememberKnownConnection(uint16_t connHandle, const SharedNode::PeerIdentity &identity);

/**
 * @brief Resolves and stores the slot for an authenticated connection.
 *
 * @param connHandle Live Bluetooth connection handle.
 * @param identity Stable peer bond identity reported by the backend.
 * @return SharedNode slot assigned to the connection, or SharedNode::INVALID_SLOT.
 */
uint8_t resolveConnectionSlot(uint16_t connHandle, const SharedNode::PeerIdentity &identity);

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
bool canClearKnownClients(const char *operationName,
                          KnownClientClearMode mode = KnownClientClearMode::REQUIRE_ACTIVE_ADMIN);

/**
 * @brief Clears known shared-node clients from the pairing policy.
 */
void clearKnownClients();

/**
 * @brief FNV-1a hash used for non-sensitive identity fingerprints.
 *
 * @param data Bytes to hash.
 * @param length Number of bytes in @p data.
 * @return 32-bit FNV-1a hash.
 */
uint32_t fnv1a32(const uint8_t *data, size_t length);

/**
 * @brief Returns true when a byte address is all zeroes or missing.
 *
 * @param data Address bytes to inspect.
 * @param length Number of bytes in @p data.
 * @return true when @p data is null or contains only zero bytes.
 */
bool addressIsEmpty(const uint8_t *data, size_t length);
#endif

} // namespace bluetooth
