#ifdef MODE_SHARED_NODE
#pragma once

/**
 * @file SharedNodePairingPolicy.h
 * @brief Shared-node pairing role and slot assignment policy.
 */

#include "Types.h"
#include "mesh/generated/meshtastic/config.pb.h"
#include "mesh/generated/meshtastic/mesh.pb.h"
#include "static/SlotTable.h"
#include "concurrency/Lock.h"

#include <Arduino.h>
#include <array>

/**
 * @brief Assigns shared-node roles and slots to authenticated clients.
 *
 * SharedNodePairingPolicy keeps a small persisted table of known clients,
 * reserves slot 0 for the admin client, assigns guest slots to additional
 * clients, and bridges transient Bluetooth connection handles to stable
 * bonding identities supplied by the BLE backend.
 */
namespace SharedNode {

/**
 * @brief Pairing decision returned to the Bluetooth backend.
 */
struct Pairing {
    /**
     * @brief Passkey the backend should use for the pairing attempt.
     */
    uint32_t passkey = 0;

    /**
     * @brief Shared-node client slot selected for this pairing.
     */
    uint8_t slot = INVALID_SLOT;
};

class PairingPolicy
{
  public:
    using Role = SharedNode::Role;

    /**
     * @brief Creates a pairing policy backed by the internal static record table.
     */
    PairingPolicy();

    /**
     * @brief Chooses the slot and passkey for a new pairing attempt.
     *
     * The selected slot is kept as pending state until the backend resolves
     * the connection or consumes the pending pairing.
     *
     * @return Pairing decision for the Bluetooth backend.
     */
    Pairing beginPairing();

    /**
     * @brief Returns and clears the pending pairing slot.
     *
     * @return Pending slot, or INVALID_SLOT when none is pending.
     */
    uint8_t consumePendingPairingSlot();

    /**
     * @brief Returns the pending pairing slot without clearing it.
     *
     * @return Pending slot, or INVALID_SLOT when none is pending.
     */
    uint8_t peekPendingPairingSlot() const;

    /**
     * @brief Returns the role implied by a shared-node slot.
     *
     * @param slotIndex Shared-node client slot.
     * @return Role implied by the slot, or Role::UNKNOWN for invalid values.
     */
    static Role roleForSlot(uint8_t slotIndex) { return SharedNode::roleForSlot(slotIndex); }

    /**
     * @brief Returns and clears the pending pairing role implied by its slot.
     *
     * @return Pending role, or Role::UNKNOWN when none is pending.
     */
    Role consumePendingPairingRole() { return roleForSlot(consumePendingPairingSlot()); }

    /**
     * @brief Returns the pending pairing role implied by its slot.
     *
     * @return Pending role, or Role::UNKNOWN when none is pending.
     */
    Role peekPendingPairingRole() const { return roleForSlot(peekPendingPairingSlot()); }

    /**
     * @brief Looks up the role currently associated with a connection handle.
     *
     * @param connHandle Bluetooth connection handle.
     * @return Assigned role, or Role::UNKNOWN when unknown.
     */
    Role roleForConnection(uint16_t connHandle) const;

    /**
     * @brief Looks up the slot-implied role for a peer bond identity.
     *
     * @param identity Stable peer bond identity.
     * @return Assigned role, or Role::UNKNOWN when unknown.
     */
    Role roleForIdentity(const PeerIdentity &identity) const;

    /**
     * @brief Resolves a connection slot and returns its implied role.
     *
     * Existing bond identity records win first, then pending pairing state,
     * then a new admin or guest slot is selected if available.
     *
     * @param connHandle Bluetooth connection handle.
     * @param identity Stable peer bond identity reported by the backend.
     * @return Assigned role, or Role::UNKNOWN when no role is available.
     */
    Role resolveRoleForConnection(uint16_t connHandle, const PeerIdentity &identity);

    /**
     * @brief Resolves and records the slot for an authenticated connection.
     *
     * Existing bond identity records win first, then pending pairing state,
     * then a new admin or guest slot is selected if available.
     *
     * @param connHandle Bluetooth connection handle.
     * @param identity Stable peer bond identity reported by the backend.
     * @return Assigned slot, or INVALID_SLOT when no slot is available.
     */
    uint8_t resolveSlotForConnection(uint16_t connHandle, const PeerIdentity &identity);

    /**
     * @brief Checks whether an admin client identity is already known.
     *
     * @return true when the admin slot contains a known admin identity.
     */
    bool hasKnownAdmin() const;

    /**
     * @brief Looks up the shared-node slot associated with a connection handle.
     *
     * @param connHandle Bluetooth connection handle.
     * @return Slot index, or SharedNode::INVALID_SLOT when unknown.
     */
    uint8_t slotForConnection(uint16_t connHandle) const;

    /**
     * @brief Looks up the shared-node slot associated with a peer bond identity.
     *
     * @param identity Stable peer bond identity.
     * @return Slot index, or SharedNode::INVALID_SLOT when unknown.
     */
    uint8_t slotForIdentity(const PeerIdentity &identity) const;

    /**
     * @brief Returns the virtual node ID persisted for a slot.
     *
     * @param slotIndex Shared-node client slot.
     * @return Virtual node ID, or 0 when the slot is invalid or unassigned.
     */
    uint32_t virtualNodeIdForSlot(uint8_t slotIndex) const;

    /**
     * @brief Looks up the shared-node slot owning a virtual node ID.
     *
     * @param virtualNodeId Virtual node ID to find.
     * @return Slot index, or INVALID_SLOT when no record owns the ID.
     */
    uint8_t slotForVirtualNodeId(uint32_t virtualNodeId) const;

    /**
     * @brief Looks up the role associated with a virtual node ID.
     *
     * @param virtualNodeId Virtual node ID to find.
     * @return Slot-implied role, or Role::UNKNOWN when no record owns the ID.
     */
    Role roleForVirtualNodeId(uint32_t virtualNodeId) const;

    /**
     * @brief Persists the virtual node ID assigned to a shared-node slot.
     *
     * Guest display names are regenerated when a guest virtual node ID changes.
     *
     * @param slotIndex Shared-node client slot.
     * @param virtualNodeId Virtual node ID to store.
     * @return true when the slot contains a known identity and the ID was stored.
     */
    bool setVirtualNodeIdForSlot(uint8_t slotIndex, uint32_t virtualNodeId);

    /**
     * @brief Returns or creates the persisted virtual node ID for a guest slot.
     *
     * Allocation is owned by PairingPolicy because it can see every persisted
     * guest record, including inactive clients that do not have live sessions.
     *
     * @param slotIndex Shared-node guest slot.
     * @param virtualNodeId Output virtual node ID when successful.
     * @return true when the slot contains a known guest identity and has an ID.
     */
    bool ensureVirtualNodeIdForSlot(uint8_t slotIndex, uint32_t &virtualNodeId);

    /**
     * @brief Builds a User protobuf for a persisted virtual client identity.
     *
     * @param virtualNodeId Virtual node ID to read.
     * @param user Destination user protobuf.
     * @return true when the virtual identity exists.
     */
    bool buildVirtualUser(uint32_t virtualNodeId, meshtastic_User &user) const;

    /**
     * @brief Builds a security config with keys scoped to a virtual identity.
     *
     * Non-key security fields are copied from the device config, while
     * public_key/private_key come from the virtual client record. Admin keys
     * are included only for admin-scoped callers.
     *
     * @param virtualNodeId Virtual node ID to read.
     * @param security Destination security config.
     * @param includeAdminKeys true to preserve admin_key[] in the response.
     * @return true when the virtual identity exists.
     */
    bool buildVirtualSecurityConfig(uint32_t virtualNodeId, meshtastic_Config_SecurityConfig &security,
                                    bool includeAdminKeys) const;

    /**
     * @brief Updates the user-visible names of a virtual client identity.
     *
     * Empty/null name fields are ignored.
     *
     * @param virtualNodeId Virtual node ID to update.
     * @param shortName New short name, or null/empty to leave unchanged.
     * @param longName New long name, or null/empty to leave unchanged.
     * @return true when the virtual identity exists.
     */
    bool updateVirtualClientNames(uint32_t virtualNodeId, const char *shortName, const char *longName);

    /**
     * @brief Regenerates key material for a virtual client identity.
     *
     * @param virtualNodeId Virtual node ID to update.
     * @return true when new key material was generated and persisted.
     */
    bool regenerateVirtualClientKeys(uint32_t virtualNodeId);

    /**
     * @brief Updates virtual client keys from a security config.
     *
     * A valid 32-byte private_key is imported and its public key is derived.
     * Missing/invalid private_key requests a fresh generated keypair.
     *
     * @param virtualNodeId Virtual node ID to update.
     * @param security Security config containing key input.
     * @return true when key material was updated and persisted.
     */
    bool updateVirtualClientKeys(uint32_t virtualNodeId, const meshtastic_Config_SecurityConfig &security);

    /**
     * @brief Records a slot for a live connection after slot resolution.
     *
     * @param connHandle Bluetooth connection handle.
     * @param identity Stable peer bond identity reported by the backend.
     * @param slotIndex Shared-node slot assigned to the connection.
     */
    void rememberConnectionSlot(uint16_t connHandle, const PeerIdentity &identity, uint8_t slotIndex);

    /**
     * @brief Marks a connection handle as disconnected.
     *
     * @param connHandle Bluetooth connection handle to clear.
     */
    void clearConnection(uint16_t connHandle);

    /**
     * @brief Marks a slot after an explicit ToRadio.disconnect from a phone.
     *
     * The slot becomes DISCONNECTED rather than EMPTY. Its bond identity is
     * retained for reconnects, but new pairing may reuse it after EMPTY slots.
     *
     * @param slotIndex Shared-node client slot to mark disconnected.
     */
    void disconnectSlot(uint8_t slotIndex);

    /**
     * @brief Removes the persisted identity stored in one slot.
     *
     * @param slotIndex Shared-node client slot to invalidate.
     */
    void invalidateSlot(uint8_t slotIndex);

    /**
     * @brief Clears all known shared-node client identities.
     */
    void clearAll();

    /**
     * @brief Clears all known shared-node client identities.
     */
    void clearAllKnownClients() { clearAll(); }

#ifdef PIO_UNIT_TESTING
    ClientRecord &recordForTest(uint8_t slotIndex) { return records[slotIndex]; }
    const ClientRecord &recordForTest(uint8_t slotIndex) const { return records[slotIndex]; }
#endif

  private:
    /**
     * @brief Loads persisted client records from NodeDB if not loaded yet.
     *
     * @pre policyLock is held by the caller.
     */
    void loadFromNodeDBLocked();

    /**
     * @brief Saves current client records to NodeDB.
     *
     * @pre policyLock is held by the caller.
     */
    void persistToNodeDBLocked();

    /**
     * @brief Selects an admin or guest slot for a new pairing attempt.
     *
     * @pre policyLock is held by the caller.
     * @return Pairing decision with role UNKNOWN when no slot is available.
     */
    Pairing choosePairingLocked();

    /**
     * @brief Finds the slot currently bound to a connection handle.
     *
     * @pre policyLock is held by the caller.
     * @param connHandle Bluetooth connection handle.
     * @return Slot index, or -1 when no live record matches.
     */
    int8_t findSlotByConnectionLocked(uint16_t connHandle) const;

    /**
     * @brief Finds the slot persisted for a peer bond identity.
     *
     * @pre policyLock is held by the caller.
     * @param identity Stable peer bond identity.
     * @return Slot index, or -1 when no record matches.
     */
    int8_t findSlotByIdentityLocked(const PeerIdentity &identity) const;

    /**
     * @brief Finds the slot persisted for a virtual node ID.
     *
     * @pre policyLock is held by the caller.
     * @param virtualNodeId Virtual node ID to find.
     * @return Slot index, or -1 when no record matches.
     */
    int8_t findSlotByVirtualNodeIdLocked(uint32_t virtualNodeId) const;

    /**
     * @brief Finds an allocatable guest slot.
     *
     * Allocation considers only EMPTY first, then DISCONNECTED. NOT_ACTIVE and
     * ACTIVE slots are owned by known peers and must not be reused.
     *
     * @pre policyLock is held by the caller.
     * @return Guest slot index, or -1 when no guest slot is available.
     */
    int8_t findAvailableGuestSlotLocked() const;

    /**
     * @brief Assigns generated names and key material for a virtual client identity.
     *
     * @pre policyLock is held by the caller.
     * @param record Virtual client record to update.
     * @param virtualNodeId Non-zero virtual node ID assigned to the client.
     * @param forceNewKeys true when a reused slot belongs to a new peer.
     * @return true when durable record data changed.
     */
    bool assignVirtualClientIdentityLocked(ClientRecord &record, uint32_t virtualNodeId, bool forceNewKeys);

    /**
     * @brief Allocates a virtual node ID that is not used by any persisted record.
     *
     * @pre policyLock is held by the caller.
     * @param slotIndex Slot requesting the ID; an existing ID on this slot may be reused.
     * @return Non-zero virtual node ID, or 0 when the namespace is exhausted.
     */
    uint32_t allocateVirtualNodeIdLocked(uint8_t slotIndex);

    /**
     * @brief Generates direct-message key material for a virtual client identity.
     *
     * @pre policyLock is held by the caller.
     * @param publicKey Output public key buffer.
     * @param privateKey Output private key buffer.
     * @return true when key material was generated.
     */
    bool generateVirtualClientKeysLocked(uint8_t *publicKey, uint8_t *privateKey);

    /**
     * @brief Stores a live connection in a slot and persists identity changes.
     *
     * @pre policyLock is held by the caller.
     * @param slotIndex Shared-node client slot.
     * @param connHandle Bluetooth connection handle.
     * @param identity Stable peer bond identity reported by the backend.
     */
    void rememberSlotLocked(uint8_t slotIndex, uint16_t connHandle, const PeerIdentity &identity);

    /**
     * @brief Marks a slot as explicitly disconnected by its phone.
     *
     * @pre policyLock is held by the caller.
     * @param slotIndex Shared-node client slot to mark disconnected.
     */
    void disconnectSlotLocked(uint8_t slotIndex);

    /**
     * @brief Resets one slot.
     *
     * @pre policyLock is held by the caller.
     * @param slotIndex Shared-node client slot to clear.
     */
    void clearSlotLocked(uint8_t slotIndex);

    /**
     * @brief Checks whether the admin slot contains a known admin identity.
     *
     * @pre policyLock is held by the caller.
     * @return true when a known admin identity exists.
     */
    bool hasKnownAdminLocked() const;

    /**
     * @brief Returns a non-zero seconds-since-boot timestamp.
     *
     * @return Current uptime in seconds, clamped to at least 1.
     */
    static uint32_t nowSeconds();

    /**
     * @brief Guards access to pairing state and client records.
     */
    mutable concurrency::Lock policyLock;

    /**
     * @brief Slot selected by beginPairing() and waiting for connection resolution.
     */
    uint8_t pendingPairingSlot = INVALID_SLOT;

    /**
     * @brief Indicates whether records have been loaded from NodeDB.
     */
    bool loadedFromNodeDB = false;

    /**
     * @brief Next candidate virtual node ID for guest allocation.
     */
    uint32_t nextVirtualNodeId = 0x0A;

    /**
     * @brief Fixed-size table of persisted client records.
     */
    std::array<ClientRecord, MAX_CLIENTS> records{};

    /**
     * @brief Predicate helper used to search the record table.
     */
    StaticSlotTable<ClientRecord, MAX_CLIENTS> recordSlots;
};

/**
 * @brief Global shared-node pairing policy instance.
 */
extern PairingPolicy pairingPolicy;

} // namespace SharedNode
#endif
