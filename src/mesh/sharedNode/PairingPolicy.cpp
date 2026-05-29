#ifdef MODE_SHARED_NODE
#include "PairingPolicy.h"

/**
 * @file SharedNodePairingPolicy.cpp
 * @brief Implements shared-node pairing role and slot assignment.
 */

#include "configuration.h"
#include "RTC.h"
#include "concurrency/LockGuard.h"
#if !(MESHTASTIC_EXCLUDE_PKI || MESHTASTIC_EXCLUDE_PKI_KEYGEN)
#include "mesh/CryptoEngine.h"
#endif
#include "meshUtils.h"
#if !MESHTASTIC_EXCLUDE_PKI
#include <Curve25519.h>
#endif
#include "mesh/NodeDB.h"

#include <cstring>

namespace SharedNode {

/**
 * @brief Global shared-node pairing policy used by Bluetooth transports.
 */
PairingPolicy pairingPolicy;

/*
 * Mental model for this file:
 *
 * - SharedNode::PeerIdentity is the durable key. BLE backends must build it from bond data
 *   (IRK / identity address / peer ID), not from the current OTA address.
 * - connHandle is only a live transport handle. It is useful while connected,
 *   but it is cleared on disconnect and is never persisted as identity.
 * - connectionState is the lifecycle owner. EMPTY/DISCONNECTED are allocatable,
 *   NOT_ACTIVE/ACTIVE remain reserved for the known identity.
 * - pendingPairingSlot bridges the BLE passkey callback and the later
 *   authentication-complete callback, where the backend finally has the stable
 *   SharedNode::PeerIdentity. Role is always derived from the slot index.
 */
PairingPolicy::PairingPolicy() : recordSlots(records) {}

Pairing PairingPolicy::beginPairing()
{
    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    // The BLE stack may ask for the passkey before it exposes the peer's bond
    // identity. Reserve a slot now, then bind it to SharedNode::PeerIdentity
    // after authentication completes.
    Pairing pairing;
    if (pendingPairingSlot != SharedNode::INVALID_SLOT) {
        // Reuse the same pending decision if the stack repeats the passkey
        // request during one pairing flow.
        pairing.slot = pendingPairingSlot;
    } else {
        pairing = choosePairingLocked();
        pendingPairingSlot = pairing.slot;
    }

    // The first client (admin) gets a random PIN. Guests use the configured
    // shared PIN so the admin can hand it out without changing the admin bond.
    const Role role = roleForSlot(pairing.slot);
    if (role == Role::ADMIN) {
        pairing.passkey = random(100000, 999999);
    } else if (role == Role::GUEST) {
        pairing.passkey = config.bluetooth.fixed_pin;
    } else if (config.bluetooth.mode == meshtastic_Config_BluetoothConfig_PairingMode_RANDOM_PIN) {
        pairing.passkey = random(100000, 999999);
    } else {
        pairing.passkey = config.bluetooth.fixed_pin;
    }

    return pairing;
}

uint8_t PairingPolicy::consumePendingPairingSlot()
{
    concurrency::LockGuard guard(&policyLock);
    const uint8_t slot = pendingPairingSlot;
    pendingPairingSlot = SharedNode::INVALID_SLOT;
    return slot;
}

uint8_t PairingPolicy::peekPendingPairingSlot() const
{
    concurrency::LockGuard guard(&policyLock);
    return pendingPairingSlot;
}

Role PairingPolicy::roleForConnection(uint16_t connHandle) const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();
    const int8_t slot = findSlotByConnectionLocked(connHandle);
    return slot >= 0 ? roleForSlot(static_cast<uint8_t>(slot)) : Role::UNKNOWN;
}

Role PairingPolicy::roleForIdentity(const PeerIdentity &identity) const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();
    const int8_t slot = findSlotByIdentityLocked(identity);
    return slot >= 0 ? roleForSlot(static_cast<uint8_t>(slot)) : Role::UNKNOWN;
}

uint8_t PairingPolicy::slotForConnection(uint16_t connHandle) const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();
    const int8_t slot = findSlotByConnectionLocked(connHandle);
    return slot >= 0 ? static_cast<uint8_t>(slot) : SharedNode::INVALID_SLOT;
}

uint8_t PairingPolicy::slotForIdentity(const PeerIdentity &identity) const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();
    const int8_t slot = findSlotByIdentityLocked(identity);
    return slot >= 0 ? static_cast<uint8_t>(slot) : SharedNode::INVALID_SLOT;
}

uint32_t PairingPolicy::virtualNodeIdForSlot(uint8_t slotIndex) const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();
    return (slotIndex < records.size() && records[slotIndex].hasIdentity()) ? records[slotIndex].virtualNodeId : 0;
}

uint8_t PairingPolicy::slotForVirtualNodeId(uint32_t virtualNodeId) const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();
    const int8_t slot = findSlotByVirtualNodeIdLocked(virtualNodeId);
    return slot >= 0 ? static_cast<uint8_t>(slot) : SharedNode::INVALID_SLOT;
}

PairingPolicy::Role PairingPolicy::roleForVirtualNodeId(uint32_t virtualNodeId) const
{
    return roleForSlot(slotForVirtualNodeId(virtualNodeId));
}

bool PairingPolicy::setVirtualNodeIdForSlot(uint8_t slotIndex, uint32_t virtualNodeId)
{
    // Virtual node ID 0 has special packet semantics, so guest IDs start at a
    // non-zero value allocated by VirtualNodeManager.
    if (slotIndex >= records.size() || roleForSlot(slotIndex) != Role::GUEST || virtualNodeId == 0) {
        return false;
    }

    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    ClientRecord &record = records[slotIndex];
    if (!record.hasIdentity()) {
        return false;
    }

    const int8_t existingOwner = findSlotByVirtualNodeIdLocked(virtualNodeId);
    if (existingOwner >= 0 && static_cast<uint8_t>(existingOwner) != slotIndex) {
        LOG_WARN("Shared-node virtual node ID 0x%x already belongs to slot %u", virtualNodeId,
                 static_cast<unsigned>(existingOwner));
        return false;
    }

    const bool alreadyAssigned = record.virtualNodeId == virtualNodeId;
    const bool changed = assignVirtualClientIdentityLocked(record, virtualNodeId, false);
    if (!changed) {
        return alreadyAssigned;
    }
    persistToNodeDBLocked();
    return true;
}

bool PairingPolicy::ensureVirtualNodeIdForSlot(uint8_t slotIndex, uint32_t &virtualNodeId)
{
    virtualNodeId = 0;
    if (slotIndex >= records.size() || roleForSlot(slotIndex) != Role::GUEST) {
        return false;
    }

    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    ClientRecord &record = records[slotIndex];
    if (!record.hasIdentity()) {
        return false;
    }

    if (record.virtualNodeId != 0) {
        virtualNodeId = record.virtualNodeId;
        return true;
    }

    const uint32_t allocatedVirtualNodeId = allocateVirtualNodeIdLocked(slotIndex);
    if (allocatedVirtualNodeId == 0) {
        return false;
    }

    if (!assignVirtualClientIdentityLocked(record, allocatedVirtualNodeId, false)) {
        return false;
    }

    virtualNodeId = record.virtualNodeId;
    persistToNodeDBLocked();
    return virtualNodeId != 0;
}

bool PairingPolicy::buildVirtualUser(uint32_t virtualNodeId, meshtastic_User &user) const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();

    const int8_t slot = findSlotByVirtualNodeIdLocked(virtualNodeId);
    if (slot < 0) {
        return false;
    }

    const ClientRecord &record = records[slot];
    memset(&user, 0, sizeof(user));
    snprintf(user.id, sizeof(user.id), "!%08x", virtualNodeId);
    strncpy(user.short_name, record.shortName, sizeof(user.short_name) - 1);
    strncpy(user.long_name, record.longName, sizeof(user.long_name) - 1);
    user.public_key.size = PKI_KEY_SIZE;
    memcpy(user.public_key.bytes, record.publicKey, PKI_KEY_SIZE);
    return true;
}

bool PairingPolicy::buildVirtualSecurityConfig(uint32_t virtualNodeId, meshtastic_Config_SecurityConfig &security,
                                               bool includeAdminKeys) const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();

    const int8_t slot = findSlotByVirtualNodeIdLocked(virtualNodeId);
    if (slot < 0) {
        return false;
    }

    const ClientRecord &record = records[slot];
    security = config.security;
    security.public_key.size = PKI_KEY_SIZE;
    memcpy(security.public_key.bytes, record.publicKey, PKI_KEY_SIZE);
    security.private_key.size = PKI_KEY_SIZE;
    memcpy(security.private_key.bytes, record.privateKey, PKI_KEY_SIZE);
    if (!includeAdminKeys) {
        security.admin_key_count = 0;
        memset(security.admin_key, 0, sizeof(security.admin_key));
    }
    return true;
}

bool PairingPolicy::updateVirtualClientNames(uint32_t virtualNodeId, const char *shortName, const char *longName)
{
    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    const int8_t slot = findSlotByVirtualNodeIdLocked(virtualNodeId);
    if (slot < 0) {
        return false;
    }

    ClientRecord &record = records[slot];
    bool changed = false;
    if (shortName && *shortName && strncmp(record.shortName, shortName, sizeof(record.shortName)) != 0) {
        memset(record.shortName, 0, sizeof(record.shortName));
        strncpy(record.shortName, shortName, sizeof(record.shortName) - 1);
        changed = true;
    }
    if (longName && *longName && strncmp(record.longName, longName, sizeof(record.longName)) != 0) {
        memset(record.longName, 0, sizeof(record.longName));
        strncpy(record.longName, longName, sizeof(record.longName) - 1);
        changed = true;
    }

    if (changed) {
        persistToNodeDBLocked();
    }
    return true;
}

bool PairingPolicy::regenerateVirtualClientKeys(uint32_t virtualNodeId)
{
    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    const int8_t slot = findSlotByVirtualNodeIdLocked(virtualNodeId);
    if (slot < 0) {
        return false;
    }

    uint8_t publicKey[PKI_KEY_SIZE] = {};
    uint8_t privateKey[PKI_KEY_SIZE] = {};
    if (!generateVirtualClientKeysLocked(publicKey, privateKey)) {
        return false;
    }

    ClientRecord &record = records[slot];
    memcpy(record.publicKey, publicKey, sizeof(record.publicKey));
    memcpy(record.privateKey, privateKey, sizeof(record.privateKey));
    persistToNodeDBLocked();
    return true;
}

bool PairingPolicy::updateVirtualClientKeys(uint32_t virtualNodeId, const meshtastic_Config_SecurityConfig &security)
{
    if (security.private_key.size != PKI_KEY_SIZE || memfll(security.private_key.bytes, 0, PKI_KEY_SIZE)) {
        // Mobile clients commonly send an empty private key when they want the
        // device to generate fresh key material for the virtual identity.
        return regenerateVirtualClientKeys(virtualNodeId);
    }

#if !MESHTASTIC_EXCLUDE_PKI
    uint8_t privateKey[PKI_KEY_SIZE] = {};
    uint8_t publicKey[PKI_KEY_SIZE] = {};
    memcpy(privateKey, security.private_key.bytes, PKI_KEY_SIZE);
    Curve25519::eval(publicKey, privateKey, 0);
    if (Curve25519::isWeakPoint(publicKey)) {
        LOG_ERROR("Shared-node virtual client key import produced a weak public key");
        return false;
    }

    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    const int8_t slot = findSlotByVirtualNodeIdLocked(virtualNodeId);
    if (slot < 0) {
        return false;
    }

    ClientRecord &record = records[slot];
    memcpy(record.publicKey, publicKey, sizeof(record.publicKey));
    memcpy(record.privateKey, privateKey, sizeof(record.privateKey));
    persistToNodeDBLocked();
    return true;
#else
    (void)virtualNodeId;
    (void)security;
    return false;
#endif
}

Role PairingPolicy::resolveRoleForConnection(uint16_t connHandle, const PeerIdentity &identity)
{
    return roleForSlot(resolveSlotForConnection(connHandle, identity));
}

uint8_t PairingPolicy::resolveSlotForConnection(uint16_t connHandle, const PeerIdentity &identity)
{
    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    if (!identity) {
        LOG_WARN("Shared-node cannot resolve BLE conn %u without a bond identity", connHandle);
        pendingPairingSlot = SharedNode::INVALID_SLOT;
        return SharedNode::INVALID_SLOT;
    }

    // Resolution order matters:
    // 1. a known durable identity always wins;
    int8_t slot = findSlotByIdentityLocked(identity);

    // 2. otherwise use the slot reserved when the passkey was shown;
    if (slot < 0 && pendingPairingSlot != SharedNode::INVALID_SLOT) {
        slot = pendingPairingSlot;
    }

    // 3. if the backend did not call beginPairing(), choose a fresh slot now.
    if (slot < 0 || static_cast<size_t>(slot) >= records.size()) {
        Pairing pairing = choosePairingLocked();
        slot = pairing.slot;
    }

    pendingPairingSlot = SharedNode::INVALID_SLOT;

    // From here on, connHandle is only an in-memory live binding for PhoneAPI
    // routing. The stable thing persisted to NodeDB is identity.
    if (slot >= 0 && roleForSlot(static_cast<uint8_t>(slot)) != Role::UNKNOWN) {
        rememberSlotLocked(static_cast<uint8_t>(slot), connHandle, identity);
        return static_cast<uint8_t>(slot);
    }

    return SharedNode::INVALID_SLOT;
}

bool PairingPolicy::hasKnownAdmin() const
{
    concurrency::LockGuard guard(&policyLock);
    const_cast<PairingPolicy *>(this)->loadFromNodeDBLocked();
    return hasKnownAdminLocked();
}

void PairingPolicy::rememberConnectionSlot(uint16_t connHandle, const PeerIdentity &identity, uint8_t slotIndex)
{
    // INVALID_SLOT means the backend has not authenticated/resolved this peer yet.
    if (roleForSlot(slotIndex) == Role::UNKNOWN) {
        return;
    }

    if (!identity) {
        LOG_WARN("Shared-node cannot remember BLE conn %u without a bond identity", connHandle);
        return;
    }

    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    // Reconnect path: if the backend can resolve an existing bond identity
    // during onConnect/onSecured, attach the live handle to that known slot.
    int8_t slot = findSlotByIdentityLocked(identity);
    if (slot < 0) {
        slot = slotIndex;
    }

    if (slot < 0 || roleForSlot(static_cast<uint8_t>(slot)) == Role::UNKNOWN) {
        LOG_WARN("Shared-node has no valid slot for BLE conn %u", connHandle);
        return;
    }

    rememberSlotLocked(static_cast<uint8_t>(slot), connHandle, identity);
}

void PairingPolicy::clearConnection(uint16_t connHandle)
{
    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    const int8_t slot = findSlotByConnectionLocked(connHandle);
    if (slot < 0) {
        return;
    }

    ClientRecord &record = records[slot];

    // A BLE drop only clears the live handle. The identity remains reserved as
    // NOT_ACTIVE so a later reconnect can reclaim the same slot.
    record.connectionState = ConnectionState::NOT_ACTIVE;
    record.connHandle = 0;
    if (pendingPairingSlot == static_cast<uint8_t>(slot)) {
        pendingPairingSlot = SharedNode::INVALID_SLOT;
    }
}

void PairingPolicy::disconnectSlot(uint8_t slotIndex)
{
    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();
    if (slotIndex >= records.size()) {
        return;
    }

    disconnectSlotLocked(slotIndex);
    persistToNodeDBLocked();
}

void PairingPolicy::invalidateSlot(uint8_t slotIndex)
{
    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();
    if (slotIndex >= records.size()) {
        return;
    }

    clearSlotLocked(slotIndex);
    persistToNodeDBLocked();
}

void PairingPolicy::clearAll()
{
    concurrency::LockGuard guard(&policyLock);
    loadFromNodeDBLocked();

    pendingPairingSlot = SharedNode::INVALID_SLOT;
    for (uint8_t i = 0; i < records.size(); i++) {
        clearSlotLocked(i);
    }
    persistToNodeDBLocked();
}

void PairingPolicy::loadFromNodeDBLocked()
{
    if (loadedFromNodeDB) {
        return;
    }

    for (uint8_t i = 0; i < records.size(); i++) {
        records[i] = ClientRecord{};
    }

    if (nodeDB) {
        nodeDB->copySharedNodeRecords(records.data(), records.size());
    }

    // Persisted records describe known identities. Live connection handles are
    // reconstructed after boot, so never trust connHandle from storage.
    for (uint8_t i = 0; i < records.size(); i++) {
        if (records[i].connectionState == ConnectionState::ACTIVE) {
            records[i].connectionState = ConnectionState::NOT_ACTIVE;
        }
        records[i].connHandle = 0;
    }
    loadedFromNodeDB = true;
}

void PairingPolicy::persistToNodeDBLocked()
{
    if (nodeDB) {
        nodeDB->saveSharedNodeRecords(records.data(), records.size());
    }
}

Pairing PairingPolicy::choosePairingLocked()
{
    Pairing pairing;

    // Slot 0 is special: the first stable identity to pair becomes the admin.
    // Once it exists, all future new pairings are guests.
    if (!hasKnownAdminLocked() && records[SharedNode::ADMIN_SLOT].canAllocate()) {
        pairing.slot = SharedNode::ADMIN_SLOT;
        return pairing;
    }

    const int8_t guestSlot = findAvailableGuestSlotLocked();
    if (guestSlot >= 0) {
        pairing.slot = static_cast<uint8_t>(guestSlot);
    }
    return pairing;
}

int8_t PairingPolicy::findSlotByConnectionLocked(uint16_t connHandle) const
{
    return recordSlots.findIndex(
        [connHandle](const ClientRecord &record) { return record.isActive() && record.connHandle == connHandle; });
}

int8_t PairingPolicy::findSlotByIdentityLocked(const PeerIdentity &identity) const
{
    if (!identity) {
        return -1;
    }

    return recordSlots.findIndex(
        [&identity](const ClientRecord &record) { return record.hasIdentity() && record.peerIdentity == identity; });
}

int8_t PairingPolicy::findSlotByVirtualNodeIdLocked(uint32_t virtualNodeId) const
{
    if (virtualNodeId == 0) {
        return -1;
    }

    return recordSlots.findIndex([virtualNodeId](const ClientRecord &record) {
        return record.hasIdentity() && record.virtualNodeId == virtualNodeId;
    });
}

int8_t PairingPolicy::findAvailableGuestSlotLocked() const
{
    // New peers may reuse only never-used slots first, then slots explicitly
    // disconnected by the app. Known inactive and active slots stay reserved
    // for their current peer identity.
    int8_t slot = recordSlots.findIndex(
        [](const ClientRecord &record) { return record.connectionState == ConnectionState::EMPTY; }, 1);
    if (slot >= 0) {
        return slot;
    }

    return recordSlots.findIndex(
        [](const ClientRecord &record) { return record.connectionState == ConnectionState::DISCONNECTED; }, 1);
}

bool PairingPolicy::assignVirtualClientIdentityLocked(ClientRecord &record, uint32_t virtualNodeId, bool forceNewKeys)
{
    if (virtualNodeId == 0) {
        return false;
    }

    bool changed = false;
    const bool virtualNodeIdChanged = record.virtualNodeId != virtualNodeId;
    const bool needsNewKeys = virtualNodeIdChanged || forceNewKeys;
    uint8_t publicKey[PKI_KEY_SIZE] = {};
    uint8_t privateKey[PKI_KEY_SIZE] = {};
    if (needsNewKeys && !generateVirtualClientKeysLocked(publicKey, privateKey)) {
        return false;
    }

    if (virtualNodeIdChanged) {
        record.virtualNodeId = virtualNodeId;
        changed = true;
    }

    if (virtualNodeIdChanged || record.shortName[0] == '\0') {
        // Default names are derived from the virtual node ID so reconnecting
        // guests keep stable labels unless the user later customizes them.
        snprintf(record.shortName, sizeof(record.shortName), "G%02X", static_cast<unsigned>(virtualNodeId) & 0xff);
        changed = true;
    }
    if (virtualNodeIdChanged || record.longName[0] == '\0') {
        snprintf(record.longName, sizeof(record.longName), "Guest %02X", static_cast<unsigned>(virtualNodeId) & 0xff);
        changed = true;
    }

    if (needsNewKeys) {
        memcpy(record.publicKey, publicKey, sizeof(record.publicKey));
        memcpy(record.privateKey, privateKey, sizeof(record.privateKey));
        changed = true;
    }
    return changed;
}

uint32_t PairingPolicy::allocateVirtualNodeIdLocked(uint8_t slotIndex)
{
    // Keep virtual node IDs compact and recognizable while checking against
    // every persisted guest identity, not only clients that are connected now.
    if (nextVirtualNodeId < 0x0A || nextVirtualNodeId > 0xFE) {
        nextVirtualNodeId = 0x0A;
    }

    for (uint16_t attempts = 0; attempts < 0xF5; attempts++) {
        const uint32_t candidate = nextVirtualNodeId;
        nextVirtualNodeId++;
        if (nextVirtualNodeId > 0xFE) {
            nextVirtualNodeId = 0x0A;
        }

        const int8_t ownerSlot = findSlotByVirtualNodeIdLocked(candidate);
        if (ownerSlot < 0 || static_cast<uint8_t>(ownerSlot) == slotIndex) {
            return candidate;
        }
    }

    LOG_ERROR("Shared-node virtual node ID namespace is exhausted");
    return 0;
}

bool PairingPolicy::generateVirtualClientKeysLocked(uint8_t *publicKey, uint8_t *privateKey)
{
#if !(MESHTASTIC_EXCLUDE_PKI || MESHTASTIC_EXCLUDE_PKI_KEYGEN)
    if (!crypto || !publicKey || !privateKey) {
        return false;
    }

    crypto->generateKeyPair(publicKey, privateKey);
    return true;
#else
    (void)publicKey;
    (void)privateKey;
    return false;
#endif
}

void PairingPolicy::rememberSlotLocked(uint8_t slotIndex, uint16_t connHandle, const PeerIdentity &identity)
{
    // Validation
    if (slotIndex >= records.size()) {
        return;
    }

    if (!identity) {
        LOG_WARN("Shared-node slot %u cannot be remembered without a bond identity", static_cast<unsigned>(slotIndex));
        return;
    }

    ClientRecord &record = records[slotIndex];
    if (record.isActive() && record.connHandle != connHandle && record.peerIdentity != identity) {
        // A slot can have at most one live connection. This protects against a
        // second peer taking over an active guest/admin slot.
        LOG_WARN("Shared-node slot %u is already active", slotIndex);
        return;
    }

    const bool wasDisconnected = record.connectionState == ConnectionState::DISCONNECTED;
    const bool changedIdentity = !record.hasIdentity() || record.peerIdentity != identity;
    const Role role = roleForSlot(slotIndex);
    bool virtualClientMetadataChanged = false;

    if (changedIdentity) {
        // The slot identity changed, so reset per-client metadata. The virtual
        // node ID intentionally stays attached to the slot unless reassigned.
        const uint32_t previousVirtualNodeId = (role == Role::GUEST) ? record.virtualNodeId : 0;
        ClientRecord newRecord;
        newRecord.peerIdentity = identity;
        newRecord.registerTime = nowSeconds();
        if (previousVirtualNodeId != 0) {
            virtualClientMetadataChanged = assignVirtualClientIdentityLocked(newRecord, previousVirtualNodeId, true);
            if (!virtualClientMetadataChanged) {
                LOG_ERROR("Shared-node failed to generate virtual client keys for slot %u", static_cast<unsigned>(slotIndex));
                return;
            }
        }
        record = newRecord;
    }

    record.connectionState = ConnectionState::ACTIVE;
    record.connHandle = connHandle;
    record.lastSeen = nowSeconds();

    // Persist durable identity changes. If the same identity reconnects
    // from DISCONNECTED, save it back as NOT_ACTIVE so the slot is reserved
    // again after reboot.
    const bool shouldPersistIdentityChange = changedIdentity && (role != Role::GUEST || record.virtualNodeId != 0);
    if (shouldPersistIdentityChange || wasDisconnected || virtualClientMetadataChanged) {
        persistToNodeDBLocked();
    }
}

void PairingPolicy::disconnectSlotLocked(uint8_t slotIndex)
{
    if (slotIndex >= records.size()) {
        return;
    }

    ClientRecord &record = records[slotIndex];

    const bool hadIdentity = record.hasIdentity();
    const PeerIdentity peerIdentity = record.peerIdentity;
    const uint32_t virtualNodeId = record.virtualNodeId;
    const uint32_t registerTime = record.registerTime;
    char shortName[SHORT_NAME_SIZE] = {};
    char longName[LONG_NAME_SIZE] = {};
    strncpy(shortName, record.shortName, sizeof(shortName) - 1);
    strncpy(longName, record.longName, sizeof(longName) - 1);
    uint8_t publicKey[PKI_KEY_SIZE] = {};
    uint8_t privateKey[PKI_KEY_SIZE] = {};
    memcpy(publicKey, record.publicKey, sizeof(publicKey));
    memcpy(privateKey, record.privateKey, sizeof(privateKey));

    record = SharedNode::ClientRecord{};
    record.connectionState = ConnectionState::DISCONNECTED;
    record.connHandle = 0;
    // App-level disconnect releases the live session but keeps durable identity
    // data so the same bonded phone can reconnect to its slot later.
    if (hadIdentity) {
        record.peerIdentity = peerIdentity.c_str();
    }
    record.virtualNodeId = virtualNodeId;
    record.registerTime = registerTime;
    strncpy(record.shortName, shortName, sizeof(record.shortName) - 1);
    strncpy(record.longName, longName, sizeof(record.longName) - 1);
    memcpy(record.publicKey, publicKey, sizeof(record.publicKey));
    memcpy(record.privateKey, privateKey, sizeof(record.privateKey));
    record.lastSeen = nowSeconds();

    if (pendingPairingSlot == slotIndex) {
        pendingPairingSlot = SharedNode::INVALID_SLOT;
    }
}

void PairingPolicy::clearSlotLocked(uint8_t slotIndex)
{
    if (slotIndex >= records.size()) {
        return;
    }
    recordSlots.invalidate(slotIndex);
}

bool PairingPolicy::hasKnownAdminLocked() const
{
    const ClientRecord &admin = records[ADMIN_SLOT];
    // An admin is considered claimed only after a backend supplied a formatted
    // stable identity. A pending pairing alone must not block first-admin setup.
    return admin.hasIdentity() && admin.peerIdentity.stable();
}

uint32_t PairingPolicy::nowSeconds()
{
    uint32_t now = getValidTime(RTCQualityFromNet);
    if (now == 0) {
        now = millis() / 1000;
        if (now == 0) {
            now = 1;  // Fallback: ensure non-zero
        }
    }
    return now;
}

} // namespace SharedNode
#endif
