#ifdef MODE_SHARED_NODE
#include "BluetoothPolicy.h"

#include "VirtualNodeManager.h"
#include "configuration.h"

namespace SharedNode::BluetoothPolicy
{

Pairing beginPairing()
{
    return pairingPolicy.beginPairing();
}

void rememberKnownConnection(uint16_t connHandle, const PeerIdentity &identity)
{
    // Reconnects can skip the passkey path when the backend already knows the
    // peer identity; bind the live handle back to its durable slot.
    const uint8_t knownSlot = pairingPolicy.slotForIdentity(identity);
    if (knownSlot != INVALID_SLOT) {
        pairingPolicy.rememberConnectionSlot(connHandle, identity, knownSlot);
    }
}

uint8_t resolveConnectionSlot(uint16_t connHandle, const PeerIdentity &identity)
{
    // Authentication completion is where BLE stacks expose the stable identity
    // needed to turn a pending passkey slot into a durable SharedNode record.
    return pairingPolicy.resolveSlotForConnection(connHandle, identity);
}

uint8_t slotForConnection(uint16_t connHandle)
{
    return pairingPolicy.slotForConnection(connHandle);
}

void clearConnection(uint16_t connHandle)
{
    pairingPolicy.clearConnection(connHandle);
}

void logResolvedPairingSlot(uint8_t slot)
{
    const Role role = roleForSlot(slot);
    if (role == Role::ADMIN) {
        LOG_INFO("Shared-node admin paired");
    } else if (role == Role::UNKNOWN) {
        LOG_WARN("Shared-node pairing completed without an available slot");
    }
}

void consumePendingPairingSlot()
{
    pairingPolicy.consumePendingPairingSlot();
}

bool canClearKnownClients(const char *operationName, KnownClientClearMode mode)
{
    if (mode == KnownClientClearMode::LOCAL_RECOVERY) {
        LOG_INFO("Allow shared-node %s from local recovery path", operationName ? operationName : "clear");
        return true;
    }

    if (virtualNodeManager.hasActiveAdminSession()) {
        return true;
    }

    LOG_WARN("Ignoring shared-node %s without an active admin session", operationName ? operationName : "clear");
    return false;
}

void clearKnownClients()
{
    pairingPolicy.clearAllKnownClients();
}

} // namespace SharedNode::BluetoothPolicy
#endif
