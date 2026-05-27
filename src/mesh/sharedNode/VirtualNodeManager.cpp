#ifdef MODE_SHARED_NODE
#include "VirtualNodeManager.h"

/**
 * @file VirtualNodeManager.cpp
 * @brief Implements shared-node virtual session management and local delivery.
 */

#include "configuration.h"
#include "NodeDB.h"
#include "PhoneAPI.h"
#include "concurrency/LockGuard.h"
#include "mesh-pb-constants.h"
#include "mesh/sharedNode/PairingPolicy.h"


/**
 * @brief Global shared-node virtual manager.
 */
VirtualNodeManager virtualNodeManager;


VirtualNodeManager::VirtualNodeManager() : sessionSlots(sessions) {}

/*
 * Runtime model:
 *
 * - SharedNodePairingPolicy decides who a BLE peer is and which slot it owns.
 * - VirtualNodeManager only tracks live PhoneAPI sessions and packet routing.
 * - Guest virtual node IDs stay attached to shared-node slots, so reconnecting
 *   guests keep the same node number after the BLE bond is recognized.
 */

VirtualNodeManager::SessionStartResult VirtualNodeManager::connectAsAdmin(PhoneAPI *api)
{
    if (!api) {
        return SessionStartResult::UNKNOWN_ROLE;
    }

    concurrency::LockGuard guard(&sessionLock);
    if (SharedNode::roleForSlot(api->getSharedNodeSlot()) != SharedNode::Role::ADMIN) {
        return SessionStartResult::UNKNOWN_ROLE;
    }

    if (hasAdminLocked(api)) {
        // The admin is the real local node identity; allowing two active admin
        // PhoneAPI sessions would make local admin operations ambiguous.
        return SessionStartResult::ADMIN_ALREADY_CONNECTED;
    }

    SessionInfo *session = findSessionByApiLocked(api);
    if (!session) {
        session = allocateSessionLocked();
    }
    if (!session) {
        return SessionStartResult::TABLE_FULL;
    }

    session->used = true;
    session->api = api;
    session->sharedNodeSlot = SharedNode::ADMIN_SLOT;
    // Admin traffic uses the physical node number, not a virtual guest ID.
    session->virtualNodeId = nodeDB ? nodeDB->getNodeNum() : 0;
    return SessionStartResult::OK;
}

VirtualNodeManager::SessionStartResult VirtualNodeManager::connectAsGuest(PhoneAPI *api)
{
    if (!api) {
        return SessionStartResult::UNKNOWN_ROLE;
    }

    concurrency::LockGuard guard(&sessionLock);
    const uint8_t sharedNodeSlot = api->getSharedNodeSlot();
    if (SharedNode::roleForSlot(sharedNodeSlot) != SharedNode::Role::GUEST) {
        return SessionStartResult::UNKNOWN_ROLE;
    }

    SessionInfo *session = findSessionByApiLocked(api);
    if (!session) {
        size_t guestCount = 0;
        for (const SessionInfo &candidate : sessions) {
            if (candidate.used && SharedNode::roleForSlot(candidate.sharedNodeSlot) == SharedNode::Role::GUEST) {
                guestCount++;
            }
        }
        if (guestCount >= SharedNode::MAX_GUESTS) {
            return SessionStartResult::GUEST_LIMIT_REACHED;
        }
        // Allocate a new live session only after enforcing the configured guest
        // limit; the pairing policy may have more persisted slots than are
        // currently allowed to be connected.
        session = allocateSessionLocked();
    }
    if (!session) {
        return SessionStartResult::TABLE_FULL;
    }

    NodeNum virtualNodeId = SharedNode::pairingPolicy.virtualNodeIdForSlot(sharedNodeSlot);
    if (virtualNodeId == 0) {
        // First connection for this slot: create the guest node ID and persist
        // it via the pairing policy so future reconnects keep the same ID.
        virtualNodeId = allocateVirtualNodeIdLocked();
        if (!SharedNode::pairingPolicy.setVirtualNodeIdForSlot(sharedNodeSlot, virtualNodeId)) {
            *session = SessionInfo{};
            return SessionStartResult::GUEST_IDENTITY_UNAVAILABLE;
        }
    }

    session->used = true;
    session->api = api;
    session->sharedNodeSlot = sharedNodeSlot;
    session->virtualNodeId = virtualNodeId;
    return SessionStartResult::OK;
}

void VirtualNodeManager::disconnect(PhoneAPI *api)
{
    if (!api) {
        return;
    }

    concurrency::LockGuard guard(&sessionLock);
    SessionInfo *session = findSessionByApiLocked(api);
    if (session) {
        *session = SessionInfo{};
    }
}

VirtualNodeManager::OutgoingPacketResult VirtualNodeManager::handleOutgoingPacket(meshtastic_MeshPacket &packet,
                                                                                  PhoneAPI *sourceApi)
{
    // Non-PhoneAPI callers are device-originated or internal mesh paths. They
    // are already trusted and do not have a per-client shared-node session.
    if (sourceApi == nullptr) {
        return {OutgoingPacketDecision::ALLOW_RADIO, OutgoingRejectionReason::NONE};
    }

    concurrency::LockGuard guard(&sessionLock);
    SessionInfo *session = findSessionByApiLocked(sourceApi);
    if (!session) {
        return {OutgoingPacketDecision::REJECT, OutgoingRejectionReason::NOT_AUTHORIZED};
    }

    const NodeNum localNodeNum = nodeDB ? nodeDB->getNodeNum() : 0;
    const bool isAdminPacket = packet.which_payload_variant == meshtastic_MeshPacket_decoded_tag &&
                               packet.decoded.portnum == meshtastic_PortNum_ADMIN_APP;
    SessionInfo *localSession = nullptr;
    if (!isBroadcast(packet.to) && packet.to != 0 && packet.to != localNodeNum) {
        localSession = findSessionByVirtualNodeLocked(packet.to);
    }
    const bool targetsPhysicalLocalNode = packet.to == 0 || packet.to == localNodeNum;
    const bool targetsLocalVirtualNode = localSession != nullptr;

    const SharedNode::Role sourceRole = SharedNode::roleForSlot(session->sharedNodeSlot);
    const bool sourceIsAdmin = sourceRole == SharedNode::Role::ADMIN;
    const bool sourceUsesVirtualIdentity = session->virtualNodeId != 0 && session->virtualNodeId != localNodeNum;

    if (isAdminPacket && sourceUsesVirtualIdentity) {
        const bool targetsOwnVirtualNode = packet.to == session->virtualNodeId;
        if (isBroadcast(packet.to) || !(targetsPhysicalLocalNode || targetsOwnVirtualNode)) {
            return {OutgoingPacketDecision::REJECT, OutgoingRejectionReason::NOT_OWN_PROFILE};
        }

        // Virtual clients may use ADMIN_APP only as a local control path.
        // AdminModule will scope owner/key operations to packet.from.
        packet.to = localNodeNum;
        packet.from = session->virtualNodeId;
        packet.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_API;
        packet.next_hop = NO_NEXT_HOP_PREFERENCE;
        packet.relay_node = NO_RELAY_NODE;
        return {OutgoingPacketDecision::ALLOW_RADIO, OutgoingRejectionReason::NONE};
    }

    if (isAdminPacket && !sourceIsAdmin &&
        (isBroadcast(packet.to) || targetsPhysicalLocalNode || targetsLocalVirtualNode)) {
        // Guests can send normal mesh traffic, but admin commands are either
        // handled by the scoped virtual path above or rejected.
        return {OutgoingPacketDecision::REJECT, OutgoingRejectionReason::ADMIN_ONLY};
    }

    // Direct messages between guests on the same device should not consume
    // airtime. Rewrite them as locally delivered packets and queue them for the
    // destination PhoneAPI.
    if (!isBroadcast(packet.to) && packet.to != 0) {
        if (localSession && localSession->api && localSession->api != sourceApi) {
            meshtastic_MeshPacket localPacket = packet;
            localPacket.to = localSession->virtualNodeId;
            localPacket.from = session->virtualNodeId;
            localPacket.next_hop = NO_NEXT_HOP_PREFERENCE;
            localPacket.relay_node = NO_RELAY_NODE;

            enqueueLocalPacketLocked(localSession->api, localPacket);
            return {OutgoingPacketDecision::HANDLED_LOCAL, OutgoingRejectionReason::NONE};
        }
    }

    if (sourceUsesVirtualIdentity) {
        // Radio-bound virtual client packets must appear to come from the
        // virtual node, never from the physical shared node.
        packet.from = session->virtualNodeId;
    }

    return {OutgoingPacketDecision::ALLOW_RADIO, OutgoingRejectionReason::NONE};
}

bool VirtualNodeManager::sendNotificationToVirtualNode(NodeNum nodeNum, meshtastic_LogRecord_Level level, uint32_t replyId,
                                                       const char *message)
{
    PhoneAPI *api = nullptr;
    {
        concurrency::LockGuard guard(&sessionLock);
        SessionInfo *session = findSessionByVirtualNodeLocked(nodeNum);
        if (session) {
            api = session->api;
        }
    }

    if (!api) {
        return false;
    }

    // Notify outside sessionLock because PhoneAPI::sendNotification() can wake
    // transport callbacks that may ask the manager for more local packets.
    api->sendNotification(level, replyId, message);
    return true;
}

const char *VirtualNodeManager::getSessionStartMessage(SessionStartResult result)
{
    switch (result) {
    case SessionStartResult::OK:
        return nullptr;
    case SessionStartResult::ADMIN_ALREADY_CONNECTED:
        return "The shared node admin is already connected.";
    case SessionStartResult::GUEST_LIMIT_REACHED:
    case SessionStartResult::TABLE_FULL:
        return "Shared node is full. Ask the admin to free a guest slot.";
    case SessionStartResult::GUEST_IDENTITY_UNAVAILABLE:
        return "Could not prepare your shared-node identity. Ask the admin to reconnect you.";
    case SessionStartResult::UNKNOWN_ROLE:
    default:
        return "This phone is not authorized for this shared node.";
    }
}

const char *VirtualNodeManager::getOutgoingRejectionMessage(OutgoingRejectionReason reason)
{
    switch (reason) {
    case OutgoingRejectionReason::ADMIN_ONLY:
        return "Only the shared node admin can change this setting.";
    case OutgoingRejectionReason::NOT_OWN_PROFILE:
        return "You can only change your own shared-node profile.";
    case OutgoingRejectionReason::NOT_AUTHORIZED:
        return "This phone is not authorized for this shared node.";
    case OutgoingRejectionReason::NONE:
    default:
        return nullptr;
    }
}

void VirtualNodeManager::handleIncomingPacket(meshtastic_MeshPacket &packet)
{
    if (!nodeDB) {
        return;
    }

    concurrency::LockGuard guard(&sessionLock);
    const NodeNum localNodeNum = nodeDB->getNodeNum();
    for (SessionInfo &session : sessions) {
        const bool sessionUsesVirtualIdentity = session.virtualNodeId != 0 && session.virtualNodeId != localNodeNum;
        if (!session.used || !session.api || !sessionUsesVirtualIdentity) {
            continue;
        }

        if (isBroadcast(packet.to) || packet.to == session.virtualNodeId) {
            // Guest sessions receive broadcast mesh traffic plus unicast
            // traffic addressed to their virtual node number. They do not read
            // the physical node's global phone queue.
            enqueueLocalPacketLocked(session.api, packet);
        }
    }
}

bool VirtualNodeManager::popLocalPacketForApi(const PhoneAPI *api, meshtastic_MeshPacket &packetOut)
{
    if (!api) {
        return false;
    }

    concurrency::LockGuard guard(&sessionLock);
    SessionInfo *session = findSessionByApiLocked(const_cast<PhoneAPI *>(api));
    if (!session) {
        return false;
    }

    return session->localPackets.pop(packetOut);
}

bool VirtualNodeManager::hasLocalPacketForApi(const PhoneAPI *api) const
{
    if (!api) {
        return false;
    }

    concurrency::LockGuard guard(&sessionLock);
    const SessionInfo *session = findSessionByApiLocked(api);
    return session && !session->localPackets.empty();
}

NodeNum VirtualNodeManager::getVirtualNodeId(const PhoneAPI *api) const
{
    if (!api) {
        return 0;
    }

    concurrency::LockGuard guard(&sessionLock);
    const SessionInfo *session = findSessionByApiLocked(api);
    return session ? session->virtualNodeId : 0;
}

bool VirtualNodeManager::isLocalVirtualNode(NodeNum nodeNum) const
{
    if (nodeNum == 0) {
        return false;
    }

    const NodeNum localNodeNum = nodeDB ? nodeDB->getNodeNum() : 0;
    if (nodeNum == localNodeNum) {
        return false;
    }

    concurrency::LockGuard guard(&sessionLock);
    return findSessionByVirtualNodeLocked(nodeNum) != nullptr;
}

uint8_t VirtualNodeManager::sharedNodeSlotForVirtualNode(NodeNum nodeNum) const
{
    if (nodeNum == 0) {
        return SharedNode::INVALID_SLOT;
    }

    const NodeNum localNodeNum = nodeDB ? nodeDB->getNodeNum() : 0;
    if (nodeNum == localNodeNum) {
        return SharedNode::INVALID_SLOT;
    }

    concurrency::LockGuard guard(&sessionLock);
    const SessionInfo *session = findSessionByVirtualNodeLocked(nodeNum);
    return session ? session->sharedNodeSlot : SharedNode::INVALID_SLOT;
}

bool VirtualNodeManager::isAdmin(const PhoneAPI *api) const
{
    if (!api) {
        return false;
    }

    concurrency::LockGuard guard(&sessionLock);
    const SessionInfo *session = findSessionByApiLocked(api);
    return session && SharedNode::roleForSlot(session->sharedNodeSlot) == SharedNode::Role::ADMIN;
}

bool VirtualNodeManager::hasActiveAdminSession() const
{
    concurrency::LockGuard guard(&sessionLock);
    return hasAdminLocked();
}

VirtualNodeManager::SessionInfo *VirtualNodeManager::allocateSessionLocked()
{
    SessionInfo *session = sessionSlots.allocate([](const SessionInfo &candidate) { return !candidate.used; });
    if (session) {
        *session = SessionInfo{};
        session->used = true;
    }
    return session;
}

VirtualNodeManager::SessionInfo *VirtualNodeManager::findSessionByApiLocked(PhoneAPI *api)
{
    return sessionSlots.find([api](const SessionInfo &session) { return session.used && session.api == api; });
}

const VirtualNodeManager::SessionInfo *VirtualNodeManager::findSessionByApiLocked(const PhoneAPI *api) const
{
    return sessionSlots.find([api](const SessionInfo &session) { return session.used && session.api == api; });
}

VirtualNodeManager::SessionInfo *VirtualNodeManager::findSessionByVirtualNodeLocked(NodeNum virtualNodeId)
{
    return sessionSlots.find(
        [virtualNodeId](const SessionInfo &session) { return session.used && session.virtualNodeId == virtualNodeId; });
}

const VirtualNodeManager::SessionInfo *VirtualNodeManager::findSessionByVirtualNodeLocked(NodeNum virtualNodeId) const
{
    return sessionSlots.find(
        [virtualNodeId](const SessionInfo &session) { return session.used && session.virtualNodeId == virtualNodeId; });
}

bool VirtualNodeManager::hasAdminLocked(const PhoneAPI *exceptApi) const
{
    for (const SessionInfo &session : sessions) {
        if (session.used && SharedNode::roleForSlot(session.sharedNodeSlot) == SharedNode::Role::ADMIN &&
            session.api != exceptApi) {
            return true;
        }
    }
    return false;
}

void VirtualNodeManager::enqueueLocalPacketLocked(const PhoneAPI *api, const meshtastic_MeshPacket &packet)
{
    SessionInfo *session = findSessionByApiLocked(const_cast<PhoneAPI *>(api));
    if (!session) {
        return;
    }
    session->localPackets.push(packet);
}

NodeNum VirtualNodeManager::allocateVirtualNodeIdLocked()
{
    // Keep virtual node IDs small and visually distinct from the physical node
    // number. 0 is reserved by packet semantics, 0xff is avoided as a sentinel.
    if (nextVirtualNodeId < 0x0A || nextVirtualNodeId > 0xFE) {
        nextVirtualNodeId = 0x0A;
    }

    for (uint16_t attempts = 0; attempts < 0xF5; attempts++) {
        const NodeNum candidate = nextVirtualNodeId;
        nextVirtualNodeId++;
        if (nextVirtualNodeId > 0xFE) {
            nextVirtualNodeId = 0x0A;
        }
        if (!findSessionByVirtualNodeLocked(candidate)) {
            return candidate;
        }
    }

    // The configured table is tiny, so this should only happen if state is
    // already inconsistent. Return a candidate rather than blocking pairing.
    return nextVirtualNodeId++;
}
#endif
