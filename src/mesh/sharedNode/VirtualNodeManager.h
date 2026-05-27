#ifdef MODE_SHARED_NODE
#pragma once

/**
 * @file VirtualNodeManager.h
 * @brief Shared-node virtual session and packet routing manager.
 */

#include <Arduino.h>
#include <array>

#include "configuration.h"
#include "MeshTypes.h"
#include "concurrency/Lock.h"
#include "mesh/sharedNode/LocalPacketPool.h"
#include "mesh/sharedNode/Types.h"
#include "mesh/sharedNode/static/SlotTable.h"

class PhoneAPI;

/**
 * @brief Manages shared-node PhoneAPI sessions and guest virtual node IDs.
 *
 * VirtualNodeManager maps connected PhoneAPI clients to either the real local
 * node identity for the admin session or to per-guest virtual node IDs. It also
 * enforces guest restrictions on outgoing admin packets and queues packets that
 * can be delivered locally between clients on the same device. Guest local
 * delivery is routed through SharedNode::LocalPacketPool; the admin/physical
 * node remains on the normal PhoneAPI global queue and radio paths.
 */
class VirtualNodeManager
{
  public:
    /**
     * @brief Runtime state for one connected admin or guest session.
     */
    struct SessionInfo {
        /**
         * @brief Connected client's PhoneAPI instance.
         */
        PhoneAPI *api = nullptr;

        /**
         * @brief Virtual node ID assigned to this session, or 0 if unassigned.
         */
        NodeNum virtualNodeId = 0;

        /**
         * @brief Shared-node slot owned by this session.
         */
        uint8_t sharedNodeSlot = SharedNode::INVALID_SLOT;

        /**
         * @brief Runtime table index used by both session and guest delivery state.
         *
         * LocalPacketPool stores only compact indexes in packet metadata, so
         * this value is the bridge between the live session table and the
         * parallel local-delivery state array.
         */
        uint8_t sessionIndex = SharedNode::LocalPacketPool::INVALID_INDEX;

        /**
         * @brief Indicates whether this slot currently contains an active session.
         */
        bool used = false;
    };

    /**
     * @brief Decision returned after processing a client-originated packet.
     */
    enum class OutgoingPacketDecision : uint8_t {
      /**
       * @brief Allow the packet to continue to the radio path.
       */
      ALLOW_RADIO = 0,

      /**
       * @brief Reject the packet before it reaches the radio path.
       */
      REJECT = 1,

      /**
       * @brief Packet was queued for another local virtual node.
       */
      HANDLED_LOCAL = 2,
    };

    /**
     * @brief Result returned when registering an API session.
     */
    enum class SessionStartResult : uint8_t {
        OK = 0,
        UNKNOWN_ROLE = 1,
        ADMIN_ALREADY_CONNECTED = 2,
        GUEST_LIMIT_REACHED = 3,
        TABLE_FULL = 4,
        GUEST_IDENTITY_UNAVAILABLE = 5,
    };

    /**
     * @brief User-facing reason for a rejected outgoing packet.
     */
    enum class OutgoingRejectionReason : uint8_t {
        NONE = 0,
        NOT_AUTHORIZED = 1,
        ADMIN_ONLY = 2,
        NOT_OWN_PROFILE = 3,
    };

    /**
     * @brief Result returned after processing a client-originated packet.
     */
    struct OutgoingPacketResult {
        OutgoingPacketDecision decision = OutgoingPacketDecision::ALLOW_RADIO;
        OutgoingRejectionReason rejectionReason = OutgoingRejectionReason::NONE;
    };

    /**
     * @brief Creates a manager backed by the internal static session table.
     */
    VirtualNodeManager();

    /**
     * @brief Connects a PhoneAPI session as the shared-node admin.
     *
     * Only one active admin session is allowed at a time.
     *
     * @param api PhoneAPI instance for the connected client.
     * @return Session registration result.
     */
    SessionStartResult connectAsAdmin(PhoneAPI *api);

    /**
     * @brief Connects a PhoneAPI session as a shared-node guest.
     *
     * A guest receives a stable virtual node ID for its assigned shared-node
     * slot. If the slot has no ID yet, one is allocated and persisted through
     * SharedNodePairingPolicy.
     *
     * @param api PhoneAPI instance for the connected client.
     * @return Session registration result.
     */
    SessionStartResult connectAsGuest(PhoneAPI *api);

    /**
     * @brief Disconnects a PhoneAPI session and clears its runtime state.
     *
     * @param api PhoneAPI instance to disconnect.
     */
    void disconnect(PhoneAPI *api);

    /**
     * @brief Returns the virtual node ID assigned to a session.
     *
     * @param api PhoneAPI instance to look up.
     * @return Assigned virtual node ID, or 0 when no session exists.
     */
    NodeNum getVirtualNodeId(const PhoneAPI *api) const;

    /**
     * @brief Checks whether a node number belongs to an active local guest session.
     *
     * @param nodeNum Node number to test.
     * @return true when the node number is assigned to a live local session.
     */
    bool isLocalVirtualNode(NodeNum nodeNum) const;

    /**
     * @brief Returns the shared-node slot for an active local virtual node.
     *
     * The physical node number is not considered a virtual node, even if an
     * admin PhoneAPI session is connected.
     *
     * @param nodeNum Virtual node number to inspect.
     * @return Shared-node slot, or INVALID_SLOT when the node is not active locally.
     */
    uint8_t sharedNodeSlotForVirtualNode(NodeNum nodeNum) const;

    /**
     * @brief Checks whether a PhoneAPI session is the active admin session.
     *
     * @param api PhoneAPI instance to test.
     * @return true when the session exists and its slot implies admin privileges.
     */
    bool isAdmin(const PhoneAPI *api) const;

    /**
     * @brief Checks whether any admin session is currently active.
     *
     * @return true when an admin session is connected.
     */
    bool hasActiveAdminSession() const;

    /**
     * @brief Applies shared-node rules to a packet emitted by a client.
     *
     * Guest packets are rewritten to use the guest virtual node ID as source.
     * Guest admin packets targeting local nodes are rejected. Packets addressed
     * to another local virtual node are queued locally instead of sent by radio.
     *
     * @param packet Packet to inspect and possibly rewrite.
     * @param sourceApi Source PhoneAPI instance, or nullptr for non-client packets.
     * @return Result describing how the caller should handle the packet.
     */
    OutgoingPacketResult handleOutgoingPacket(meshtastic_MeshPacket &packet, PhoneAPI *sourceApi);

    /**
     * @brief Queues a user-facing notification to an active virtual client.
     *
     * @param nodeNum Active virtual node ID to notify.
     * @param level Notification level.
     * @param replyId Packet ID associated with the failed action, or 0.
     * @param message User-facing message.
     * @return true when a live local session received the notification.
     */
    bool sendNotificationToVirtualNode(NodeNum nodeNum, meshtastic_LogRecord_Level level, uint32_t replyId, const char *message);

    /**
     * @brief Maps a session start result to a user-facing message.
     *
     * @param result Session start result.
     * @return Message text, or nullptr for success.
     */
    static const char *getSessionStartMessage(SessionStartResult result);

    /**
     * @brief Maps an outgoing rejection reason to a user-facing message.
     *
     * @param reason Rejection reason.
     * @return Message text, or nullptr when no message is needed.
     */
    static const char *getOutgoingRejectionMessage(OutgoingRejectionReason reason);

    /**
     * @brief Queues an incoming mesh packet for matching local guest sessions.
     *
     * This path is guest-only: broadcasts are stored once in the shared pool
     * for all active virtual guests, and unicasts to a virtual guest become
     * targeted pool entries. The physical node/admin delivery path is left to
     * the regular PhoneAPI queue.
     *
     * @param packet Incoming packet to offer to local guest queues.
     */
    void handleIncomingPacket(meshtastic_MeshPacket &packet);

    /**
     * @brief Checks whether a PhoneAPI session has queued local packets.
     *
     * Only virtual guest sessions consult LocalPacketPool. Admin/physical
     * sessions should continue through the normal global PhoneAPI queue.
     *
     * @param api PhoneAPI instance to inspect.
     * @return true when at least one local packet is queued.
     */
    bool hasLocalPacketForApi(const PhoneAPI *api) const;

    /**
     * @brief Pops the oldest locally queued packet for a PhoneAPI session.
     *
     * The pool returns SERVICE, DIRECT, then shared BROADCAST packets for guest
     * sessions. Admin/physical sessions do not consume this guest-only pool.
     *
     * @param api PhoneAPI instance to inspect.
     * @param packetOut Destination updated with the popped packet.
     * @return true when a packet was popped.
     */
    bool popLocalPacketForApi(const PhoneAPI *api, meshtastic_MeshPacket &packetOut);

#ifdef PIO_UNIT_TESTING
    /**
     * @brief Returns local packet pool counters for unit tests.
     *
     * @return Snapshot of shared guest local-delivery pool counters.
     */
    SharedNode::LocalPacketPool::Stats getLocalPacketPoolStatsForTest() const { return localPacketPool.getStatsForTest(); }

    /**
     * @brief Returns local delivery counters for a live API session.
     *
     * @param api PhoneAPI instance to inspect.
     * @return Snapshot of that session's local delivery counters, or empty stats.
     */
    SharedNode::LocalPacketPool::SessionStats getLocalSessionStatsForTest(const PhoneAPI *api) const;
#endif

  private:
    /**
     * @brief Guards access to session state.
     */
    mutable concurrency::Lock sessionLock;

    /**
     * @brief Fixed-size table of active admin and guest sessions.
     */
    std::array<SessionInfo, SharedNode::MAX_CLIENTS> sessions{};

    /**
     * @brief Predicate helper used to search the session table.
     */
    StaticSlotTable<SessionInfo, SharedNode::MAX_CLIENTS> sessionSlots;

    /**
     * @brief Per-session guest delivery state indexed by SessionInfo::sessionIndex.
     */
    std::array<SharedNode::LocalPacketPool::SessionState, SharedNode::MAX_CLIENTS> localDeliverySessions{};

    /**
     * @brief Shared static packet pool used only by guest local delivery.
     */
    SharedNode::LocalPacketPool localPacketPool;

    /**
     * @brief Allocates a free session slot.
     *
     * @pre sessionLock is held by the caller.
     * @return Mutable session slot, or nullptr when no slot is free.
     */
    SessionInfo *allocateSessionLocked();

    /**
     * @brief Finds a mutable session by PhoneAPI pointer.
     *
     * @pre sessionLock is held by the caller.
     * @param api PhoneAPI instance to find.
     * @return Matching session, or nullptr when not connected.
     */
    SessionInfo *findSessionByApiLocked(PhoneAPI *api);

    /**
     * @brief Finds a const session by PhoneAPI pointer.
     *
     * @pre sessionLock is held by the caller.
     * @param api PhoneAPI instance to find.
     * @return Matching session, or nullptr when not connected.
     */
    const SessionInfo *findSessionByApiLocked(const PhoneAPI *api) const;

    /**
     * @brief Finds a mutable session by virtual node ID.
     *
     * @pre sessionLock is held by the caller.
     * @param virtualNodeId Virtual node ID to find.
     * @return Matching session, or nullptr when not connected.
     */
    SessionInfo *findSessionByVirtualNodeLocked(NodeNum virtualNodeId);

    /**
     * @brief Finds a const session by virtual node ID.
     *
     * @pre sessionLock is held by the caller.
     * @param virtualNodeId Virtual node ID to find.
     * @return Matching session, or nullptr when not connected.
     */
    const SessionInfo *findSessionByVirtualNodeLocked(NodeNum virtualNodeId) const;

    /**
     * @brief Checks whether an admin session exists.
     *
     * @pre sessionLock is held by the caller.
     * @param exceptApi Optional PhoneAPI instance to ignore during the check.
     * @return true when another admin session is active.
     */
    bool hasAdminLocked(const PhoneAPI *exceptApi = nullptr) const;

    /**
     * @brief Clears a live session and releases any guest local delivery state.
     *
     * Guest cleanup immediately releases targeted packet slots. Shared
     * broadcast entries remain globally owned and are reclaimed by cursors.
     *
     * @pre sessionLock is held by the caller.
     * @param session Session to clear.
     */
    void clearSessionLocked(SessionInfo &session);

    /**
     * @brief Returns true when a session is a virtual guest with local delivery.
     *
     * This excludes the admin/physical node even when an admin PhoneAPI session
     * is connected, keeping the guest eviction pool isolated from the main node.
     *
     * @pre sessionLock is held by the caller.
     * @param session Session to inspect.
     * @param localNodeNum Physical node number.
     * @return true when the session represents a virtual guest.
     */
    bool isLocalDeliveryGuestLocked(const SessionInfo &session, NodeNum localNodeNum) const;

    /**
     * @brief Classifies a targeted packet for local delivery priority.
     *
     * SERVICE is intentionally narrow and reserved for local control-plane
     * traffic. Ordinary data-plane packets remain DIRECT so they cannot starve
     * broadcast or other guests as high-priority traffic.
     *
     * @param packet Packet to classify.
     * @return SERVICE for narrow control-plane packets, otherwise DIRECT.
     */
    SharedNode::LocalPacketPool::PacketKind classifyTargetedLocalPacket(const meshtastic_MeshPacket &packet) const;

    /**
     * @brief Queues a packet for local delivery to a guest session.
     *
     * The helper assumes the caller has already selected a live virtual guest
     * destination and classified the packet. Admin/physical traffic is not
     * routed through this helper.
     *
     * @pre sessionLock is held by the caller.
     * @param session Destination session.
     * @param packet Packet to queue.
     * @param kind Local delivery class.
     */
    void enqueueLocalPacketLocked(SessionInfo &session, const meshtastic_MeshPacket &packet,
                                  SharedNode::LocalPacketPool::PacketKind kind);

};

/**
 * @brief Global shared-node virtual manager.
 */
extern VirtualNodeManager virtualNodeManager;
#endif
