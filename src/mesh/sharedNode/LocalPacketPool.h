#ifdef MODE_SHARED_NODE
#pragma once

/**
 * @file LocalPacketPool.h
 * @brief SharedNode guest local-delivery packet pool.
 */

#include <Arduino.h>
#include <array>
#include <stddef.h>

#include "MeshTypes.h"
#include "mesh/sharedNode/Types.h"

namespace SharedNode
{

/**
 * @brief Static local-delivery pool shared by all virtual guest sessions.
 *
 * The pool stores each broadcast packet once and lets every guest advance a
 * sequence cursor through the shared broadcast log. Direct and service packets
 * are stored as targeted entries linked from the destination session. The class
 * intentionally performs no locking; VirtualNodeManager owns synchronization.
 */
class LocalPacketPool
{
  public:
    /**
     * @brief Sentinel index for empty linked-list links.
     */
    static constexpr uint8_t INVALID_INDEX = 0xff;

    /**
     * @brief Local delivery class encoded in LocalPacketEntry metadata.
     */
    enum class PacketKind : uint8_t {
        /**
         * @brief Unused packet slot available for reuse.
         */
        FREE = 0,

        /**
         * @brief Narrow local control-plane packet, such as admin or routing responses.
         */
        SERVICE = 1,

        /**
         * @brief Targeted local data-plane packet for exactly one guest session.
         */
        DIRECT = 2,

        /**
         * @brief Shared broadcast-log packet readable by every active guest cursor.
         */
        BROADCAST = 3,
    };

    /**
     * @brief Computed consumer state used when reclaiming packet slots.
     */
    enum class DeliveryHealth : uint8_t {
        /**
         * @brief Session has polled recently or has no pending local backlog.
         */
        ACTIVE = 0,

        /**
         * @brief Session is still connected but has not drained its backlog recently.
         */
        STALLED = 1,

        /**
         * @brief Session has been silent long enough to lose queued local delivery under pressure.
         */
        DEAD = 2,
    };

    /**
     * @brief Per-live-session state owned by VirtualNodeManager.
     */
    struct SessionState {
        /**
         * @brief Head index for the per-session SERVICE linked list.
         */
        uint8_t serviceHead = INVALID_INDEX;

        /**
         * @brief Tail index for the per-session SERVICE linked list.
         */
        uint8_t serviceTail = INVALID_INDEX;

        /**
         * @brief Head index for the per-session DIRECT linked list.
         */
        uint8_t directHead = INVALID_INDEX;

        /**
         * @brief Tail index for the per-session DIRECT linked list.
         */
        uint8_t directTail = INVALID_INDEX;

        /**
         * @brief Number of SERVICE packets currently linked to this session.
         */
        uint8_t pendingService = 0;

        /**
         * @brief Number of DIRECT packets currently linked to this session.
         */
        uint8_t pendingDirect = 0;

        /**
         * @brief Next broadcast-log sequence number this session should read.
         *
         * Broadcast entries are shared globally, so each guest advances this
         * wrap-safe cursor instead of owning per-broadcast packet copies.
         */
        uint16_t nextBroadcastSeq = 0;

        /**
         * @brief Millisecond timestamp of the most recent local-delivery poll.
         */
        uint32_t lastLocalPollMs = 0;

        /**
         * @brief Count of local packets dropped for this session.
         */
        uint32_t droppedLocalPackets = 0;

        /**
         * @brief True when this state belongs to a currently connected guest.
         */
        bool deliveryActive = false;
    };

#ifdef PIO_UNIT_TESTING
    /**
     * @brief Snapshot of pool-wide counters for tests.
     */
    struct Stats {
        /**
         * @brief Number of occupied packet slots across all packet kinds.
         */
        size_t usedTotal = 0;

        /**
         * @brief Number of occupied shared broadcast-log slots.
         */
        size_t usedBroadcast = 0;

        /**
         * @brief Number of occupied DIRECT slots.
         */
        size_t usedDirect = 0;

        /**
         * @brief Number of occupied SERVICE slots.
         */
        size_t usedService = 0;

        /**
         * @brief Number of slots currently available for allocation.
         */
        size_t freeCount = 0;

        /**
         * @brief Number of broadcast packets dropped by pool pressure.
         */
        uint32_t droppedBroadcast = 0;

        /**
         * @brief Number of DIRECT packets dropped by pool pressure or caps.
         */
        uint32_t droppedDirect = 0;

        /**
         * @brief Number of SERVICE packets dropped by pool pressure or caps.
         */
        uint32_t droppedService = 0;
    };

    /**
     * @brief Snapshot of one session's local-delivery state for tests.
     */
    struct SessionStats {
        /**
         * @brief Number of SERVICE packets queued for the session.
         */
        uint8_t pendingService = 0;

        /**
         * @brief Number of DIRECT packets queued for the session.
         */
        uint8_t pendingDirect = 0;

        /**
         * @brief Next broadcast sequence the session will attempt to read.
         */
        uint16_t nextBroadcastSeq = 0;

        /**
         * @brief Count of packets dropped from this session's local queues.
         */
        uint32_t droppedLocalPackets = 0;

        /**
         * @brief True when this test snapshot represents an active guest delivery state.
         */
        bool deliveryActive = false;
    };
#endif

    /**
     * @brief Creates an empty local-delivery pool.
     */
    LocalPacketPool();

    /**
     * @brief Clears every packet slot and resets broadcast sequencing.
     */
    void reset();

    /**
     * @brief Initializes a guest session to receive only future broadcasts.
     *
     * @param session Session delivery state to initialize.
     * @param nowMs Current millisecond timestamp.
     */
    void initializeSession(SessionState &session, uint32_t nowMs);

    /**
     * @brief Drops all targeted packets for a session and disables delivery.
     *
     * Broadcast packets are not per-session owned, so cleanup only resets the
     * session cursor to the current tail.
     *
     * @param session Session delivery state to clean up.
     * @param sessionIndex Index encoded in targeted packet metadata.
     */
    void cleanupSession(SessionState &session, uint8_t sessionIndex);

    /**
     * @brief Queues one shared broadcast packet for all active guest sessions.
     *
     * @param packet Packet to store once in the shared broadcast log.
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param nowMs Current millisecond timestamp.
     * @return true when the broadcast was stored.
     */
    bool enqueueBroadcast(const meshtastic_MeshPacket &packet, SessionState *sessions, size_t sessionCount, uint32_t nowMs);

    /**
     * @brief Queues a targeted direct or service packet for one guest session.
     *
     * @param kind Targeted packet class; must be DIRECT or SERVICE.
     * @param targetSessionIndex Destination session index.
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param packet Packet to queue.
     * @param nowMs Current millisecond timestamp.
     * @return true when the packet was stored.
     */
    bool enqueueTargeted(PacketKind kind, uint8_t targetSessionIndex, SessionState *sessions, size_t sessionCount,
                         const meshtastic_MeshPacket &packet, uint32_t nowMs);

    /**
     * @brief Pops the next packet for a guest session.
     *
     * Packets are delivered in service, direct, then broadcast order. Polling
     * refreshes the session health even when no packet is available.
     *
     * @param sessionIndex Session index to pop for.
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param packetOut Destination updated with the popped packet.
     * @param nowMs Current millisecond timestamp.
     * @return true when a packet was popped.
     */
    bool pop(uint8_t sessionIndex, SessionState *sessions, size_t sessionCount, meshtastic_MeshPacket &packetOut,
             uint32_t nowMs);

    /**
     * @brief Checks whether a session has any local packet available.
     *
     * @param session Session delivery state to inspect.
     * @return true when a targeted packet or readable broadcast exists.
     */
    bool hasPending(const SessionState &session) const;

    /**
     * @brief Returns the next sequence assigned to a newly queued packet.
     *
     * @return Current sequence tail.
     */
    uint16_t currentSequence() const { return nextSeq; }

#ifdef PIO_UNIT_TESTING
    /**
     * @brief Returns pool counters for unit tests.
     *
     * @return Snapshot of pool-wide slot and drop counters.
     */
    Stats getStatsForTest() const;

    /**
     * @brief Returns one session's counters for unit tests.
     *
     * @param session Session state to snapshot.
     * @return Snapshot of per-session local-delivery counters.
     */
    static SessionStats getSessionStatsForTest(const SessionState &session);

    /**
     * @brief Overrides a session poll timestamp for unit tests.
     *
     * @param session Session state to update.
     * @param lastLocalPollMs Replacement millisecond timestamp.
     */
    static void setLastLocalPollMsForTest(SessionState &session, uint32_t lastLocalPollMs)
    {
        session.lastLocalPollMs = lastLocalPollMs;
    }
#endif

  private:
    /**
     * @brief Compact packet slot stored in the shared static pool.
     */
    struct LocalPacketEntry {
        /**
         * @brief Packet payload copied from the mesh/local delivery path.
         */
        meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_zero;

        /**
         * @brief Wrap-safe insertion sequence used for broadcast cursors and ordering.
         */
        uint16_t seq = 0;

        /**
         * @brief Packed metadata: bits 0..1 are PacketKind, bits 2..6 are target session index.
         */
        uint8_t meta = 0;

        /**
         * @brief Next entry index in a linked list; this is an array index, not a pointer.
         */
        uint8_t next = INVALID_INDEX;
    };

    std::array<LocalPacketEntry, LOCAL_PACKET_POOL_SIZE> entries{};
    uint8_t broadcastHead = INVALID_INDEX;
    uint8_t broadcastTail = INVALID_INDEX;
    uint16_t nextSeq = 0;
    size_t usedTotal = 0;
    size_t usedBroadcast = 0;
    size_t usedDirect = 0;
    size_t usedService = 0;
    uint32_t droppedBroadcast = 0;
    uint32_t droppedDirect = 0;
    uint32_t droppedService = 0;

    /**
     * @brief Packs a packet kind and 5-bit target session index into metadata.
     *
     * @param kind Packet kind to encode in bits 0..1.
     * @param targetSessionIndex Session index to encode in bits 2..6.
     * @return Packed LocalPacketEntry metadata byte.
     */
    static uint8_t makeMeta(PacketKind kind, uint8_t targetSessionIndex);

    /**
     * @brief Extracts the packet kind from an entry's packed metadata.
     *
     * @param entry Packet slot to inspect.
     * @return Packet kind stored in bits 0..1.
     */
    static PacketKind kindOf(const LocalPacketEntry &entry);

    /**
     * @brief Extracts the target session index from an entry's packed metadata.
     *
     * @param entry Packet slot to inspect.
     * @return 5-bit target session index stored in bits 2..6.
     */
    static uint8_t targetOf(const LocalPacketEntry &entry);

    /**
     * @brief Checks whether a packet kind is owned by one destination session.
     *
     * @param kind Packet kind to inspect.
     * @return true for SERVICE and DIRECT packets.
     */
    static bool isTargetedKind(PacketKind kind);

    /**
     * @brief Compares two uint16_t sequence numbers with wrap-safe ordering.
     *
     * @param left Sequence to test.
     * @param right Reference sequence.
     * @return true when @p left is before @p right.
     */
    static bool sequenceBefore(uint16_t left, uint16_t right);

    /**
     * @brief Compares two uint16_t sequence numbers with wrap-safe ordering.
     *
     * @param left Sequence to test.
     * @param right Reference sequence.
     * @return true when @p left is after @p right.
     */
    static bool sequenceAfter(uint16_t left, uint16_t right);

    /**
     * @brief Compares two uint16_t sequence numbers with wrap-safe ordering.
     *
     * @param left Sequence to test.
     * @param right Reference sequence.
     * @return true when @p left is equal to or after @p right.
     */
    static bool sequenceAtOrAfter(uint16_t left, uint16_t right);

    /**
     * @brief Counts free packet slots in the static pool.
     *
     * @return Number of currently unused slots.
     */
    size_t freeCount() const { return LOCAL_PACKET_POOL_SIZE - usedTotal; }

    /**
     * @brief Calculates slots that must remain free to preserve broadcast reserve.
     *
     * @return Number of free slots targeted traffic may not consume.
     */
    size_t broadcastDeficit() const;

    /**
     * @brief Finds any unused packet slot.
     *
     * @return Slot index, or INVALID_INDEX when the pool is full.
     */
    uint8_t findFreeSlot() const;

    /**
     * @brief Finds an unused slot without violating the broadcast reserve floor.
     *
     * @return Slot index, or INVALID_INDEX when targeted traffic should not allocate.
     */
    uint8_t findFreeSlotForTargeted() const;

    /**
     * @brief Computes delivery health from poll recency and backlog.
     *
     * @param session Session state to evaluate.
     * @param nowMs Current millisecond timestamp.
     * @return ACTIVE, STALLED, or DEAD for eviction decisions.
     */
    DeliveryHealth healthFor(const SessionState &session, uint32_t nowMs) const;

    /**
     * @brief Returns the per-session packet cap for a kind and health state.
     *
     * @param kind Targeted packet kind to cap.
     * @param health Computed session health.
     * @return Maximum retained packets for that class.
     */
    size_t capFor(PacketKind kind, DeliveryHealth health) const;

    /**
     * @brief Checks whether a session can read a broadcast entry at its cursor.
     *
     * @param session Session state to inspect.
     * @return true when the broadcast log contains a sequence at or after the cursor.
     */
    bool hasBroadcastPending(const SessionState &session) const;

    /**
     * @brief Checks whether a broadcast should be preserved for stalled sessions.
     *
     * @param slotIndex Broadcast slot to inspect.
     * @return true when the slot is inside the configured stalled backlog window.
     */
    bool isWithinStalledBroadcastBacklog(uint8_t slotIndex) const;

    /**
     * @brief Checks whether a broadcast entry can be reclaimed.
     *
     * @param slotIndex Broadcast slot to inspect.
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param nowMs Current millisecond timestamp.
     * @param pressure true when reclaiming during allocation pressure.
     * @return true when no relevant active cursor still needs the entry.
     */
    bool canReclaimBroadcast(uint8_t slotIndex, const SessionState *sessions, size_t sessionCount, uint32_t nowMs,
                             bool pressure) const;

    /**
     * @brief Releases consumed broadcast-log entries from the head.
     *
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param nowMs Current millisecond timestamp.
     * @param pressure true to ignore DEAD and over-backlog STALLED cursors.
     * @return true when at least one broadcast entry was reclaimed.
     */
    bool reclaimConsumedBroadcasts(SessionState *sessions, size_t sessionCount, uint32_t nowMs, bool pressure);

    /**
     * @brief Acquires a slot for a new broadcast packet using broadcast eviction rules.
     *
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param nowMs Current millisecond timestamp.
     * @param slotIndex Output slot index when allocation succeeds.
     * @return true when a slot was acquired.
     */
    bool acquireSlotForBroadcast(SessionState *sessions, size_t sessionCount, uint32_t nowMs, uint8_t &slotIndex);

    /**
     * @brief Acquires a slot for a new targeted packet using reserve-aware eviction.
     *
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param nowMs Current millisecond timestamp.
     * @param slotIndex Output slot index when allocation succeeds.
     * @return true when a slot was acquired.
     */
    bool acquireSlotForTargeted(SessionState *sessions, size_t sessionCount, uint32_t nowMs, uint8_t &slotIndex);

    /**
     * @brief Stores a packet as the newest shared broadcast-log entry.
     *
     * @param slotIndex Free slot to populate.
     * @param packet Packet to store.
     */
    void storeBroadcast(uint8_t slotIndex, const meshtastic_MeshPacket &packet);

    /**
     * @brief Stores a packet as the newest entry in a session targeted queue.
     *
     * @param slotIndex Free slot to populate.
     * @param kind Targeted packet kind.
     * @param targetSessionIndex Destination session index for metadata.
     * @param target Destination session state.
     * @param packet Packet to store.
     */
    void storeTargeted(uint8_t slotIndex, PacketKind kind, uint8_t targetSessionIndex, SessionState &target,
                       const meshtastic_MeshPacket &packet);

    /**
     * @brief Pops the oldest targeted packet of a given kind from a session.
     *
     * @param session Session state to pop from.
     * @param kind Targeted packet kind.
     * @param packetOut Destination updated with the popped packet.
     * @return true when a packet was popped.
     */
    bool popTargeted(SessionState &session, PacketKind kind, meshtastic_MeshPacket &packetOut);

    /**
     * @brief Drops the oldest targeted packet of a given kind from a session.
     *
     * @param session Session state to trim.
     * @param kind Targeted packet kind.
     * @param countDrop true to increment drop counters.
     * @return true when a packet was dropped.
     */
    bool dropOldestTargeted(SessionState &session, PacketKind kind, bool countDrop);

    /**
     * @brief Drops all SERVICE and DIRECT packets owned by a session.
     *
     * @param session Session state to purge.
     * @param countDrop true to increment drop counters.
     * @return true when at least one packet was dropped.
     */
    bool dropAllTargeted(SessionState &session, bool countDrop);

    /**
     * @brief Purges targeted queues for sessions considered DEAD.
     *
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param nowMs Current millisecond timestamp.
     * @return true when at least one packet was dropped.
     */
    bool purgeDeadTargeted(SessionState *sessions, size_t sessionCount, uint32_t nowMs);

    /**
     * @brief Trims stalled sessions down to their lower per-kind caps.
     *
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @param nowMs Current millisecond timestamp.
     * @return true when at least one packet was dropped.
     */
    bool trimStalledTargeted(SessionState *sessions, size_t sessionCount, uint32_t nowMs);

    /**
     * @brief Drops one DIRECT packet from the active session with the largest direct backlog.
     *
     * @param sessions All delivery sessions.
     * @param sessionCount Number of entries in @p sessions.
     * @return true when a packet was dropped.
     */
    bool dropOldestDirectFromMostBacklogged(SessionState *sessions, size_t sessionCount);

    /**
     * @brief Drops the oldest shared broadcast-log entry.
     *
     * @param countDrop true to increment broadcast drop counters.
     * @return true when a broadcast packet was dropped.
     */
    bool dropOldestBroadcast(bool countDrop);

    /**
     * @brief Releases a targeted slot and decrements its pool counters.
     *
     * @param slotIndex Slot index to release.
     * @param kind Targeted packet kind stored in the slot.
     */
    void releaseTargetedSlot(uint8_t slotIndex, PacketKind kind);

    /**
     * @brief Releases the current broadcast-log head and decrements counters.
     *
     * @param countDrop true to increment broadcast drop counters.
     */
    void releaseBroadcastHead(bool countDrop);

    /**
     * @brief Marks a slot as FREE by resetting its compact entry state.
     *
     * @param slotIndex Slot index to reset.
     */
    void releaseFreeSlot(uint8_t slotIndex);
};

} // namespace SharedNode
#endif
