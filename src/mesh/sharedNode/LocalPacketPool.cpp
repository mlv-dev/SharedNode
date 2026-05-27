#ifdef MODE_SHARED_NODE
#include "mesh/sharedNode/LocalPacketPool.h"

/**
 * @file LocalPacketPool.cpp
 * @brief Implements SharedNode guest local-delivery buffering.
 */

namespace SharedNode
{

LocalPacketPool::LocalPacketPool()
{
    reset();
}

void LocalPacketPool::reset()
{
    for (LocalPacketEntry &entry : entries) {
        entry = LocalPacketEntry{};
    }
    broadcastHead = INVALID_INDEX;
    broadcastTail = INVALID_INDEX;
    nextSeq = 0;
    usedTotal = 0;
    usedBroadcast = 0;
    usedDirect = 0;
    usedService = 0;
    droppedBroadcast = 0;
    droppedDirect = 0;
    droppedService = 0;
}

void LocalPacketPool::initializeSession(SessionState &session, uint32_t nowMs)
{
    session = SessionState{};
    session.deliveryActive = true;
    // New or reconnected guests start at the current broadcast tail. Older
    // broadcast backlog belongs to clients that were already connected.
    session.nextBroadcastSeq = nextSeq;
    session.lastLocalPollMs = nowMs;
}

void LocalPacketPool::cleanupSession(SessionState &session, uint8_t)
{
    // Disconnected clients do not retain targeted delivery state. Broadcast is
    // shared, so cleanup only advances this session away from old backlog.
    dropAllTargeted(session, false);
    session = SessionState{};
    session.nextBroadcastSeq = nextSeq;
}

bool LocalPacketPool::enqueueBroadcast(const meshtastic_MeshPacket &packet, SessionState *sessions, size_t sessionCount,
                                       uint32_t nowMs)
{
    uint8_t slotIndex = INVALID_INDEX;
    if (!acquireSlotForBroadcast(sessions, sessionCount, nowMs, slotIndex)) {
        droppedBroadcast++;
        return false;
    }

    storeBroadcast(slotIndex, packet);
    return true;
}

bool LocalPacketPool::enqueueTargeted(PacketKind kind, uint8_t targetSessionIndex, SessionState *sessions, size_t sessionCount,
                                      const meshtastic_MeshPacket &packet, uint32_t nowMs)
{
    if (!isTargetedKind(kind) || !sessions || targetSessionIndex >= sessionCount) {
        return false;
    }

    SessionState &target = sessions[targetSessionIndex];
    if (!target.deliveryActive) {
        return false;
    }

    const DeliveryHealth health = healthFor(target, nowMs);
    if (health == DeliveryHealth::DEAD) {
        // DEAD is a local-delivery pressure state, not a transport decision.
        // The client may poll again later; until then it should not pin queue
        // memory needed by active guests.
        if (kind == PacketKind::SERVICE && target.pendingService > 0) {
            while (target.pendingService > 0) {
                dropOldestTargeted(target, PacketKind::SERVICE, true);
            }
            const uint8_t slotIndex = findFreeSlot();
            if (slotIndex != INVALID_INDEX) {
                storeTargeted(slotIndex, kind, targetSessionIndex, target, packet);
                return true;
            }
        }

        target.droppedLocalPackets++;
        if (kind == PacketKind::SERVICE) {
            droppedService++;
        } else {
            droppedDirect++;
        }
        return false;
    }

    const size_t cap = capFor(kind, health);
    const uint8_t pending = kind == PacketKind::SERVICE ? target.pendingService : target.pendingDirect;
    if (pending >= cap) {
        if (cap == 0) {
            target.droppedLocalPackets++;
            if (kind == PacketKind::SERVICE) {
                droppedService++;
            } else {
                droppedDirect++;
            }
            return false;
        }

        while ((kind == PacketKind::SERVICE ? target.pendingService : target.pendingDirect) >= cap) {
            if (!dropOldestTargeted(target, kind, true)) {
                target.droppedLocalPackets++;
                if (kind == PacketKind::SERVICE) {
                    droppedService++;
                } else {
                    droppedDirect++;
                }
                return false;
            }
        }

        const uint8_t replacementSlot = findFreeSlot();
        if (replacementSlot != INVALID_INDEX) {
            storeTargeted(replacementSlot, kind, targetSessionIndex, target, packet);
            return true;
        }
    }

    uint8_t slotIndex = INVALID_INDEX;
    if (!acquireSlotForTargeted(sessions, sessionCount, nowMs, slotIndex)) {
        if (kind == PacketKind::SERVICE && target.pendingService > 0 &&
            dropOldestTargeted(target, PacketKind::SERVICE, true)) {
            slotIndex = findFreeSlot();
        }
    }

    if (slotIndex == INVALID_INDEX) {
        target.droppedLocalPackets++;
        if (kind == PacketKind::SERVICE) {
            droppedService++;
        } else {
            droppedDirect++;
        }
        return false;
    }

    storeTargeted(slotIndex, kind, targetSessionIndex, target, packet);
    return true;
}

bool LocalPacketPool::pop(uint8_t sessionIndex, SessionState *sessions, size_t sessionCount, meshtastic_MeshPacket &packetOut,
                          uint32_t nowMs)
{
    if (!sessions || sessionIndex >= sessionCount) {
        return false;
    }

    SessionState &session = sessions[sessionIndex];
    if (!session.deliveryActive) {
        return false;
    }

    // A poll proves the transport is alive even when no packet is returned, so
    // empty reads also refresh ACTIVE/STALLED/DEAD classification.
    session.lastLocalPollMs = nowMs;

    // SERVICE is only a narrow local control-plane class, but it should still
    // be delivered before ordinary direct traffic when both are waiting.
    if (popTargeted(session, PacketKind::SERVICE, packetOut)) {
        return true;
    }
    if (popTargeted(session, PacketKind::DIRECT, packetOut)) {
        return true;
    }

    for (uint8_t slotIndex = broadcastHead; slotIndex != INVALID_INDEX; slotIndex = entries[slotIndex].next) {
        const LocalPacketEntry &entry = entries[slotIndex];
        if (sequenceAtOrAfter(entry.seq, session.nextBroadcastSeq)) {
            packetOut = entry.packet;
            session.nextBroadcastSeq = static_cast<uint16_t>(entry.seq + 1U);
            // A broadcast packet is stored once globally. After one cursor
            // moves, the head may become reclaimable for every live guest.
            reclaimConsumedBroadcasts(sessions, sessionCount, nowMs, false);
            return true;
        }
    }

    session.nextBroadcastSeq = nextSeq;
    return false;
}

bool LocalPacketPool::hasPending(const SessionState &session) const
{
    return session.deliveryActive && (session.pendingService > 0 || session.pendingDirect > 0 || hasBroadcastPending(session));
}

#ifdef PIO_UNIT_TESTING
LocalPacketPool::Stats LocalPacketPool::getStatsForTest() const
{
    Stats stats;
    stats.usedTotal = usedTotal;
    stats.usedBroadcast = usedBroadcast;
    stats.usedDirect = usedDirect;
    stats.usedService = usedService;
    stats.freeCount = freeCount();
    stats.droppedBroadcast = droppedBroadcast;
    stats.droppedDirect = droppedDirect;
    stats.droppedService = droppedService;
    return stats;
}

LocalPacketPool::SessionStats LocalPacketPool::getSessionStatsForTest(const SessionState &session)
{
    SessionStats stats;
    stats.pendingService = session.pendingService;
    stats.pendingDirect = session.pendingDirect;
    stats.nextBroadcastSeq = session.nextBroadcastSeq;
    stats.droppedLocalPackets = session.droppedLocalPackets;
    stats.deliveryActive = session.deliveryActive;
    return stats;
}
#endif

uint8_t LocalPacketPool::makeMeta(PacketKind kind, uint8_t targetSessionIndex)
{
    return static_cast<uint8_t>((targetSessionIndex << 2U) | (static_cast<uint8_t>(kind) & 0x03U));
}

LocalPacketPool::PacketKind LocalPacketPool::kindOf(const LocalPacketEntry &entry)
{
    return static_cast<PacketKind>(entry.meta & 0x03U);
}

uint8_t LocalPacketPool::targetOf(const LocalPacketEntry &entry)
{
    return static_cast<uint8_t>((entry.meta >> 2U) & 0x1fU);
}

bool LocalPacketPool::isTargetedKind(PacketKind kind)
{
    return kind == PacketKind::SERVICE || kind == PacketKind::DIRECT;
}

bool LocalPacketPool::sequenceBefore(uint16_t left, uint16_t right)
{
    return static_cast<int16_t>(static_cast<uint16_t>(left - right)) < 0;
}

bool LocalPacketPool::sequenceAfter(uint16_t left, uint16_t right)
{
    return sequenceBefore(right, left);
}

bool LocalPacketPool::sequenceAtOrAfter(uint16_t left, uint16_t right)
{
    return !sequenceBefore(left, right);
}

size_t LocalPacketPool::broadcastDeficit() const
{
    return usedBroadcast >= LOCAL_BROADCAST_RESERVED ? 0 : LOCAL_BROADCAST_RESERVED - usedBroadcast;
}

uint8_t LocalPacketPool::findFreeSlot() const
{
    for (uint16_t i = 0; i < LOCAL_PACKET_POOL_SIZE; ++i) {
        const uint8_t slotIndex = static_cast<uint8_t>(i);
        if (kindOf(entries[slotIndex]) == PacketKind::FREE) {
            return slotIndex;
        }
    }
    return INVALID_INDEX;
}

uint8_t LocalPacketPool::findFreeSlotForTargeted() const
{
    // Targeted traffic may use free space only after leaving enough empty slots
    // for broadcast to climb back to its configured reserve floor.
    if (freeCount() <= broadcastDeficit()) {
        return INVALID_INDEX;
    }
    return findFreeSlot();
}

LocalPacketPool::DeliveryHealth LocalPacketPool::healthFor(const SessionState &session, uint32_t nowMs) const
{
    if (!session.deliveryActive) {
        return DeliveryHealth::DEAD;
    }

    if (session.pendingService == 0 && session.pendingDirect == 0 && !hasBroadcastPending(session)) {
        return DeliveryHealth::ACTIVE;
    }

    const uint32_t elapsedMs = nowMs - session.lastLocalPollMs;
    if (elapsedMs >= LOCAL_DEAD_MS) {
        return DeliveryHealth::DEAD;
    }
    if (elapsedMs >= LOCAL_STALLED_MS) {
        return DeliveryHealth::STALLED;
    }
    return DeliveryHealth::ACTIVE;
}

size_t LocalPacketPool::capFor(PacketKind kind, DeliveryHealth health) const
{
    if (kind == PacketKind::SERVICE) {
        return health == DeliveryHealth::ACTIVE ? LOCAL_ACTIVE_MAX_SERVICE : LOCAL_STALLED_MAX_SERVICE;
    }
    if (kind == PacketKind::DIRECT) {
        return health == DeliveryHealth::ACTIVE ? LOCAL_ACTIVE_MAX_DIRECT : LOCAL_STALLED_MAX_DIRECT;
    }
    return 0;
}

bool LocalPacketPool::hasBroadcastPending(const SessionState &session) const
{
    if (!session.deliveryActive) {
        return false;
    }

    for (uint8_t slotIndex = broadcastHead; slotIndex != INVALID_INDEX; slotIndex = entries[slotIndex].next) {
        if (sequenceAtOrAfter(entries[slotIndex].seq, session.nextBroadcastSeq)) {
            return true;
        }
    }
    return false;
}

bool LocalPacketPool::isWithinStalledBroadcastBacklog(uint8_t slotIndex) const
{
    if (LOCAL_STALLED_BROADCAST_BACKLOG == 0 || slotIndex == INVALID_INDEX ||
        kindOf(entries[slotIndex]) != PacketKind::BROADCAST) {
        return false;
    }

    size_t newerBroadcasts = 0;
    const uint16_t seq = entries[slotIndex].seq;
    for (uint8_t candidate = broadcastHead; candidate != INVALID_INDEX; candidate = entries[candidate].next) {
        if (sequenceAfter(entries[candidate].seq, seq)) {
            newerBroadcasts++;
        }
    }
    return newerBroadcasts < LOCAL_STALLED_BROADCAST_BACKLOG;
}

bool LocalPacketPool::canReclaimBroadcast(uint8_t slotIndex, const SessionState *sessions, size_t sessionCount, uint32_t nowMs,
                                          bool pressure) const
{
    if (slotIndex == INVALID_INDEX || kindOf(entries[slotIndex]) != PacketKind::BROADCAST) {
        return false;
    }

    const uint16_t seq = entries[slotIndex].seq;
    for (size_t i = 0; i < sessionCount; ++i) {
        const SessionState &session = sessions[i];
        if (!session.deliveryActive) {
            continue;
        }

        const DeliveryHealth health = healthFor(session, nowMs);
        if (pressure && health == DeliveryHealth::DEAD) {
            continue;
        }
        if (pressure && health == DeliveryHealth::STALLED && !isWithinStalledBroadcastBacklog(slotIndex)) {
            continue;
        }

        if (!sequenceAfter(session.nextBroadcastSeq, seq)) {
            return false;
        }
    }
    return true;
}

bool LocalPacketPool::reclaimConsumedBroadcasts(SessionState *sessions, size_t sessionCount, uint32_t nowMs, bool pressure)
{
    bool reclaimed = false;
    while (broadcastHead != INVALID_INDEX && canReclaimBroadcast(broadcastHead, sessions, sessionCount, nowMs, pressure)) {
        releaseBroadcastHead(false);
        reclaimed = true;
    }
    return reclaimed;
}

bool LocalPacketPool::acquireSlotForBroadcast(SessionState *sessions, size_t sessionCount, uint32_t nowMs, uint8_t &slotIndex)
{
    slotIndex = findFreeSlot();
    if (slotIndex != INVALID_INDEX) {
        return true;
    }

    reclaimConsumedBroadcasts(sessions, sessionCount, nowMs, false);
    slotIndex = findFreeSlot();
    if (slotIndex != INVALID_INDEX) {
        return true;
    }

    reclaimConsumedBroadcasts(sessions, sessionCount, nowMs, true);
    slotIndex = findFreeSlot();
    if (slotIndex != INVALID_INDEX) {
        return true;
    }

    if (usedBroadcast < LOCAL_BROADCAST_RESERVED) {
        purgeDeadTargeted(sessions, sessionCount, nowMs);
        trimStalledTargeted(sessions, sessionCount, nowMs);
        dropOldestDirectFromMostBacklogged(sessions, sessionCount);
        slotIndex = findFreeSlot();
        if (slotIndex != INVALID_INDEX) {
            return true;
        }
    }

    if (usedBroadcast > 0 && dropOldestBroadcast(true)) {
        slotIndex = findFreeSlot();
        return slotIndex != INVALID_INDEX;
    }

    return false;
}

bool LocalPacketPool::acquireSlotForTargeted(SessionState *sessions, size_t sessionCount, uint32_t nowMs, uint8_t &slotIndex)
{
    slotIndex = findFreeSlotForTargeted();
    if (slotIndex != INVALID_INDEX) {
        return true;
    }

    reclaimConsumedBroadcasts(sessions, sessionCount, nowMs, false);
    slotIndex = findFreeSlotForTargeted();
    if (slotIndex != INVALID_INDEX) {
        return true;
    }

    // SERVICE is higher priority than DIRECT, but not untouchable: a full pool
    // still has to protect active clients and the broadcast reserve.
    purgeDeadTargeted(sessions, sessionCount, nowMs);
    slotIndex = findFreeSlotForTargeted();
    if (slotIndex != INVALID_INDEX) {
        return true;
    }

    trimStalledTargeted(sessions, sessionCount, nowMs);
    slotIndex = findFreeSlotForTargeted();
    if (slotIndex != INVALID_INDEX) {
        return true;
    }

    if (usedBroadcast > LOCAL_BROADCAST_RESERVED && dropOldestBroadcast(true)) {
        slotIndex = findFreeSlotForTargeted();
        if (slotIndex != INVALID_INDEX) {
            return true;
        }
    }

    if (dropOldestDirectFromMostBacklogged(sessions, sessionCount)) {
        slotIndex = findFreeSlotForTargeted();
        return slotIndex != INVALID_INDEX;
    }

    return false;
}

void LocalPacketPool::storeBroadcast(uint8_t slotIndex, const meshtastic_MeshPacket &packet)
{
    LocalPacketEntry &entry = entries[slotIndex];
    entry.packet = packet;
    entry.seq = nextSeq++;
    // Broadcasts do not need a recipient mask because each active guest owns a
    // sequence cursor into the same linked log.
    entry.meta = makeMeta(PacketKind::BROADCAST, 0);
    entry.next = INVALID_INDEX;

    if (broadcastTail != INVALID_INDEX) {
        entries[broadcastTail].next = slotIndex;
    } else {
        broadcastHead = slotIndex;
    }
    broadcastTail = slotIndex;
    usedTotal++;
    usedBroadcast++;
}

void LocalPacketPool::storeTargeted(uint8_t slotIndex, PacketKind kind, uint8_t targetSessionIndex, SessionState &target,
                                    const meshtastic_MeshPacket &packet)
{
    LocalPacketEntry &entry = entries[slotIndex];
    entry.packet = packet;
    entry.seq = nextSeq++;
    entry.meta = makeMeta(kind, targetSessionIndex);
    entry.next = INVALID_INDEX;

    uint8_t &head = kind == PacketKind::SERVICE ? target.serviceHead : target.directHead;
    uint8_t &tail = kind == PacketKind::SERVICE ? target.serviceTail : target.directTail;
    uint8_t &pending = kind == PacketKind::SERVICE ? target.pendingService : target.pendingDirect;
    if (tail != INVALID_INDEX) {
        entries[tail].next = slotIndex;
    } else {
        head = slotIndex;
    }
    tail = slotIndex;
    pending++;

    usedTotal++;
    if (kind == PacketKind::SERVICE) {
        usedService++;
    } else {
        usedDirect++;
    }
}

bool LocalPacketPool::popTargeted(SessionState &session, PacketKind kind, meshtastic_MeshPacket &packetOut)
{
    uint8_t &head = kind == PacketKind::SERVICE ? session.serviceHead : session.directHead;
    uint8_t &tail = kind == PacketKind::SERVICE ? session.serviceTail : session.directTail;
    uint8_t &pending = kind == PacketKind::SERVICE ? session.pendingService : session.pendingDirect;
    if (head == INVALID_INDEX) {
        return false;
    }

    const uint8_t slotIndex = head;
    packetOut = entries[slotIndex].packet;
    head = entries[slotIndex].next;
    if (head == INVALID_INDEX) {
        tail = INVALID_INDEX;
    }
    if (pending > 0) {
        pending--;
    }
    releaseTargetedSlot(slotIndex, kind);
    return true;
}

bool LocalPacketPool::dropOldestTargeted(SessionState &session, PacketKind kind, bool countDrop)
{
    uint8_t &head = kind == PacketKind::SERVICE ? session.serviceHead : session.directHead;
    uint8_t &tail = kind == PacketKind::SERVICE ? session.serviceTail : session.directTail;
    uint8_t &pending = kind == PacketKind::SERVICE ? session.pendingService : session.pendingDirect;
    if (head == INVALID_INDEX) {
        return false;
    }

    const uint8_t slotIndex = head;
    head = entries[slotIndex].next;
    if (head == INVALID_INDEX) {
        tail = INVALID_INDEX;
    }
    if (pending > 0) {
        pending--;
    }

    releaseTargetedSlot(slotIndex, kind);
    if (countDrop) {
        session.droppedLocalPackets++;
        if (kind == PacketKind::SERVICE) {
            droppedService++;
        } else {
            droppedDirect++;
        }
    }
    return true;
}

bool LocalPacketPool::dropAllTargeted(SessionState &session, bool countDrop)
{
    bool dropped = false;
    while (dropOldestTargeted(session, PacketKind::SERVICE, countDrop)) {
        dropped = true;
    }
    while (dropOldestTargeted(session, PacketKind::DIRECT, countDrop)) {
        dropped = true;
    }
    return dropped;
}

bool LocalPacketPool::purgeDeadTargeted(SessionState *sessions, size_t sessionCount, uint32_t nowMs)
{
    bool dropped = false;
    for (size_t i = 0; i < sessionCount; ++i) {
        if (sessions[i].deliveryActive && healthFor(sessions[i], nowMs) == DeliveryHealth::DEAD) {
            // Pressure cleanup drops local queues but deliberately does not
            // disconnect the phone. A later poll makes the session active again.
            dropped |= dropAllTargeted(sessions[i], true);
            sessions[i].nextBroadcastSeq = nextSeq;
        }
    }
    return dropped;
}

bool LocalPacketPool::trimStalledTargeted(SessionState *sessions, size_t sessionCount, uint32_t nowMs)
{
    bool dropped = false;
    for (size_t i = 0; i < sessionCount; ++i) {
        SessionState &session = sessions[i];
        if (!session.deliveryActive || healthFor(session, nowMs) != DeliveryHealth::STALLED) {
            continue;
        }
        while (session.pendingDirect > LOCAL_STALLED_MAX_DIRECT) {
            dropped |= dropOldestTargeted(session, PacketKind::DIRECT, true);
        }
        while (session.pendingService > LOCAL_STALLED_MAX_SERVICE) {
            dropped |= dropOldestTargeted(session, PacketKind::SERVICE, true);
        }
        if (LOCAL_STALLED_BROADCAST_BACKLOG == 0) {
            // A stalled session configured with no backlog allowance should not
            // keep old broadcast entries alive under pressure.
            session.nextBroadcastSeq = nextSeq;
        }
    }
    return dropped;
}

bool LocalPacketPool::dropOldestDirectFromMostBacklogged(SessionState *sessions, size_t sessionCount)
{
    SessionState *victim = nullptr;
    uint8_t largestDirectCount = 0;
    for (size_t i = 0; i < sessionCount; ++i) {
        if (sessions[i].deliveryActive && sessions[i].pendingDirect > largestDirectCount) {
            victim = &sessions[i];
            largestDirectCount = sessions[i].pendingDirect;
        }
    }
    return victim && dropOldestTargeted(*victim, PacketKind::DIRECT, true);
}

bool LocalPacketPool::dropOldestBroadcast(bool countDrop)
{
    if (broadcastHead == INVALID_INDEX) {
        return false;
    }
    releaseBroadcastHead(countDrop);
    return true;
}

void LocalPacketPool::releaseTargetedSlot(uint8_t slotIndex, PacketKind kind)
{
    if (slotIndex >= LOCAL_PACKET_POOL_SIZE) {
        return;
    }
    releaseFreeSlot(slotIndex);
    if (usedTotal > 0) {
        usedTotal--;
    }
    if (kind == PacketKind::SERVICE) {
        if (usedService > 0) {
            usedService--;
        }
    } else if (kind == PacketKind::DIRECT && usedDirect > 0) {
        usedDirect--;
    }
}

void LocalPacketPool::releaseBroadcastHead(bool countDrop)
{
    if (broadcastHead == INVALID_INDEX) {
        return;
    }

    const uint8_t slotIndex = broadcastHead;
    broadcastHead = entries[slotIndex].next;
    if (broadcastHead == INVALID_INDEX) {
        broadcastTail = INVALID_INDEX;
    }

    releaseFreeSlot(slotIndex);
    if (usedTotal > 0) {
        usedTotal--;
    }
    if (usedBroadcast > 0) {
        usedBroadcast--;
    }
    if (countDrop) {
        droppedBroadcast++;
    }
}

void LocalPacketPool::releaseFreeSlot(uint8_t slotIndex)
{
    entries[slotIndex] = LocalPacketEntry{};
}

} // namespace SharedNode
#endif
