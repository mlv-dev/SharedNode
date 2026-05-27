#ifdef MODE_SHARED_NODE
#pragma once

/**
 * @file SharedNodeTypes.h
 * @brief Shared-node role, peer identity, and persisted client record types.
 */

#include <Arduino.h>
#include <cstring>

/**
 * @brief Default total number of SharedNode client connections.
 *
 * This includes the physical admin connection plus every guest connection.
 */
#ifndef SHARED_NODE_MAX_CLIENTS
#define SHARED_NODE_MAX_CLIENTS 5
#endif

/**
 * @brief Default number of packet slots in the guest local-delivery pool.
 */
#ifndef SHARED_NODE_LOCAL_PACKET_POOL_SIZE
#define SHARED_NODE_LOCAL_PACKET_POOL_SIZE 32
#endif

/**
 * @brief Default minimum number of packet slots reserved for broadcast backlog.
 */
#ifndef SHARED_NODE_LOCAL_BROADCAST_RESERVED
#define SHARED_NODE_LOCAL_BROADCAST_RESERVED 8
#endif

/**
 * @brief Default idle time in milliseconds before a guest is considered stalled.
 */
#ifndef SHARED_NODE_LOCAL_STALLED_MS
#define SHARED_NODE_LOCAL_STALLED_MS 30000
#endif

/**
 * @brief Default idle time in milliseconds before a guest is considered dead.
 */
#ifndef SHARED_NODE_LOCAL_DEAD_MS
#define SHARED_NODE_LOCAL_DEAD_MS 600000
#endif

/**
 * @brief Default per-session SERVICE packet cap for an active guest.
 */
#ifndef SHARED_NODE_LOCAL_ACTIVE_MAX_SERVICE
#define SHARED_NODE_LOCAL_ACTIVE_MAX_SERVICE 4
#endif

/**
 * @brief Default per-session DIRECT packet cap for an active guest.
 */
#ifndef SHARED_NODE_LOCAL_ACTIVE_MAX_DIRECT
#define SHARED_NODE_LOCAL_ACTIVE_MAX_DIRECT 8
#endif

/**
 * @brief Default per-session SERVICE packet cap for a stalled guest.
 */
#ifndef SHARED_NODE_LOCAL_STALLED_MAX_SERVICE
#define SHARED_NODE_LOCAL_STALLED_MAX_SERVICE 1
#endif

/**
 * @brief Default per-session DIRECT packet cap for a stalled guest.
 */
#ifndef SHARED_NODE_LOCAL_STALLED_MAX_DIRECT
#define SHARED_NODE_LOCAL_STALLED_MAX_DIRECT 1
#endif

/**
 * @brief Default broadcast backlog, in packet slots, preserved for stalled guests.
 */
#ifndef SHARED_NODE_LOCAL_STALLED_BROADCAST_BACKLOG
#define SHARED_NODE_LOCAL_STALLED_BROADCAST_BACKLOG 0
#endif

/**
 * @brief Shared-node namespace for small value types and helpers.
 */
namespace SharedNode
{

/**
 * @brief Maximum number of shared-node client connections.
 *
 * The value includes the admin slot plus all guest slots. It is limited to 32
 * because LocalPacketPool metadata stores the target session index in 5 bits.
 */
static constexpr size_t MAX_CLIENTS = SHARED_NODE_MAX_CLIENTS;

/**
 * @brief Maximum number of guest clients allowed in shared-node mode.
 */
static constexpr size_t MAX_GUESTS = SHARED_NODE_MAX_CLIENTS - 1;

/**
 * @brief Maximum number of packet slots in the shared guest local-delivery pool.
 *
 * Unit: packet slots. Each slot stores one meshtastic_MeshPacket plus compact
 * pool metadata.
 */
static constexpr size_t LOCAL_PACKET_POOL_SIZE = SHARED_NODE_LOCAL_PACKET_POOL_SIZE;

/**
 * @brief Packet slots reserved as the minimum guest broadcast backlog.
 *
 * Unit: packet slots. Targeted traffic may not consume free slots needed to
 * let broadcast usage return to this floor.
 */
static constexpr size_t LOCAL_BROADCAST_RESERVED = SHARED_NODE_LOCAL_BROADCAST_RESERVED;

/**
 * @brief Idle interval after which a connected guest is treated as stalled.
 *
 * Unit: milliseconds since the guest last polled local delivery.
 */
static constexpr uint32_t LOCAL_STALLED_MS = SHARED_NODE_LOCAL_STALLED_MS;

/**
 * @brief Idle interval after which a connected guest is treated as dead.
 *
 * Unit: milliseconds since the guest last polled local delivery.
 */
static constexpr uint32_t LOCAL_DEAD_MS = SHARED_NODE_LOCAL_DEAD_MS;

/**
 * @brief Maximum service/control packets retained for an active guest.
 *
 * Unit: per-session packet count.
 */
static constexpr size_t LOCAL_ACTIVE_MAX_SERVICE = SHARED_NODE_LOCAL_ACTIVE_MAX_SERVICE;

/**
 * @brief Maximum direct packets retained for an active guest.
 *
 * Unit: per-session packet count.
 */
static constexpr size_t LOCAL_ACTIVE_MAX_DIRECT = SHARED_NODE_LOCAL_ACTIVE_MAX_DIRECT;

/**
 * @brief Maximum service/control packets retained for a stalled guest.
 *
 * Unit: per-session packet count.
 */
static constexpr size_t LOCAL_STALLED_MAX_SERVICE = SHARED_NODE_LOCAL_STALLED_MAX_SERVICE;

/**
 * @brief Maximum direct packets retained for a stalled guest.
 *
 * Unit: per-session packet count.
 */
static constexpr size_t LOCAL_STALLED_MAX_DIRECT = SHARED_NODE_LOCAL_STALLED_MAX_DIRECT;

/**
 * @brief Broadcast packets a stalled guest may keep behind its cursor.
 *
 * Unit: packet slots. Zero means stalled guests do not retain broadcast backlog
 * during pressure reclaim.
 */
static constexpr size_t LOCAL_STALLED_BROADCAST_BACKLOG = SHARED_NODE_LOCAL_STALLED_BROADCAST_BACKLOG;

// The packed LocalPacketEntry metadata allocates five bits for the target
// session index, so the local delivery table cannot grow beyond 32 entries.
static_assert(MAX_CLIENTS <= 32, "SharedNode local packet metadata supports at most 32 total clients");
static_assert(LOCAL_PACKET_POOL_SIZE > 0, "SharedNode local packet pool must contain at least one slot");
static_assert(LOCAL_PACKET_POOL_SIZE <= 255, "SharedNode local packet pool uses uint8_t indexes with 0xff as invalid");
static_assert(LOCAL_BROADCAST_RESERVED <= LOCAL_PACKET_POOL_SIZE,
              "SharedNode broadcast reserve cannot exceed the local packet pool size");
static_assert(LOCAL_ACTIVE_MAX_SERVICE <= 255 && LOCAL_ACTIVE_MAX_DIRECT <= 255 &&
                  LOCAL_STALLED_MAX_SERVICE <= 255 && LOCAL_STALLED_MAX_DIRECT <= 255,
              "SharedNode local packet per-session caps must fit in uint8_t counters");

/**
 * @brief Slot index reserved for the admin client.
 */
static constexpr uint8_t ADMIN_SLOT = 0;

/**
 * @brief Sentinel slot value used when no shared-node slot is assigned.
 */
static constexpr uint8_t INVALID_SLOT = 0xff;

/**
 * @brief Peer identity buffer size, including the null terminator.
 */
static constexpr size_t PEER_IDENTITY_SIZE = 32;

/**
 * @brief Generated short-name buffer size, including the null terminator.
 */
static constexpr size_t SHORT_NAME_SIZE = 5;

/**
 * @brief Generated long-name buffer size, including the null terminator.
 */
static constexpr size_t LONG_NAME_SIZE = 40;

/**
 * @brief Curve25519 public/private key size for persisted virtual client identities.
 */
static constexpr size_t PKI_KEY_SIZE = 32;

/**
 * @brief Shared-node connection role.
 *
 * This is a mesh/session concept, not a Bluetooth concept. BLE backends use it
 * only to bind an authenticated transport connection to a PhoneAPI session.
 */
enum class Role : uint8_t {
    /**
     * @brief Role has not been resolved or is not known.
     */
    UNKNOWN = 0,

    /**
     * @brief Admin session with permission to manage shared-node state.
     */
    ADMIN = 1,

    /**
     * @brief Guest session that receives a virtual node identity.
     */
    GUEST = 2,
};

/**
 * @brief Returns the shared-node role implied by a slot index.
 *
 * Slot 0 is the admin identity. Every valid non-zero slot is a guest identity.
 * INVALID_SLOT and out-of-range slot values do not imply a role.
 *
 * @param slotIndex Shared-node client slot.
 * @return Role implied by the slot, or UNKNOWN for invalid slot values.
 */
inline Role roleForSlot(uint8_t slotIndex)
{
    if (slotIndex == INVALID_SLOT || slotIndex >= MAX_CLIENTS) {
        return Role::UNKNOWN;
    }
    return slotIndex == ADMIN_SLOT ? Role::ADMIN : Role::GUEST;
}

/**
 * @brief Lifecycle/connection state for one shared-node slot.
 *
 * Allocation intentionally only considers states 0 and 1. States 2 and 3 keep
 * ownership for a known phone: 2 may reconnect later, and 3 is currently live.
 */
enum class ConnectionState : uint8_t {
    /**
     * @brief Slot has never been assigned to a peer.
     */
    EMPTY = 0,

    /**
     * @brief Peer explicitly sent ToRadio.disconnect and released the slot.
     *
     * The BLE bond identity is still retained so the same OS-level paired
     * device can reconnect without becoming a new guest. This state is also
     * allocatable when no EMPTY slots remain.
     */
    DISCONNECTED = 1,

    /**
     * @brief Peer owns this slot, but the BLE link is not active right now.
     */
    NOT_ACTIVE = 2,

    /**
     * @brief Peer owns this slot and currently has a live BLE connection.
     */
    ACTIVE = 3,
};

/**
 * @brief Checks whether a connection state retains a peer identity.
 *
 * DISCONNECTED still retains identity because ToRadio.disconnect is an
 * application-level disconnect, not an OS-level bond removal.
 */
inline bool connectionStateRetainsIdentity(ConnectionState state)
{
    return state == ConnectionState::DISCONNECTED || state == ConnectionState::NOT_ACTIVE || state == ConnectionState::ACTIVE;
}

/**
 * @brief Checks whether a new peer may be assigned to a slot in this state.
 */
inline bool connectionStateCanAllocate(ConnectionState state)
{
    return state == ConnectionState::EMPTY || state == ConnectionState::DISCONNECTED;
}

/**
 * @brief Decodes a persisted connection state value.
 */
inline ConnectionState connectionStateFromValue(uint32_t value)
{
    switch (static_cast<ConnectionState>(value)) {
    case ConnectionState::EMPTY:
    case ConnectionState::DISCONNECTED:
    case ConnectionState::NOT_ACTIVE:
    case ConnectionState::ACTIVE:
        return static_cast<ConnectionState>(value);
    default:
        return ConnectionState::EMPTY;
    }
}

/**
 * @brief Null-terminated stack-provided bond identity wrapper.
 *
 * Bluetooth backends format platform-specific identity information from their
 * bonding layer into this fixed buffer before the pairing policy compares or
 * persists it. The value should come from the peer identity address, IRK-backed
 * bond record, or equivalent stack peer ID, not from the current over-the-air
 * BLE address.
 */
struct PeerIdentity {
    /**
     * @brief Null-terminated identity storage.
     */
    char value[PEER_IDENTITY_SIZE] = {};

    /**
     * @brief Clears the stored identity.
     */
    void clear() { value[0] = '\0'; }

    /**
     * @brief Checks whether the stored identity is present.
     *
     * This lets callers write `if (identity)` for the "has identity" case.
     *
     * @return true when an identity string is stored.
     */
    explicit operator bool() const { return !operator!(); }

    /**
     * @brief Checks whether the stored identity is empty.
     *
     * This lets callers write `if (!identity)` for the "no identity" case.
     *
     * @return true when no identity is stored.
     */
    bool operator!() const { return value[0] == '\0'; }

    /**
     * @brief Checks whether this value was produced by a bond identity formatter.
     *
     * Backends prefix identities so records from different BLE stacks cannot
     * collide accidentally.
     *
     * @return true when the value uses a stable identity prefix.
     */
    bool stable() const
    {
        return strncmp(value, "bf:", 3) == 0 || strncmp(value, "nb:", 3) == 0;
    }

    /**
     * @brief Returns the stored identity as a C string.
     *
     * @return Null-terminated identity string.
     */
    const char *c_str() const { return value; }

    /**
     * @brief Assigns a peer identity string to this wrapper.
     *
     * A null input clears the identity. Non-null input is truncated to fit the
     * fixed-size buffer and is always null-terminated.
     *
     * @param identity Source identity string, or nullptr to clear.
     */
    PeerIdentity &operator=(const char *identity)
    {
        if (!identity) {
            clear();
            return *this;
        }

        strncpy(value, identity, sizeof(value) - 1);
        value[sizeof(value) - 1] = '\0';
        return *this;
    }

    /**
     * @brief Compares this identity with another PeerIdentity.
     *
     * @param other Identity wrapper to compare with.
     * @return true when both identities are non-empty and equal.
     */
    bool operator==(const PeerIdentity &other) const { return *this == other.c_str(); }

    /**
     * @brief Compares this identity with another PeerIdentity for inequality.
     *
     * @param other Identity wrapper to compare with.
     * @return true when operator== returns false.
     */
    bool operator!=(const PeerIdentity &other) const { return !(*this == other); }

    /**
     * @brief Compares this identity with a C string.
     *
     * Empty identities never compare equal.
     *
     * @param other Identity string to compare with.
     * @return true when both identities are non-empty and equal.
     */
    bool operator==(const char *other) const
    {
        return *this && other && strncmp(value, other, sizeof(value)) == 0;
    }

    /**
     * @brief Compares this identity with a C string for inequality.
     *
     * @param other Identity string to compare with.
     * @return true when operator== returns false.
     */
    bool operator!=(const char *other) const { return !(*this == other); }
};

/**
 * @brief Persisted pairing and runtime state for one shared-node client slot.
 */
struct ClientRecord {
    /**
     * @brief Slot lifecycle state used for allocation and reconnect handling.
     */
    ConnectionState connectionState = ConnectionState::EMPTY;

    /**
     * @brief Active transport connection handle, or 0 when disconnected.
     */
    uint16_t connHandle = 0;

    /**
     * @brief Virtual node ID assigned to a virtual client.
     */
    uint32_t virtualNodeId = 0;

    /**
     * @brief Stable bond identity used to match reconnecting clients.
     */
    PeerIdentity peerIdentity = {};

    /**
     * @brief Generated short node name for the virtual identity.
     */
    char shortName[SHORT_NAME_SIZE] = {};

    /**
     * @brief Generated long node name for the virtual identity.
     */
    char longName[LONG_NAME_SIZE] = {};

    /**
     * @brief Virtual client identity public key.
     */
    uint8_t publicKey[PKI_KEY_SIZE] = {};

    /**
     * @brief Virtual client identity private key.
     */
    uint8_t privateKey[PKI_KEY_SIZE] = {};

    /**
     * @brief Seconds-since-boot timestamp when this identity was registered.
     */
    uint32_t registerTime = 0;

    /**
     * @brief Seconds-since-boot timestamp when this identity was last seen.
     */
    uint32_t lastSeen = 0;

    /**
     * @brief Checks whether this slot is available for a newly paired peer.
     */
    bool canAllocate() const { return connectionStateCanAllocate(connectionState); }

    /**
     * @brief Checks whether this slot currently owns a durable peer identity.
     */
    bool hasIdentity() const
    {
        return connectionStateRetainsIdentity(connectionState) && peerIdentity;
    }

    /**
     * @brief Checks whether this slot has a live transport connection.
     */
    bool isActive() const { return connectionState == ConnectionState::ACTIVE; }
};

} // namespace SharedNode
#endif
