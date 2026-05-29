#ifdef MODE_SHARED_NODE
#pragma once

/**
 * @file AdminPolicy.h
 * @brief SharedNode-scoped AdminMessage policy helpers.
 */

#include "Types.h"
#include "MeshTypes.h"
#include "mesh/generated/meshtastic/admin.pb.h"
#include "mesh/generated/meshtastic/config.pb.h"
#include "mesh/generated/meshtastic/mesh.pb.h"

namespace SharedNode::AdminPolicy
{

/**
 * @brief Describes an AdminMessage rewritten from a local SharedNode virtual client.
 */
struct Context {
    /**
     * @brief true when the packet came from an active local virtual node over the API transport.
     */
    bool isLocalVirtual = false;

    /**
     * @brief SharedNode role associated with the virtual node slot.
     */
    Role role = Role::UNKNOWN;

    /**
     * @brief Virtual node ID used as the packet source.
     */
    NodeNum virtualNodeId = 0;
};

/**
 * @brief User-facing reason for a scoped admin operation failure.
 */
enum class FailureReason : uint8_t {
    NONE = 0,
    ADMIN_ONLY = 1,
    PROFILE_UNAVAILABLE = 2,
    IDENTITY_UNAVAILABLE = 3,
};

/**
 * @brief Builds SharedNode admin context from a rewritten local virtual packet.
 *
 * @param packet Incoming mesh packet to inspect.
 * @return Context describing the local virtual source, or defaults when not applicable.
 */
Context contextForPacket(const meshtastic_MeshPacket &packet);

/**
 * @brief Checks whether a local virtual client may execute an admin payload.
 *
 * @param context SharedNode context for the packet source.
 * @param request Decoded admin request to authorize.
 * @return true when the payload is allowed for the virtual client role.
 */
bool isMessageAllowed(const Context &context, const meshtastic_AdminMessage *request);

/**
 * @brief Builds the persisted virtual owner profile for a local SharedNode client.
 *
 * @param virtualNodeId Local virtual node ID whose owner profile should be returned.
 * @param owner Destination owner protobuf.
 * @return true when the virtual identity exists.
 */
bool buildOwner(NodeNum virtualNodeId, meshtastic_User &owner);

/**
 * @brief Builds the scoped security config for a local SharedNode client.
 *
 * @param context SharedNode context for the virtual source.
 * @param security Destination security config.
 * @return true when the virtual identity exists.
 */
bool buildSecurityConfig(const Context &context, meshtastic_Config_SecurityConfig &security);

/**
 * @brief Applies an owner/profile update to a local virtual client identity.
 *
 * @param virtualNodeId Local virtual node ID to update.
 * @param owner Requested owner data.
 * @return true when the virtual identity was found and updated.
 */
bool updateOwner(NodeNum virtualNodeId, const meshtastic_User &owner);

/**
 * @brief Applies a scoped security update for a local virtual client.
 *
 * Guests can regenerate only their own virtual keys. Admin-scoped virtual
 * clients may also update shared security fields while preserving the physical
 * node keypair.
 *
 * @param context SharedNode context for the local virtual source.
 * @param configPayload Requested config payload.
 * @param requiresReboot Output set when the shared security change requires reboot.
 * @param managedModeCleared Output set when invalid managed mode was disabled.
 * @return true when the scoped update was accepted and applied.
 */
bool applySecurityConfig(const Context &context, const meshtastic_Config &configPayload, bool &requiresReboot,
                         bool &managedModeCleared);

/**
 * @brief Maps a SharedNode admin failure reason to a user-facing message.
 *
 * @param reason Failure reason.
 * @return Message text, or nullptr when no notification is needed.
 */
const char *failureMessage(FailureReason reason);

} // namespace SharedNode::AdminPolicy
#endif
