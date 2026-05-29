#ifdef MODE_SHARED_NODE
#include "AdminPolicy.h"

#include "configuration.h"
#include "mesh/NodeDB.h"
#include "mesh/sharedNode/PairingPolicy.h"
#include "mesh/sharedNode/VirtualNodeManager.h"

namespace SharedNode::AdminPolicy
{

Context contextForPacket(const meshtastic_MeshPacket &packet)
{
    Context context;
    if (packet.transport_mechanism != meshtastic_MeshPacket_TransportMechanism_TRANSPORT_API || packet.from == 0 || !nodeDB) {
        return context;
    }

    const NodeNum localNodeNum = nodeDB->getNodeNum();
    if (packet.from == localNodeNum) {
        return context;
    }

    // MeshService rewrites allowed guest admin packets to target the physical
    // node, while packet.from remains the virtual identity used for scoping.
    const uint8_t slot = virtualNodeManager.sharedNodeSlotForVirtualNode(packet.from);
    if (slot == INVALID_SLOT) {
        return context;
    }

    context.isLocalVirtual = true;
    context.role = roleForSlot(slot);
    context.virtualNodeId = packet.from;
    return context;
}

bool isMessageAllowed(const Context &context, const meshtastic_AdminMessage *request)
{
    if (!context.isLocalVirtual) {
        return true;
    }

    if (context.role == Role::ADMIN) {
        return true;
    }

    if (context.role != Role::GUEST || !request) {
        return false;
    }

    // Guests may manage only their own profile and virtual key material. All
    // physical-node settings stay reserved for the shared-node admin.
    switch (request->which_payload_variant) {
    case meshtastic_AdminMessage_get_owner_request_tag:
    case meshtastic_AdminMessage_set_owner_tag:
        return true;
    case meshtastic_AdminMessage_get_config_request_tag:
        return request->get_config_request == meshtastic_AdminMessage_ConfigType_SECURITY_CONFIG;
    case meshtastic_AdminMessage_set_config_tag:
        return request->set_config.which_payload_variant == meshtastic_Config_security_tag;
    default:
        return false;
    }
}

bool buildOwner(NodeNum virtualNodeId, meshtastic_User &owner)
{
    return pairingPolicy.buildVirtualUser(virtualNodeId, owner);
}

bool buildSecurityConfig(const Context &context, meshtastic_Config_SecurityConfig &security)
{
    return pairingPolicy.buildVirtualSecurityConfig(context.virtualNodeId, security, context.role == Role::ADMIN);
}

bool updateOwner(NodeNum virtualNodeId, const meshtastic_User &owner)
{
    return pairingPolicy.updateVirtualClientNames(virtualNodeId, owner.short_name, owner.long_name);
}

bool applySecurityConfig(const Context &context, const meshtastic_Config &configPayload, bool &requiresReboot,
                         bool &managedModeCleared)
{
    requiresReboot = false;
    managedModeCleared = false;
    if (!context.isLocalVirtual || configPayload.which_payload_variant != meshtastic_Config_security_tag) {
        return false;
    }

    const meshtastic_Config_SecurityConfig &requestedSecurity = configPayload.payload_variant.security;
    if (context.role == Role::GUEST) {
        // Guests cannot import arbitrary admin/security state; an app request
        // to set security becomes a scoped regeneration of their own keys.
        return pairingPolicy.regenerateVirtualClientKeys(context.virtualNodeId);
    }

    if (context.role != Role::ADMIN) {
        return false;
    }

    if (!pairingPolicy.updateVirtualClientKeys(context.virtualNodeId, requestedSecurity)) {
        return false;
    }

    const auto physicalPublicKey = config.security.public_key;
    const auto physicalPrivateKey = config.security.private_key;
    requiresReboot = config.security.debug_log_api_enabled != requestedSecurity.debug_log_api_enabled ||
                     config.security.serial_enabled != requestedSecurity.serial_enabled;

    config.security = requestedSecurity;
    config.security.public_key = physicalPublicKey;
    config.security.private_key = physicalPrivateKey;

    if (config.security.is_managed && !(config.security.admin_key[0].size == 32 || config.security.admin_key[1].size == 32 ||
                                        config.security.admin_key[2].size == 32)) {
        config.security.is_managed = false;
        managedModeCleared = true;
    }
    return true;
}

const char *failureMessage(FailureReason reason)
{
    switch (reason) {
    case FailureReason::ADMIN_ONLY:
        return "Only the shared node admin can change this setting.";
    case FailureReason::PROFILE_UNAVAILABLE:
        return "Could not update your shared-node profile. Ask the admin to reconnect you.";
    case FailureReason::IDENTITY_UNAVAILABLE:
        return "Could not prepare your shared-node identity. Ask the admin to reconnect you.";
    case FailureReason::NONE:
    default:
        return nullptr;
    }
}

} // namespace SharedNode::AdminPolicy
#endif
