#pragma once
#ifdef ESP_PLATFORM
#include <esp_ota_ops.h>
#endif
#include "ProtobufModule.h"
#ifdef MODE_SHARED_NODE
#include "mesh/sharedNode/Types.h"
#endif
#include <sys/types.h>
#if HAS_WIFI
#include "mesh/wifi/WiFiAPClient.h"
#endif

/**
 * Datatype passed to Observers by AdminModule, to allow external handling of admin messages
 */
struct AdminModule_ObserverData {
    const meshtastic_AdminMessage *request;
    meshtastic_AdminMessage *response;
    AdminMessageHandleResult *result;
};

/**
 * Admin module for admin messages
 */
class AdminModule : public ProtobufModule<meshtastic_AdminMessage>, public Observable<AdminModule_ObserverData *>
{
  public:
    /** Constructor
     * name is for debugging output
     */
    AdminModule();

  protected:
    /** Called to handle a particular incoming message

    @return true if you've guaranteed you've handled this message and no other handlers should be considered for it
    */
    virtual bool handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_AdminMessage *p) override;

  private:
#ifdef MODE_SHARED_NODE
    /**
     * @brief Describes an AdminMessage that was rewritten from a local SharedNode virtual client.
     */
    struct SharedNodeAdminContext {
        /**
         * @brief true when the packet came from an active local virtual node over the API transport.
         */
        bool isLocalVirtual = false;

        /**
         * @brief SharedNode role associated with the virtual node slot.
         */
        SharedNode::Role role = SharedNode::Role::UNKNOWN;

        /**
         * @brief Virtual node ID used as the packet source.
         */
        NodeNum virtualNodeId = 0;
    };
#endif

    bool hasOpenEditTransaction = false;

    uint8_t session_passkey[8] = {0};
    uint session_time = 0;

    void saveChanges(int saveWhat, bool shouldReboot = true);

    /**
     * Getters
     */
    void handleGetModuleConfigResponse(const meshtastic_MeshPacket &req, meshtastic_AdminMessage *p);
    void handleGetOwner(const meshtastic_MeshPacket &req);
    void handleGetConfig(const meshtastic_MeshPacket &req, uint32_t configType);
    void handleGetModuleConfig(const meshtastic_MeshPacket &req, uint32_t configType);
    void handleGetChannel(const meshtastic_MeshPacket &req, uint32_t channelIndex);
    void handleGetDeviceMetadata(const meshtastic_MeshPacket &req);
    void handleGetDeviceConnectionStatus(const meshtastic_MeshPacket &req);
    void handleGetNodeRemoteHardwarePins(const meshtastic_MeshPacket &req);
    void handleGetDeviceUIConfig(const meshtastic_MeshPacket &req);
#ifdef MODE_SHARED_NODE
    /**
     * @brief Sends the persisted virtual owner profile for a local SharedNode client.
     *
     * @param req Original admin request packet.
     * @param virtualNodeId Local virtual node ID whose owner profile should be returned.
     */
    void handleGetVirtualOwner(const meshtastic_MeshPacket &req, NodeNum virtualNodeId);

    /**
     * @brief Sends the virtual security config for a local SharedNode client.
     *
     * @param req Original admin request packet.
     * @param virtualNodeId Local virtual node ID whose security config should be returned.
     * @param includeAdminKeys true when admin keys may be included in the response.
     */
    void handleGetVirtualSecurityConfig(const meshtastic_MeshPacket &req, NodeNum virtualNodeId, bool includeAdminKeys);
#endif
    /**
     * Setters
     */
    void handleSetOwner(const meshtastic_User &o);
    void handleSetChannel(const meshtastic_Channel &cc);

  protected:
    void handleSetConfig(const meshtastic_Config &c, bool fromOthers);

  private:
    bool handleSetModuleConfig(const meshtastic_ModuleConfig &c);
    void handleSetChannel();
    void handleSetHamMode(const meshtastic_HamParameters &req);
    void handleStoreDeviceUIConfig(const meshtastic_DeviceUIConfig &uicfg);
    void handleSendInputEvent(const meshtastic_AdminMessage_InputEvent &inputEvent);
    void reboot(int32_t seconds);

#ifdef MODE_SHARED_NODE
    /**
     * @brief Builds SharedNode admin context from a rewritten local virtual packet.
     *
     * @param mp Incoming mesh packet to inspect.
     * @return Context describing the local virtual source, or defaults when not applicable.
     */
    SharedNodeAdminContext getSharedNodeAdminContext(const meshtastic_MeshPacket &mp) const;

    /**
     * @brief Checks whether a local virtual client may execute an admin payload.
     *
     * @param context SharedNode context for the packet source.
     * @param request Decoded admin request to authorize.
     * @return true when the payload is allowed for the virtual client role.
     */
    bool sharedNodeAdminMessageAllowed(const SharedNodeAdminContext &context, const meshtastic_AdminMessage *request) const;

    /**
     * @brief Applies an owner/profile update to a local virtual client identity.
     *
     * @param virtualNodeId Local virtual node ID to update.
     * @param owner Requested owner data.
     * @return true when the virtual identity was found and updated.
     */
    bool handleSetVirtualOwner(NodeNum virtualNodeId, const meshtastic_User &owner);

    /**
     * @brief Applies a scoped security update for a local virtual client.
     *
     * Guests can regenerate only their own virtual keys. Admin-scoped virtual
     * clients may also update shared security fields while preserving the
     * physical node keypair.
     *
     * @param context SharedNode context for the local virtual source.
     * @param config Requested config payload.
     * @return true when the scoped update was accepted and persisted.
     */
    bool handleSetVirtualSecurityConfig(const SharedNodeAdminContext &context, const meshtastic_Config &config);
#endif

    void setPassKey(meshtastic_AdminMessage *res);
    bool checkPassKey(meshtastic_AdminMessage *res);

    bool messageIsResponse(const meshtastic_AdminMessage *r);
    bool messageIsRequest(const meshtastic_AdminMessage *r);
    void sendWarning(const char *format, ...) __attribute__((format(printf, 2, 3)));
    void sendWarningAndLog(const char *format, ...) __attribute__((format(printf, 2, 3)));
};

static constexpr const char *licensedModeMessage =
    "Licensed mode activated, removing admin channel and encryption from all channels";

extern AdminModule *adminModule;

void disableBluetooth();
