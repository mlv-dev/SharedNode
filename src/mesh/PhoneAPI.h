#pragma once

#include "Observer.h"
#include "concurrency/Lock.h"
#ifdef MODE_SHARED_NODE
#include "mesh/sharedNode/Types.h"
#endif
#include "mesh-pb-constants.h"
#include "meshtastic/portnums.pb.h"
#include <deque>
#include <iterator>
#include <string>
#include <unordered_map>
#include <vector>

// Make sure that we never let our packets grow too large for one BLE packet
#define MAX_TO_FROM_RADIO_SIZE 512

#if meshtastic_FromRadio_size > MAX_TO_FROM_RADIO_SIZE
#error "meshtastic_FromRadio_size is too large for our BLE packets"
#endif
#if meshtastic_ToRadio_size > MAX_TO_FROM_RADIO_SIZE
#error "meshtastic_ToRadio_size is too large for our BLE packets"
#endif

#define SPECIAL_NONCE_ONLY_CONFIG 69420
#define SPECIAL_NONCE_ONLY_NODES 69421 // ( ͡° ͜ʖ ͡°)

/**
 * Provides our protobuf based API which phone/PC clients can use to talk to our device
 * over UDP, bluetooth or serial.
 *
 * Subclass to customize behavior for particular type of transport (BLE, UDP, TCP, serial)
 *
 * Eventually there should be once instance of this class for each live connection (because it has a bit of state
 * for that connection)
 */
class PhoneAPI
    : public Observer<uint32_t> // FIXME, we shouldn't be inheriting from Observer, instead use CallbackObserver as a member
{
    enum State {
        STATE_SEND_NOTHING, // Initial state, don't send anything until the client starts asking for config
        STATE_SEND_UIDATA,  // send stored data for device-ui
        STATE_SEND_MY_INFO, // send our my info record
        STATE_SEND_OWN_NODEINFO,
        STATE_SEND_METADATA,
        STATE_SEND_CHANNELS,        // Send all channels
        STATE_SEND_CONFIG,          // Replacement for the old Radioconfig
        STATE_SEND_MODULECONFIG,    // Send Module specific config
        STATE_SEND_OTHER_NODEINFOS, // states progress in this order as the device sends to to the client
        STATE_SEND_FILEMANIFEST,    // Send file manifest
        STATE_SEND_COMPLETE_ID,
        STATE_SEND_PACKETS // send packets or debug strings
    };

    State state = STATE_SEND_NOTHING;

    uint8_t config_state = 0;

    // Hashmap of timestamps for last time we received a packet on the API per portnum
    std::unordered_map<meshtastic_PortNum, uint32_t> lastPortNumToRadio;
    uint32_t recentToRadioPacketIds[20]; // Last 20 ToRadio MeshPacket IDs we have seen

    /**
     * Each packet sent to the phone has an incrementing count
     */
    uint32_t fromRadioNum = 0;

    /// We temporarily keep the packet here between the call to available and getFromRadio.  We will free it after the phone
    /// downloads it
    meshtastic_MeshPacket *packetForPhone = NULL;

#ifdef MODE_SHARED_NODE
    /// Per-connection virtual packet routed by VirtualNodeManager (not allocated from packetPool).
    bool hasVirtualPacketForPhone = false;
    meshtastic_MeshPacket virtualPacketForPhone = meshtastic_MeshPacket_init_zero;
#endif

    // file transfer packets destined for phone. Push it to the queue then free it.
    meshtastic_XModem xmodemPacketForPhone = meshtastic_XModem_init_zero;

    // Keep QueueStatus packet just as packetForPhone
    meshtastic_QueueStatus *queueStatusPacketForPhone = NULL;

    // Keep MqttClientProxyMessage packet just as packetForPhone
    meshtastic_MqttClientProxyMessage *mqttClientProxyMessageForPhone = NULL;

    // Local notifications are per PhoneAPI instance so SharedNode guests can
    // receive permission/limit errors without reading the global phone queue.
    meshtastic_ClientNotification *clientNotification = NULL;
    bool closeAfterClientNotification = false;
    bool closeAfterFromRadioRead = false;

    /// We temporarily keep the nodeInfo here between the call to available and getFromRadio
    meshtastic_NodeInfo nodeInfoForPhone = meshtastic_NodeInfo_init_default;
    // Prefetched node info entries ready for immediate transmission to the phone.
    std::deque<meshtastic_NodeInfo> nodeInfoQueue;
    // Tunable size of the node info cache so we can keep BLE reads non-blocking.
    static constexpr size_t kNodePrefetchDepth = 4;
    // Protect nodeInfoForPhone + nodeInfoQueue because NimBLE callbacks run in a separate FreeRTOS task.
    concurrency::Lock nodeInfoMutex;

    meshtastic_ToRadio toRadioScratch = {
        0}; // this is a static scratch object, any data must be copied elsewhere before returning

    /// Use to ensure that clients don't get confused about old messages from the radio
    uint32_t config_nonce = 0;
    uint32_t readIndex = 0;

    std::vector<meshtastic_FileInfo> filesManifest = {};

    void resetReadIndex() { readIndex = 0; }

  public:
    PhoneAPI();

    /// Destructor - calls close()
    virtual ~PhoneAPI();

#ifdef MODE_SHARED_NODE
    /**
     * @brief Returns the shared-node role implied by this connection's slot.
     *
     * The BLE transport sets the slot before config starts. INVALID_SLOT maps
     * to Role::UNKNOWN and represents a normal non-shared API connection.
     *
     * @return Role associated with the current shared-node slot.
     */
    SharedNode::Role getConnectionMode() const { return SharedNode::roleForSlot(sharedNodeSlot); }

    /**
     * @brief Assigns the shared-node slot resolved by the transport.
     *
     * @param slot Shared-node slot index, or SharedNode::INVALID_SLOT for a normal connection.
     */
    void setSharedNodeSlot(uint8_t slot) { sharedNodeSlot = slot; }

    /**
     * @brief Returns the shared-node slot assigned to this API connection.
     *
     * @return Shared-node slot index, or SharedNode::INVALID_SLOT when unset.
     */
    uint8_t getSharedNodeSlot() const { return sharedNodeSlot; }

    /**
     * @brief Checks whether this API connection is the shared-node admin.
     *
     * @return true when getConnectionMode() resolves to SharedNode::Role::ADMIN.
     */
    bool isAdmin() const { return getConnectionMode() == SharedNode::Role::ADMIN; }

    /**
     * @brief Checks whether this API connection is a shared-node guest.
     *
     * @return true when getConnectionMode() resolves to SharedNode::Role::GUEST.
     */
    bool isGuest() const { return getConnectionMode() == SharedNode::Role::GUEST; }
#endif

    // Call this when the client drops the connection, resets the state to STATE_SEND_NOTHING
    // Unregisters our observer.  A closed connection **can** be reopened by calling init again.
    virtual void close();

    /**
     * Handle a ToRadio protobuf
     * @return true true if a packet was queued for sending (so that caller can yield)
     */
    virtual bool handleToRadio(const uint8_t *buf, size_t len);

    /**
     * Send a (client)notification to the phone
     *
     * This queues locally on the current PhoneAPI so the exact client that
     * triggered an error receives the message.
     *
     * @param level Client-visible severity level.
     * @param replyId Optional packet/request ID associated with the notification, or 0.
     * @param message Null-terminated user-facing message.
     */
    virtual void sendNotification(meshtastic_LogRecord_Level level, uint32_t replyId, const char *message);

    /**
     * @brief Sends a notification, then asks the transport to close after the client has read it.
     *
     * This is used for rejected SharedNode startup attempts so the app receives
     * one explanatory FromRadio.clientNotification before BLE/API teardown.
     *
     * @param level Client-visible severity level.
     * @param replyId Optional packet/request ID associated with the notification, or 0.
     * @param message Null-terminated user-facing message.
     */
    void sendNotificationAndClose(meshtastic_LogRecord_Level level, uint32_t replyId, const char *message);

    /**
     * @brief Completes any deferred transport close after a FromRadio read.
     *
     * Transports call this after the read response has been handed to the stack,
     * ensuring sendNotificationAndClose() does not disconnect before the client
     * can receive the final notification payload.
     */
    void onFromRadioReadComplete();

    /**
     * Get the next packet we want to send to the phone
     *
     * We assume buf is at least FromRadio_size bytes long.
     * Returns number of bytes in the FromRadio packet (or 0 if no packet available)
     */
    size_t getFromRadio(uint8_t *buf);

    void sendConfigComplete();

    /**
     * Return true if we have data available to send to the phone
     */
    bool available();

    bool isConnected() { return state != STATE_SEND_NOTHING; }
    bool isSendingPackets() { return state == STATE_SEND_PACKETS; }
#ifdef PIO_UNIT_TESTING
    void setSendingPacketsForTest() { state = STATE_SEND_PACKETS; }
#endif

  protected:
    /// Our fromradio packet while it is being assembled
    meshtastic_FromRadio fromRadioScratch = {};

    /** the last msec we heard from the client on the other side of this link */
    uint32_t lastContactMsec = 0;

    /// Hookable to find out when connection changes
    virtual void onConnectionChanged(bool connected) {}

    /// If we haven't heard from the other side in a while then say not connected. Returns true if timeout occurred
    bool checkConnectionTimeout();

    /// Check the current underlying physical link to see if the client is currently connected
    virtual bool checkIsConnected() = 0;

    /**
     * Subclasses can use this as a hook to provide custom notifications for their transport (i.e. bluetooth notifies)
     */
    virtual void onNowHasData(uint32_t fromRadioNum) {}

    /**
     * @brief Transport-specific hook used after a final notification has been delivered.
     *
     * BLE backends override this to disconnect the exact connection that read
     * the final client notification.
     */
    virtual void onCloseAfterNotificationDelivered() {}

    /// Subclasses can use these lifecycle hooks for transport-specific behavior around config/steady-state
    /// (i.e. BLE connection params)
    virtual void onConfigStart() {}
    virtual void onConfigComplete() {}

    /// begin a new connection
    void handleStartConfig();

    enum APIType {
        TYPE_NONE, // Initial state, don't send anything until the client starts asking for config
        TYPE_BLE,
        TYPE_WIFI,
        TYPE_SERIAL,
        TYPE_PACKET,
        TYPE_HTTP,
        TYPE_ETH
    };

    APIType api_type = TYPE_NONE;

#ifdef MODE_SHARED_NODE
    /// INVALID_SLOT means a normal single-user API connection. Other values are
    /// shared-node clients whose role is implied by the slot index.
    uint8_t sharedNodeSlot = SharedNode::INVALID_SLOT;
#endif

  private:
    void releasePhonePacket();

    void releaseQueueStatusPhonePacket();

    void prefetchNodeInfos();

    void releaseMqttClientProxyPhonePacket();

    /**
     * @brief Releases the currently queued local or global client notification.
     */
    void releaseClientNotification();

    /**
     * @brief Queues a local notification for this API connection.
     *
     * @param notification Pool-allocated notification owned by this PhoneAPI after the call.
     * @param closeAfterDelivery true to close the transport after the notification is read.
     */
    void queueClientNotification(meshtastic_ClientNotification *notification, bool closeAfterDelivery);

    bool wasSeenRecently(uint32_t packetId);

    /**
     * Handle a packet that the phone wants us to send.  We can write to it but can not keep a reference to it
     * @return true true if a packet was queued for sending
     */
    bool handleToRadioPacket(meshtastic_MeshPacket &p);

    /// If the mesh service tells us fromNum has changed, tell the phone
    virtual int onNotify(uint32_t newValue) override;
};
