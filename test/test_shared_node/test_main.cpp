#include <unity.h>

#ifndef MODE_SHARED_NODE
void setup()
{
    UNITY_BEGIN();
    TEST_IGNORE_MESSAGE("test_shared_node requires MODE_SHARED_NODE");
    exit(UNITY_END());
}

void loop() {}
#else

#include "CryptoEngine.h"
#include "TestUtil.h"
#include "configuration.h"
#include "mesh/MeshService.h"
#include "mesh/NodeDB.h"
#include "mesh/PhoneAPI.h"
#include "mesh/sharedNode/AdminPolicy.h"
#include "mesh/sharedNode/PairingPolicy.h"
#include "mesh/sharedNode/RecordProto.h"
#include "mesh/sharedNode/VirtualNodeManager.h"

#include <cstring>

class FakeCryptoEngine : public CryptoEngine
{
  public:
    uint8_t generateCount = 0;

    void generateKeyPair(uint8_t *pubKey, uint8_t *privKey) override
    {
        generateCount++;
        for (uint8_t i = 0; i < SharedNode::PKI_KEY_SIZE; i++) {
            pubKey[i] = static_cast<uint8_t>(0x10 + generateCount + i);
            privKey[i] = static_cast<uint8_t>(0x80 + generateCount + i);
        }
    }
};

static FakeCryptoEngine fakeCrypto;
static CryptoEngine *previousCrypto = nullptr;
static MeshService testMeshService;
static MeshService *previousService = nullptr;

static SharedNode::PeerIdentity peerIdentity(const char *value)
{
    SharedNode::PeerIdentity identity;
    identity = value;
    return identity;
}

static bool bytesEqual(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, SharedNode::PKI_KEY_SIZE) == 0;
}

static bool keyMatchesPattern(const uint8_t *key, uint8_t start)
{
    for (uint8_t i = 0; i < SharedNode::PKI_KEY_SIZE; i++) {
        if (key[i] != static_cast<uint8_t>(start + i)) {
            return false;
        }
    }
    return true;
}

static bool adminKeyIsZero(uint8_t index, const meshtastic_Config_SecurityConfig &security)
{
    if (security.admin_key[index].size != 0) {
        return false;
    }
    for (uint8_t i = 0; i < sizeof(security.admin_key[index].bytes); i++) {
        if (security.admin_key[index].bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

static void setAdminKey(uint8_t index, uint8_t start)
{
    if (index >= 3) {
        return;
    }

    if (config.security.admin_key_count < index + 1) {
        config.security.admin_key_count = index + 1;
    }
    config.security.admin_key[index].size = SharedNode::PKI_KEY_SIZE;
    for (uint8_t i = 0; i < SharedNode::PKI_KEY_SIZE; i++) {
        config.security.admin_key[index].bytes[i] = static_cast<uint8_t>(start + i);
    }
}

static void useFakeCrypto()
{
    nodeDB = nullptr;
    previousService = service;
    service = &testMeshService;
    previousCrypto = crypto;
    fakeCrypto.generateCount = 0;
    crypto = &fakeCrypto;
    config.security = meshtastic_Config_SecurityConfig_init_zero;
    SharedNode::pairingPolicy.clearAll();
}

static void restoreCrypto()
{
    crypto = previousCrypto;
    previousCrypto = nullptr;
    service = previousService;
    previousService = nullptr;
}

class TestPhoneAPI : public PhoneAPI
{
  public:
    bool notified = false;
    bool closeAfterNotification = false;

  protected:
    bool checkIsConnected() override { return true; }

    void onNowHasData(uint32_t) override { notified = true; }

    void onCloseAfterNotificationDelivered() override { closeAfterNotification = true; }
};

static bool readClientNotification(TestPhoneAPI &api, meshtastic_ClientNotification &notification)
{
    uint8_t buffer[meshtastic_FromRadio_size] = {};
    const size_t length = api.getFromRadio(buffer);
    if (length == 0) {
        return false;
    }

    meshtastic_FromRadio fromRadio = meshtastic_FromRadio_init_zero;
    TEST_ASSERT_TRUE(pb_decode_from_bytes(buffer, length, &meshtastic_FromRadio_msg, &fromRadio));
    TEST_ASSERT_EQUAL(meshtastic_FromRadio_clientNotification_tag, fromRadio.which_payload_variant);
    notification = fromRadio.clientNotification;
    return true;
}

static uint8_t claimGuest(SharedNode::PairingPolicy &policy, uint16_t connHandle, const SharedNode::PeerIdentity &identity)
{
    TEST_ASSERT_EQUAL_UINT8(SharedNode::ADMIN_SLOT, policy.resolveSlotForConnection(1, peerIdentity("bf:admin")));
    const uint8_t guestSlot = policy.resolveSlotForConnection(connHandle, identity);
    TEST_ASSERT_NOT_EQUAL_UINT8(SharedNode::INVALID_SLOT, guestSlot);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SharedNode::Role::GUEST),
                            static_cast<uint8_t>(SharedNode::roleForSlot(guestSlot)));
    return guestSlot;
}

void setUp(void)
{
    useFakeCrypto();
}

void tearDown(void)
{
    restoreCrypto();
}

static void test_client_record_proto_round_trip_preserves_names_and_keys()
{
    SharedNode::ClientRecord source;
    source.connectionState = SharedNode::ConnectionState::ACTIVE;
    source.virtualNodeId = 0x123456ab;
    source.peerIdentity = "bf:guest-a";
    strncpy(source.shortName, "GAB", sizeof(source.shortName) - 1);
    strncpy(source.longName, "Guest AB", sizeof(source.longName) - 1);
    source.registerTime = 11;
    source.lastSeen = 22;
    for (uint8_t i = 0; i < SharedNode::PKI_KEY_SIZE; i++) {
        source.publicKey[i] = static_cast<uint8_t>(i);
        source.privateKey[i] = static_cast<uint8_t>(0x80 + i);
    }

    meshtastic_SharedNodeClient raw = meshtastic_SharedNodeClient_init_zero;
    SharedNode::saveClientRecordToProto(raw, source);

    TEST_ASSERT_EQUAL_UINT32(source.virtualNodeId, raw.virtual_node_id);
    TEST_ASSERT_EQUAL_STRING("GAB", raw.short_name);
    TEST_ASSERT_EQUAL_STRING("Guest AB", raw.long_name);
    TEST_ASSERT_EQUAL_STRING("bf:guest-a", raw.peer_identity);
    TEST_ASSERT_EQUAL_UINT32(static_cast<uint32_t>(SharedNode::ConnectionState::NOT_ACTIVE), raw.connection_state);
    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, raw.public_key.size);
    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, raw.private_key.size);
    TEST_ASSERT_EQUAL_MEMORY(source.publicKey, raw.public_key.bytes, SharedNode::PKI_KEY_SIZE);
    TEST_ASSERT_EQUAL_MEMORY(source.privateKey, raw.private_key.bytes, SharedNode::PKI_KEY_SIZE);

    SharedNode::ClientRecord restored;
    SharedNode::loadClientRecordFromProto(restored, raw);

    TEST_ASSERT_EQUAL_UINT32(source.virtualNodeId, restored.virtualNodeId);
    TEST_ASSERT_EQUAL_STRING(source.shortName, restored.shortName);
    TEST_ASSERT_EQUAL_STRING(source.longName, restored.longName);
    TEST_ASSERT_EQUAL_STRING(source.peerIdentity.c_str(), restored.peerIdentity.c_str());
    TEST_ASSERT_EQUAL_MEMORY(source.publicKey, restored.publicKey, SharedNode::PKI_KEY_SIZE);
    TEST_ASSERT_EQUAL_MEMORY(source.privateKey, restored.privateKey, SharedNode::PKI_KEY_SIZE);
}

static void test_virtual_client_keys_are_generated_on_first_virtual_id_assignment()
{
    SharedNode::PairingPolicy policy;
    const SharedNode::PeerIdentity guestA = peerIdentity("bf:guest-a");
    const uint8_t slot = claimGuest(policy, 2, guestA);

    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));
    const SharedNode::ClientRecord firstRecord = policy.recordForTest(slot);
    TEST_ASSERT_EQUAL_UINT8(1, fakeCrypto.generateCount);
    TEST_ASSERT_EQUAL_STRING("GAB", firstRecord.shortName);
    TEST_ASSERT_EQUAL_STRING("Guest AB", firstRecord.longName);
    TEST_ASSERT_TRUE(keyMatchesPattern(firstRecord.publicKey, 0x11));
    TEST_ASSERT_TRUE(keyMatchesPattern(firstRecord.privateKey, 0x81));

    policy.clearConnection(2);
    TEST_ASSERT_EQUAL_UINT8(slot, policy.resolveSlotForConnection(3, guestA));
    const SharedNode::ClientRecord reconnectRecord = policy.recordForTest(slot);
    TEST_ASSERT_EQUAL_UINT8(1, fakeCrypto.generateCount);
    TEST_ASSERT_EQUAL_MEMORY(firstRecord.publicKey, reconnectRecord.publicKey, SharedNode::PKI_KEY_SIZE);
    TEST_ASSERT_EQUAL_MEMORY(firstRecord.privateKey, reconnectRecord.privateKey, SharedNode::PKI_KEY_SIZE);
}

static void test_reassigning_same_virtual_id_does_not_regenerate_keys()
{
    SharedNode::PairingPolicy policy;
    const SharedNode::PeerIdentity guestA = peerIdentity("bf:guest-a");
    const uint8_t slot = claimGuest(policy, 2, guestA);

    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));
    const SharedNode::ClientRecord firstRecord = policy.recordForTest(slot);

    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));
    const SharedNode::ClientRecord sameIdRecord = policy.recordForTest(slot);
    TEST_ASSERT_EQUAL_UINT8(1, fakeCrypto.generateCount);
    TEST_ASSERT_TRUE(bytesEqual(firstRecord.publicKey, sameIdRecord.publicKey));
    TEST_ASSERT_TRUE(bytesEqual(firstRecord.privateKey, sameIdRecord.privateKey));
}

static void test_pairing_policy_allocates_virtual_ids_without_inactive_collision()
{
    SharedNode::PairingPolicy policy;
    TEST_ASSERT_EQUAL_UINT8(SharedNode::ADMIN_SLOT, policy.resolveSlotForConnection(1, peerIdentity("bf:admin-ids")));

    const uint8_t firstSlot = policy.resolveSlotForConnection(2, peerIdentity("bf:guest-id-a"));
    TEST_ASSERT_NOT_EQUAL_UINT8(SharedNode::INVALID_SLOT, firstSlot);
    uint32_t firstVirtualNodeId = 0;
    TEST_ASSERT_TRUE(policy.ensureVirtualNodeIdForSlot(firstSlot, firstVirtualNodeId));
    TEST_ASSERT_NOT_EQUAL_UINT32(0, firstVirtualNodeId);

    policy.clearConnection(2);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SharedNode::ConnectionState::NOT_ACTIVE),
                            static_cast<uint8_t>(policy.recordForTest(firstSlot).connectionState));

    const uint8_t secondSlot = policy.resolveSlotForConnection(3, peerIdentity("bf:guest-id-b"));
    TEST_ASSERT_NOT_EQUAL_UINT8(SharedNode::INVALID_SLOT, secondSlot);
    TEST_ASSERT_NOT_EQUAL_UINT8(firstSlot, secondSlot);

    uint32_t secondVirtualNodeId = 0;
    TEST_ASSERT_TRUE(policy.ensureVirtualNodeIdForSlot(secondSlot, secondVirtualNodeId));
    TEST_ASSERT_NOT_EQUAL_UINT32(0, secondVirtualNodeId);
    TEST_ASSERT_NOT_EQUAL_UINT32(firstVirtualNodeId, secondVirtualNodeId);
}

static void test_pairing_policy_rejects_duplicate_virtual_id_assignment()
{
    SharedNode::PairingPolicy policy;
    TEST_ASSERT_EQUAL_UINT8(SharedNode::ADMIN_SLOT, policy.resolveSlotForConnection(1, peerIdentity("bf:admin-dupe")));

    const uint8_t firstSlot = policy.resolveSlotForConnection(2, peerIdentity("bf:guest-dupe-a"));
    const uint8_t secondSlot = policy.resolveSlotForConnection(3, peerIdentity("bf:guest-dupe-b"));
    TEST_ASSERT_NOT_EQUAL_UINT8(SharedNode::INVALID_SLOT, firstSlot);
    TEST_ASSERT_NOT_EQUAL_UINT8(SharedNode::INVALID_SLOT, secondSlot);

    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(firstSlot, 0x123456ab));
    TEST_ASSERT_FALSE(policy.setVirtualNodeIdForSlot(secondSlot, 0x123456ab));
    TEST_ASSERT_EQUAL_UINT32(0, policy.recordForTest(secondSlot).virtualNodeId);
}

static void test_reused_guest_slot_gets_new_keys_for_new_identity()
{
    SharedNode::PairingPolicy policy;
    const uint8_t slot = claimGuest(policy, 2, peerIdentity("bf:guest-a"));

    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));
    const SharedNode::ClientRecord firstRecord = policy.recordForTest(slot);

    policy.disconnectSlot(slot);
    policy.rememberConnectionSlot(3, peerIdentity("bf:guest-b"), slot);
    const SharedNode::ClientRecord reusedRecord = policy.recordForTest(slot);

    TEST_ASSERT_EQUAL_STRING("bf:guest-b", reusedRecord.peerIdentity.c_str());
    TEST_ASSERT_EQUAL_UINT32(firstRecord.virtualNodeId, reusedRecord.virtualNodeId);
    TEST_ASSERT_EQUAL_STRING(firstRecord.shortName, reusedRecord.shortName);
    TEST_ASSERT_EQUAL_STRING(firstRecord.longName, reusedRecord.longName);
    TEST_ASSERT_EQUAL_UINT8(2, fakeCrypto.generateCount);
    TEST_ASSERT_FALSE(bytesEqual(firstRecord.publicKey, reusedRecord.publicKey));
    TEST_ASSERT_FALSE(bytesEqual(firstRecord.privateKey, reusedRecord.privateKey));
    TEST_ASSERT_TRUE(keyMatchesPattern(reusedRecord.publicKey, 0x12));
    TEST_ASSERT_TRUE(keyMatchesPattern(reusedRecord.privateKey, 0x82));
}

static void test_virtual_user_and_security_config_are_built_from_client_record()
{
    SharedNode::PairingPolicy policy;
    const uint8_t slot = claimGuest(policy, 2, peerIdentity("bf:guest-a"));

    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));
    TEST_ASSERT_TRUE(policy.updateVirtualClientNames(0x123456ab, "ALF", "Alice"));

    meshtastic_User user = meshtastic_User_init_zero;
    TEST_ASSERT_TRUE(policy.buildVirtualUser(0x123456ab, user));
    TEST_ASSERT_EQUAL_STRING("!123456ab", user.id);
    TEST_ASSERT_EQUAL_STRING("ALF", user.short_name);
    TEST_ASSERT_EQUAL_STRING("Alice", user.long_name);
    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, user.public_key.size);

    meshtastic_Config_SecurityConfig security = meshtastic_Config_SecurityConfig_init_zero;
    TEST_ASSERT_TRUE(policy.buildVirtualSecurityConfig(0x123456ab, security, false));
    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, security.public_key.size);
    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, security.private_key.size);
    TEST_ASSERT_TRUE(keyMatchesPattern(security.public_key.bytes, 0x11));
    TEST_ASSERT_TRUE(keyMatchesPattern(security.private_key.bytes, 0x81));
    TEST_ASSERT_EQUAL_UINT8(slot, policy.slotForVirtualNodeId(0x123456ab));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(SharedNode::Role::GUEST),
                            static_cast<uint8_t>(policy.roleForVirtualNodeId(0x123456ab)));
}

static void test_guest_virtual_security_config_hides_admin_keys()
{
    SharedNode::PairingPolicy policy;
    const uint8_t slot = claimGuest(policy, 2, peerIdentity("bf:guest-a"));

    setAdminKey(0, 0x40);
    setAdminKey(1, 0x60);
    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));

    meshtastic_Config_SecurityConfig security = meshtastic_Config_SecurityConfig_init_zero;
    TEST_ASSERT_TRUE(policy.buildVirtualSecurityConfig(0x123456ab, security, false));

    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, security.public_key.size);
    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, security.private_key.size);
    TEST_ASSERT_TRUE(keyMatchesPattern(security.public_key.bytes, 0x11));
    TEST_ASSERT_TRUE(keyMatchesPattern(security.private_key.bytes, 0x81));
    TEST_ASSERT_EQUAL_UINT(0, security.admin_key_count);
    TEST_ASSERT_TRUE(adminKeyIsZero(0, security));
    TEST_ASSERT_TRUE(adminKeyIsZero(1, security));
    TEST_ASSERT_TRUE(adminKeyIsZero(2, security));
}

static void test_admin_virtual_security_config_keeps_admin_keys()
{
    SharedNode::PairingPolicy policy;
    const uint8_t slot = claimGuest(policy, 2, peerIdentity("bf:guest-a"));

    setAdminKey(0, 0x40);
    setAdminKey(1, 0x60);
    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));

    meshtastic_Config_SecurityConfig security = meshtastic_Config_SecurityConfig_init_zero;
    TEST_ASSERT_TRUE(policy.buildVirtualSecurityConfig(0x123456ab, security, true));

    TEST_ASSERT_EQUAL_UINT(2, security.admin_key_count);
    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, security.admin_key[0].size);
    TEST_ASSERT_EQUAL_UINT(SharedNode::PKI_KEY_SIZE, security.admin_key[1].size);
    TEST_ASSERT_TRUE(keyMatchesPattern(security.admin_key[0].bytes, 0x40));
    TEST_ASSERT_TRUE(keyMatchesPattern(security.admin_key[1].bytes, 0x60));
    TEST_ASSERT_TRUE(adminKeyIsZero(2, security));
}

static void test_guest_key_regeneration_does_not_change_global_admin_keys()
{
    SharedNode::PairingPolicy policy;
    const uint8_t slot = claimGuest(policy, 2, peerIdentity("bf:guest-a"));

    setAdminKey(0, 0x40);
    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));

    const auto originalAdminKey = config.security.admin_key[0];
    const pb_size_t originalAdminKeyCount = config.security.admin_key_count;
    TEST_ASSERT_TRUE(policy.regenerateVirtualClientKeys(0x123456ab));

    TEST_ASSERT_EQUAL_UINT(originalAdminKeyCount, config.security.admin_key_count);
    TEST_ASSERT_EQUAL_UINT(originalAdminKey.size, config.security.admin_key[0].size);
    TEST_ASSERT_EQUAL_MEMORY(originalAdminKey.bytes, config.security.admin_key[0].bytes, sizeof(originalAdminKey.bytes));
}

static void test_regenerating_virtual_client_keys_preserves_names()
{
    SharedNode::PairingPolicy policy;
    const uint8_t slot = claimGuest(policy, 2, peerIdentity("bf:guest-a"));

    TEST_ASSERT_TRUE(policy.setVirtualNodeIdForSlot(slot, 0x123456ab));
    TEST_ASSERT_TRUE(policy.updateVirtualClientNames(0x123456ab, "ALF", "Alice"));
    const SharedNode::ClientRecord firstRecord = policy.recordForTest(slot);

    TEST_ASSERT_TRUE(policy.regenerateVirtualClientKeys(0x123456ab));
    const SharedNode::ClientRecord regeneratedRecord = policy.recordForTest(slot);

    TEST_ASSERT_EQUAL_STRING(firstRecord.shortName, regeneratedRecord.shortName);
    TEST_ASSERT_EQUAL_STRING(firstRecord.longName, regeneratedRecord.longName);
    TEST_ASSERT_EQUAL_UINT8(2, fakeCrypto.generateCount);
    TEST_ASSERT_FALSE(bytesEqual(firstRecord.publicKey, regeneratedRecord.publicKey));
    TEST_ASSERT_FALSE(bytesEqual(firstRecord.privateKey, regeneratedRecord.privateKey));
    TEST_ASSERT_TRUE(keyMatchesPattern(regeneratedRecord.publicKey, 0x12));
    TEST_ASSERT_TRUE(keyMatchesPattern(regeneratedRecord.privateKey, 0x82));
}

static void test_shared_node_admin_policy_allows_guest_profile_and_security_only()
{
    SharedNode::AdminPolicy::Context context;
    context.isLocalVirtual = true;
    context.role = SharedNode::Role::GUEST;
    context.virtualNodeId = 0x123456ab;

    meshtastic_AdminMessage request = meshtastic_AdminMessage_init_zero;
    request.which_payload_variant = meshtastic_AdminMessage_set_owner_tag;
    TEST_ASSERT_TRUE(SharedNode::AdminPolicy::isMessageAllowed(context, &request));

    request = meshtastic_AdminMessage_init_zero;
    request.which_payload_variant = meshtastic_AdminMessage_get_config_request_tag;
    request.get_config_request = meshtastic_AdminMessage_ConfigType_SECURITY_CONFIG;
    TEST_ASSERT_TRUE(SharedNode::AdminPolicy::isMessageAllowed(context, &request));

    request = meshtastic_AdminMessage_init_zero;
    request.which_payload_variant = meshtastic_AdminMessage_set_channel_tag;
    TEST_ASSERT_FALSE(SharedNode::AdminPolicy::isMessageAllowed(context, &request));
}

static void test_shared_node_admin_policy_guest_security_regenerates_only_virtual_keys()
{
    SharedNode::PairingPolicy policy;
    const uint8_t slot = claimGuest(policy, 2, peerIdentity("bf:guest-policy"));

    uint32_t virtualNodeId = 0;
    TEST_ASSERT_TRUE(policy.ensureVirtualNodeIdForSlot(slot, virtualNodeId));
    setAdminKey(0, 0x40);
    const auto originalAdminKey = config.security.admin_key[0];
    const pb_size_t originalAdminKeyCount = config.security.admin_key_count;

    SharedNode::AdminPolicy::Context context;
    context.isLocalVirtual = true;
    context.role = SharedNode::Role::GUEST;
    context.virtualNodeId = virtualNodeId;

    meshtastic_Config configPayload = meshtastic_Config_init_zero;
    configPayload.which_payload_variant = meshtastic_Config_security_tag;
    bool requiresReboot = true;
    bool managedModeCleared = true;
    TEST_ASSERT_TRUE(SharedNode::AdminPolicy::applySecurityConfig(context, configPayload, requiresReboot, managedModeCleared));

    TEST_ASSERT_FALSE(requiresReboot);
    TEST_ASSERT_FALSE(managedModeCleared);
    TEST_ASSERT_EQUAL_UINT8(2, fakeCrypto.generateCount);
    TEST_ASSERT_EQUAL_UINT(originalAdminKeyCount, config.security.admin_key_count);
    TEST_ASSERT_EQUAL_UINT(originalAdminKey.size, config.security.admin_key[0].size);
    TEST_ASSERT_EQUAL_MEMORY(originalAdminKey.bytes, config.security.admin_key[0].bytes, sizeof(originalAdminKey.bytes));
}

static void test_phone_api_local_notification_targets_one_connection_and_closes_after_read()
{
    TestPhoneAPI target;
    TestPhoneAPI other;

    target.sendNotificationAndClose(meshtastic_LogRecord_Level_ERROR, 0, "Shared node is full. Ask the admin to free a guest slot.");

    uint8_t otherBuffer[meshtastic_FromRadio_size] = {};
    TEST_ASSERT_EQUAL_UINT(0, other.getFromRadio(otherBuffer));

    meshtastic_ClientNotification notification = meshtastic_ClientNotification_init_zero;
    TEST_ASSERT_TRUE(readClientNotification(target, notification));
    TEST_ASSERT_EQUAL(meshtastic_LogRecord_Level_ERROR, notification.level);
    TEST_ASSERT_FALSE(notification.has_reply_id);
    TEST_ASSERT_EQUAL_STRING("Shared node is full. Ask the admin to free a guest slot.", notification.message);
    TEST_ASSERT_TRUE(target.notified);
    TEST_ASSERT_FALSE(target.closeAfterNotification);

    target.onFromRadioReadComplete();
    TEST_ASSERT_TRUE(target.closeAfterNotification);
}

static void test_guest_phone_api_receives_local_notification_before_guest_queue_filter()
{
    TestPhoneAPI guest;
    guest.setSharedNodeSlot(1);
    guest.setSendingPacketsForTest();

    guest.sendNotification(meshtastic_LogRecord_Level_WARNING, 42, "Only the shared node admin can change this setting.");

    meshtastic_ClientNotification notification = meshtastic_ClientNotification_init_zero;
    TEST_ASSERT_TRUE(readClientNotification(guest, notification));
    TEST_ASSERT_EQUAL(meshtastic_LogRecord_Level_WARNING, notification.level);
    TEST_ASSERT_TRUE(notification.has_reply_id);
    TEST_ASSERT_EQUAL_UINT32(42, notification.reply_id);
    TEST_ASSERT_EQUAL_STRING("Only the shared node admin can change this setting.", notification.message);
}

static void test_virtual_node_manager_admin_duplicate_has_reason()
{
    VirtualNodeManager manager;
    TestPhoneAPI adminA;
    TestPhoneAPI adminB;
    adminA.setSharedNodeSlot(SharedNode::ADMIN_SLOT);
    adminB.setSharedNodeSlot(SharedNode::ADMIN_SLOT);

    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(VirtualNodeManager::SessionStartResult::OK),
                            static_cast<uint8_t>(manager.connectAsAdmin(&adminA)));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(VirtualNodeManager::SessionStartResult::ADMIN_ALREADY_CONNECTED),
                            static_cast<uint8_t>(manager.connectAsAdmin(&adminB)));
}

static void test_virtual_node_manager_guest_limit_has_reason()
{
    VirtualNodeManager manager;
    TestPhoneAPI guests[SharedNode::MAX_GUESTS + 1];

    const uint8_t adminSlot = SharedNode::pairingPolicy.resolveSlotForConnection(1, peerIdentity("bf:admin-limit"));
    TEST_ASSERT_EQUAL_UINT8(SharedNode::ADMIN_SLOT, adminSlot);
    const uint8_t guestSlot = SharedNode::pairingPolicy.resolveSlotForConnection(2, peerIdentity("bf:guest-limit"));
    TEST_ASSERT_NOT_EQUAL_UINT8(SharedNode::INVALID_SLOT, guestSlot);

    for (size_t i = 0; i < SharedNode::MAX_GUESTS; i++) {
        guests[i].setSharedNodeSlot(guestSlot);
        TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(VirtualNodeManager::SessionStartResult::OK),
                                static_cast<uint8_t>(manager.connectAsGuest(&guests[i])));
    }

    guests[SharedNode::MAX_GUESTS].setSharedNodeSlot(guestSlot);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(VirtualNodeManager::SessionStartResult::GUEST_LIMIT_REACHED),
                            static_cast<uint8_t>(manager.connectAsGuest(&guests[SharedNode::MAX_GUESTS])));
}

static void test_virtual_node_manager_invalid_guest_slot_has_reason()
{
    VirtualNodeManager manager;
    TestPhoneAPI guest;
    guest.setSharedNodeSlot(SharedNode::INVALID_SLOT);

    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(VirtualNodeManager::SessionStartResult::UNKNOWN_ROLE),
                            static_cast<uint8_t>(manager.connectAsGuest(&guest)));
}

static void test_virtual_node_manager_rejects_guest_admin_for_other_profile_with_reason()
{
    VirtualNodeManager manager;
    TestPhoneAPI guest;

    TEST_ASSERT_EQUAL_UINT8(SharedNode::ADMIN_SLOT,
                            SharedNode::pairingPolicy.resolveSlotForConnection(1, peerIdentity("bf:admin-reject")));
    const uint8_t guestSlot = SharedNode::pairingPolicy.resolveSlotForConnection(2, peerIdentity("bf:guest-reject"));
    TEST_ASSERT_NOT_EQUAL_UINT8(SharedNode::INVALID_SLOT, guestSlot);
    guest.setSharedNodeSlot(guestSlot);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(VirtualNodeManager::SessionStartResult::OK),
                            static_cast<uint8_t>(manager.connectAsGuest(&guest)));

    meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_zero;
    packet.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    packet.decoded.portnum = meshtastic_PortNum_ADMIN_APP;
    packet.to = 0x12345678;

    const VirtualNodeManager::OutgoingPacketResult result = manager.handleOutgoingPacket(packet, &guest);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(VirtualNodeManager::OutgoingPacketDecision::REJECT),
                            static_cast<uint8_t>(result.decision));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(VirtualNodeManager::OutgoingRejectionReason::NOT_OWN_PROFILE),
                            static_cast<uint8_t>(result.rejectionReason));
}

void setup()
{
    delay(10);
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_client_record_proto_round_trip_preserves_names_and_keys);
    RUN_TEST(test_virtual_client_keys_are_generated_on_first_virtual_id_assignment);
    RUN_TEST(test_reassigning_same_virtual_id_does_not_regenerate_keys);
    RUN_TEST(test_pairing_policy_allocates_virtual_ids_without_inactive_collision);
    RUN_TEST(test_pairing_policy_rejects_duplicate_virtual_id_assignment);
    RUN_TEST(test_reused_guest_slot_gets_new_keys_for_new_identity);
    RUN_TEST(test_virtual_user_and_security_config_are_built_from_client_record);
    RUN_TEST(test_guest_virtual_security_config_hides_admin_keys);
    RUN_TEST(test_admin_virtual_security_config_keeps_admin_keys);
    RUN_TEST(test_guest_key_regeneration_does_not_change_global_admin_keys);
    RUN_TEST(test_regenerating_virtual_client_keys_preserves_names);
    RUN_TEST(test_shared_node_admin_policy_allows_guest_profile_and_security_only);
    RUN_TEST(test_shared_node_admin_policy_guest_security_regenerates_only_virtual_keys);
    RUN_TEST(test_phone_api_local_notification_targets_one_connection_and_closes_after_read);
    RUN_TEST(test_guest_phone_api_receives_local_notification_before_guest_queue_filter);
    RUN_TEST(test_virtual_node_manager_admin_duplicate_has_reason);
    RUN_TEST(test_virtual_node_manager_guest_limit_has_reason);
    RUN_TEST(test_virtual_node_manager_invalid_guest_slot_has_reason);
    RUN_TEST(test_virtual_node_manager_rejects_guest_admin_for_other_profile_with_reason);
    exit(UNITY_END());
}

void loop() {}
#endif
