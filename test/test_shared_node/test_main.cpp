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
#include "mesh/NodeDB.h"
#include "mesh/sharedNode/PairingPolicy.h"
#include "mesh/sharedNode/RecordProto.h"

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
    previousCrypto = crypto;
    fakeCrypto.generateCount = 0;
    crypto = &fakeCrypto;
    config.security = meshtastic_Config_SecurityConfig_init_zero;
}

static void restoreCrypto()
{
    crypto = previousCrypto;
    previousCrypto = nullptr;
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

void setup()
{
    delay(10);
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_client_record_proto_round_trip_preserves_names_and_keys);
    RUN_TEST(test_virtual_client_keys_are_generated_on_first_virtual_id_assignment);
    RUN_TEST(test_reassigning_same_virtual_id_does_not_regenerate_keys);
    RUN_TEST(test_reused_guest_slot_gets_new_keys_for_new_identity);
    RUN_TEST(test_virtual_user_and_security_config_are_built_from_client_record);
    RUN_TEST(test_guest_virtual_security_config_hides_admin_keys);
    RUN_TEST(test_admin_virtual_security_config_keeps_admin_keys);
    RUN_TEST(test_guest_key_regeneration_does_not_change_global_admin_keys);
    RUN_TEST(test_regenerating_virtual_client_keys_preserves_names);
    exit(UNITY_END());
}

void loop() {}
#endif
