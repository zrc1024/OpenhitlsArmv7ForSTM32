//
// Created by 14674 on 25-7-9.
//

#ifndef TEST_H
#define TEST_H

#define MAX_PLAIN_TEXT_LEN 2048
#define CIPHER_TEXT_EXTRA_LEN 97
#define CRYPT_EAL_PKEY_KEYMGMT_OPERATE 0

#define SM3_MD_SIZE 32
#define SM2_POINT_SINGLE_COORDINATE_LEN 32
#define SM2_POINT_COORDINATE_LEN 65

#define ASSERT_TRUE(TEST)                       \
do {                                    \
if (!(TEST)) {                      \
goto EXIT;                      \
}                                   \
} while (0)
#define ASSERT_EQ(VALUE1, VALUE2)                       \
do {                                                \
int64_t value1__ = (int64_t)(VALUE1);           \
int64_t value2__ = (int64_t)(VALUE2);           \
if (value1__ != value2__) {                     \
goto EXIT;                                  \
}                                               \
} while (0)

void test_openhitls(void);
#endif //TEST_H
