#include <gtest/gtest.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/option.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/random.hpp>
#include <boost/random.hpp>
using namespace std;
#include <iostream>

#include "dap_chain_common.h"
#include "dap_math_ops.h"

#include "gtest/gtest-spi.h"

namespace mp = boost::multiprecision;


class RandomInputTests : public ::testing::Test {
protected:

    void SetUp() override {
        gen512.seed(clock());
        gen256.seed(clock());
        gen128.seed(clock());
    }
    typedef boost::random::independent_bits_engine<boost::random::mt19937, 512, mp::cpp_int> generator_type_512;
    typedef boost::random::independent_bits_engine<boost::random::mt19937, 256, mp::cpp_int> generator_type_256;
    typedef boost::random::independent_bits_engine<boost::random::mt19937, 128, mp::cpp_int> generator_type_128;

    generator_type_512 gen512;
    generator_type_256 gen256;
    generator_type_128 gen128;
};

class RandomComparisonTests: public RandomInputTests {

};


TEST(InputTests, ZeroInputBase) {
    uint256_t zero = uint256_0;
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(zero.hi, 0);
    ASSERT_EQ(zero.lo, 0);
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif

}

TEST(InputTests, ZeroInputFrom64) {
    uint256_t zero = dap_chain_uint256_from(0);
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(zero.hi, 0);
    ASSERT_EQ(zero.lo, 0);
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, ZeroInputFromString) {
    uint256_t zero = dap_chain_balance_scan("0");
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(zero.hi, 0);
    ASSERT_EQ(zero.lo, 0);
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, MaxInputFrom64) {
    uint256_t max = dap_chain_uint256_from(0xffffffffffffffff);
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(max.hi, 0);
    ASSERT_EQ(max.lo, 0xffffffffffffffff);
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
    max = GET_256_FROM_64(-1);
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(max.hi, 0);
    ASSERT_EQ(max.lo, 0xffffffffffffffff);
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}


TEST(InputTests, MaxInputFromString) {
    uint256_t max = dap_chain_balance_scan("18446744073709551615");
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(max.hi, 0);
    ASSERT_EQ(max.lo, 0xffffffffffffffff);

#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, Min128FromString) {
    uint256_t min = dap_chain_balance_scan("18446744073709551616");
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(min.hi, 0);
    ASSERT_EQ(min.lo, mp::uint128_t("18446744073709551616"));

#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, Max128FromString) {
    uint256_t max = dap_chain_balance_scan("340282366920938463463374607431768211455");
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(max.hi, 0);
    ASSERT_EQ(max.lo, mp::uint128_t("340282366920938463463374607431768211455"));
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, Min256FromString) {
    uint256_t min = dap_chain_balance_scan("340282366920938463463374607431768211456");
    #if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(min.hi, 1);
    ASSERT_EQ(min.lo, 0);

    #else
    //todo: сreate test for non-native 128 bit
        FAIL();
    #endif
}

TEST(InputTests, Max256FromString) {
    uint256_t max = dap_chain_balance_scan("115792089237316195423570985008687907853269984665640564039457584007913129639935");
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(max.hi, mp::uint128_t("340282366920938463463374607431768211455"));
    ASSERT_EQ(max.lo, mp::uint128_t("340282366920938463463374607431768211455"));
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, Get256From128) {
    uint128_t a = GET_128_FROM_64(123);
    uint256_t b = GET_256_FROM_128(a);
    ASSERT_EQ(b.lo, 123);
    ASSERT_EQ(b.hi, 0);
}

TEST_F(RandomInputTests, Input256) {
    mp::uint256_t boost_a(gen256());

    uint256_t a = dap_chain_balance_scan(to_string(boost_a).c_str());
    ASSERT_EQ(a.hi, boost_a >> 128);
    ASSERT_EQ(a.lo, boost_a & mp::uint256_t("0xffffffffffffffffffffffffffffffff"));
}

TEST(ComparisonTests, Equal128) {
    uint128_t a, b;

    a = GET_128_FROM_64(0);
    b = GET_128_FROM_64(0);

    ASSERT_TRUE(EQUAL_128(a, b));

    a = GET_128_FROM_64(1);

    ASSERT_FALSE(EQUAL_128(a, b));
}


TEST(ComparisonTests, Equal256) {
    uint256_t a, b;

    a = GET_256_FROM_64(0);
    b = GET_256_FROM_64(0);

    ASSERT_TRUE(EQUAL_256(a, b));

    a = GET_256_FROM_64(1);

    ASSERT_FALSE(EQUAL_256(a, b));

    a = dap_chain_balance_scan("340282366920938463463374607431768211456");

    ASSERT_FALSE(EQUAL_256(a, b));

    b = dap_chain_balance_scan("340282366920938463463374607431768211455");

    ASSERT_FALSE(EQUAL_256(a, b));

    b = dap_chain_balance_scan("340282366920938463463374607431768211456");

    ASSERT_TRUE(EQUAL_256(a, b));

    a = dap_chain_balance_scan("115792089237316195423570985008687907853269984665640564039457584007913129639935");

    ASSERT_FALSE(EQUAL_256(a, b));

    b = dap_chain_balance_scan("115792089237316195423570985008687907853269984665640564039457584007913129639934");

    ASSERT_FALSE(EQUAL_256(a, b));

    b = dap_chain_balance_scan("115792089237316195423570985008687907853269984665640564039457584007913129639935");

    ASSERT_TRUE(EQUAL_256(a, b));
}

TEST_F(RandomComparisonTests, Equal256) {
    mp::uint256_t boost_a(gen128());

    uint256_t a = dap_chain_balance_scan(to_string(boost_a).c_str());
    uint256_t b = dap_chain_balance_scan(to_string(boost_a).c_str());

    ASSERT_TRUE(EQUAL_256(a, b));

    ASSERT_TRUE(EQUAL_128(a.lo, b.lo));
    ASSERT_TRUE(EQUAL_128(a.hi, b.hi));
}

TEST(ComparisonTests, IsZeroTest128) {
    uint128_t a = uint128_0;

    ASSERT_TRUE(IS_ZERO_128(a));

    a = uint128_1;

    ASSERT_FALSE(IS_ZERO_128(a));

}

TEST(ComparisonTests, IsZeroTest256) {
    uint256_t a = uint256_0;

    ASSERT_TRUE(IS_ZERO_256(a));

    a = uint256_1;

    ASSERT_FALSE(IS_ZERO_256(a));

    a.lo = 0;
    a.hi = 0;

    ASSERT_TRUE(IS_ZERO_256(a));

    a.lo = 1;

    ASSERT_FALSE(IS_ZERO_256(a));

    a.hi = 1;

    ASSERT_FALSE(IS_ZERO_256(a));

    a.lo = 0;

    ASSERT_FALSE(IS_ZERO_256(a));

    a = dap_chain_balance_scan("0");

    ASSERT_TRUE(IS_ZERO_256(a));

    a = dap_chain_balance_scan("340282366920938463463374607431768211455");

    ASSERT_FALSE(IS_ZERO_256(a));

    a = dap_chain_balance_scan("115792089237316195423570985008687907853269984665640564039457584007913129639935");

    ASSERT_FALSE(IS_ZERO_256(a));

}

TEST_F(RandomComparisonTests, IsZeroTest) {
    mp::uint256_t boost_a(gen128());

    uint256_t a = dap_chain_balance_scan(to_string(boost_a).c_str());

    if (boost_a == 0) {
        ASSERT_TRUE(IS_ZERO_256(a));
    }
    else {
        ASSERT_FALSE(IS_ZERO_256(a));
    }
}

TEST()



//TEST(BoostTest, BasicSum) {
//    mp::uint256_t a {123};
//    mp::uint256_t b {321};
//    mp::uint256_t c {123+321};
//
//    uint256_t aa = GET_256_FROM_64(123);
//    uint256_t bb = GET_256_FROM_64(321);
//    uint256_t cc = uint256_0;
//    SUM_256_256(aa, bb, &cc);
//
//    ASSERT_EQ(to_string(c), dap_chain_balance_print(cc));
//
//}