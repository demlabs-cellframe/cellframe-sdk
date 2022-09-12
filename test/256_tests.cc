#include <gtest/gtest.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/option.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/random.hpp>
#include <boost/random.hpp>
using namespace std;
#include <iostream>

#include "dap_chain_common.h"
#include "dap_math_ops.h"

#include "gtest/gtest-spi.h"


#define MAX64STR "18446744073709551615"
#define MIN128STR "18446744073709551616"
#define MAX128STR "340282366920938463463374607431768211455"
#define MIN256STR "340282366920938463463374607431768211456"
#define MAX256STR "115792089237316195423570985008687907853269984665640564039457584007913129639935"

namespace bmp = boost::multiprecision;

class RandomTests : public ::testing::Test {
protected:
    void SetUp() override {
        gen512.seed(clock());
        gen256.seed(clock());
        gen128.seed(clock());
    }
    typedef boost::random::independent_bits_engine<boost::random::mt19937, 512, bmp::cpp_int> generator_type_512;
    typedef boost::random::independent_bits_engine<boost::random::mt19937, 256, bmp::cpp_int> generator_type_256;
    typedef boost::random::independent_bits_engine<boost::random::mt19937, 128, bmp::cpp_int> generator_type_128;

    generator_type_512 gen512;
    generator_type_256 gen256;
    generator_type_128 gen128;
};

class RandomInputTests : public RandomTests {

};

class DISABLED_RandomInputTestsCoins: public RandomInputTests {

};

class RandomOutputTests: public RandomTests {

};

class RandomComparisonTests: public RandomTests {

};

class RandomBitTests: public RandomTests {

};


// TODO: we need some tests with math-writing, like xxx.yyyyyE+zz, xxx.yyyye+zzz done
// TODO: maybe we can use predicates for two-string-comparision? We CANT use compare256, as it can brake all tests, if it wron. Or can we?
// TODO: need to do some tests for non-native 128-bit, like on armv7_32 (like one on raspberry)
// TODO: need to check stderr (or stdout?) for logging.
// TODO: need to split tests
// TODO: need to add some tests to bit-logic, like 0b0101 & 0b1010 and 0b0101 | 0b1010
// TODO: do we need to run random tests more than one? I think yes, but not in cycle. I think Google Tests can do this, need to implement
// TODO: need to run tests without define DAP_GLOVAL_IS_INT128 (i.e on 32-bit system or with disabling this feature by hand



//TODO: we need some tests with math-writing, like xxx.yyyyyE+zz, xxx.yyyye+zzz
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
    uint256_t max = dap_chain_balance_scan(MAX64STR);
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(max.hi, 0);
    ASSERT_EQ(max.lo, 0xffffffffffffffff);

#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, Min128FromString) {
    uint256_t min = dap_chain_balance_scan(MIN128STR);
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(min.hi, 0);
    ASSERT_EQ(min.lo, bmp::uint128_t(MIN128STR));

#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, Max128FromString) {
    uint256_t max = dap_chain_balance_scan(MAX128STR);
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(max.hi, 0);
    ASSERT_EQ(max.lo, bmp::uint128_t(MAX128STR));
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, Min256FromString) {
    uint256_t min = dap_chain_balance_scan(MIN256STR);
    #if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(min.hi, 1);
    ASSERT_EQ(min.lo, 0);

    #else
    //todo: сreate test for non-native 128 bit
        FAIL();
    #endif
}

TEST(InputTests, Max256FromString) {
    uint256_t max = dap_chain_balance_scan(MAX256STR);
#if defined(DAP_GLOBAL_IS_INT128)
    ASSERT_EQ(max.hi, bmp::uint128_t(MAX128STR));
    ASSERT_EQ(max.lo, bmp::uint128_t(MAX128STR));
#else
    //todo: сreate test for non-native 128 bit
    FAIL();
#endif
}

TEST(InputTests, EmptyInput) {
    uint256_t empty = dap_chain_balance_scan("");
    ASSERT_EQ(empty.lo, 0);
    ASSERT_EQ(empty.hi, 0);
}

TEST(InputTests, NullInput) {
    uint256_t nullinput = dap_chain_balance_scan(NULL);
    EXPECT_EQ(nullinput.lo, 0);
    EXPECT_EQ(nullinput.hi, 0);
}

TEST(InputTests, TooLongInputSome) {
    //some decimal symbols more
    uint256_t a = dap_chain_balance_scan("11579208923731619542357098500868790785326998466564056403945758400791312963993123465");


    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);


}

TEST(InputTests, TooLongInputOne) {
    //one decimal symbol more
    uint256_t a = dap_chain_balance_scan("1157920892373161954235709850086879078532699846656405640394575840079131296399351");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, OverflowTestLeastBit) {
    //one bit more (like decimal 6 instead of decimal 5 on last symbol)
    uint256_t a = dap_chain_balance_scan("115792089237316195423570985008687907853269984665640564039457584007913129639936");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, OverflowTestsMostBit) {
    //2 instead of 1 one most-significant digit
    uint256_t a = dap_chain_balance_scan("215792089237316195423570985008687907853269984665640564039457584007913129639936");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, NonDigitSymbolsInputHexadermical) {
    uint256_t a = dap_chain_balance_scan("123a23");
    //todo: check that this is logging

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);

}

TEST(InputTests, NonDigitSymbolsInputNonHexadermicalLead) {
    uint256_t a = dap_chain_balance_scan("hhh123");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, NonDigitSymbolsInputNonHexadermicalTail) {
    uint256_t a = dap_chain_balance_scan("11579208923731619542357098500868790785326998466564056403945758400791312963993q");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}


TEST(InputTests, LeadingZeroesOne) {
    uint256_t a = dap_chain_balance_scan("01");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 1);
}

TEST(InputTests, LeadingZeroesMany) {
    uint256_t a = dap_chain_balance_scan("0000000001");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 1);
}

TEST(InputTests, LeadingZeroesAlot) {
    //exactly 78
    uint256_t a = dap_chain_balance_scan("000000000000000000000000000000000000000000000000000000000000000000000000000001");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 1);
}

TEST(InputTests, ScientificInputSimplePlus) {
    uint256_t a = dap_chain_balance_scan("1.0e+10");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 10000000000);
}

TEST(InputTests, ScientificInputSimple) {
    uint256_t a = dap_chain_balance_scan("1.0e10");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 10000000000);

}

TEST(InputTests, ScientificInputSimpleCapital) {
    uint256_t a = dap_chain_balance_scan("1.0E+10");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 10000000000);
}

TEST(DISABLED_InputTests, ScientificInputSimpleNotImportantZeroes) {
    //todo: turn this on, when we can handle this

    uint256_t a = dap_chain_balance_scan("1.23456789000000e9");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 1234567890);
}

TEST(DISABLED_InputTests, ScientificInputSimpleNotImportantZeroesAtAll) {

    uint256_t a = dap_chain_balance_scan("1.234000000000000000000000000000e+3");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 1234);
}

TEST(InputTests, ScientificInputSimpleMax64) {
    uint256_t a = dap_chain_balance_scan("1.8446744073709551615e19");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0xffffffffffffffff);
}

TEST(InputTests, ScientificInputSimpleMax64Plus) {
    uint256_t a = dap_chain_balance_scan("1.8446744073709551615e+19");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0xffffffffffffffff);
}

TEST(InputTests, ScientificInputSimpleMin128) {
    uint256_t a = dap_chain_balance_scan("1.8446744073709551616e19");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, bmp::uint256_t(MIN128STR));
}

TEST(InputTests, ScientificIncputSimpleMin128Plus) {
    uint256_t a = dap_chain_balance_scan("1.8446744073709551616e+19");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, bmp::uint256_t(MIN128STR));
}

TEST(InputTests, ScientificInputSimple128Max) {
    uint256_t a = dap_chain_balance_scan("3.40282366920938463463374607431768211455e38");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, bmp::uint256_t(MAX128STR));
}

TEST(InputTests, ScientificInputSimple256Min) {
    uint256_t a = dap_chain_balance_scan("3.40282366920938463463374607431768211456e38");

    EXPECT_EQ(a.hi, 1);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, ScientificInputSimple256Max) {
    uint256_t a = dap_chain_balance_scan("1.15792089237316195423570985008687907853269984665640564039457584007913129639935e77");

    EXPECT_EQ(a.hi, bmp::uint256_t(MAX128STR));
    EXPECT_EQ(a.lo, bmp::uint256_t(MAX128STR));
}

TEST(InputTests, ScientificInputSimple256MaxPlus) {
    uint256_t a = dap_chain_balance_scan("1.15792089237316195423570985008687907853269984665640564039457584007913129639935e+77");

    EXPECT_EQ(a.hi, bmp::uint256_t(MAX128STR));
    EXPECT_EQ(a.lo, bmp::uint256_t(MAX128STR));
}

TEST(InputTests, ScientificInputSimpleLessThanOne) {
    uint256_t a = dap_chain_balance_scan("0.1e1");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 1);
}

TEST(InputTests, ScientificInputSimpleMoreThanTwo) {
    uint256_t a = dap_chain_balance_scan("123.123e3");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 123123);
}

TEST(InputTests, ScientificInputSimpleMaxAndMoreThanTwo) {
    uint256_t a = dap_chain_balance_scan("11579208923731619542357098500868790785326998466564056403945758400791.3129639935e10");

    EXPECT_EQ(a.hi, bmp::uint256_t(MAX128STR));
    EXPECT_EQ(a.lo, bmp::uint256_t(MAX128STR));
}

TEST(InputTests, IncorrectScientificInputMorePluses) {
    uint256_t a = dap_chain_balance_scan("1.0E+++10");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, IncorrectScientificInputMoreExps) {
    uint256_t a = dap_chain_balance_scan("1.0EEE+10");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);

}

TEST(InputTests, IncorrectScientificInputMoreDots) {
    uint256_t a = dap_chain_balance_scan("1.1.1e3");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, IncorrectScientificInputFractionPart){
    // with fraction part
    uint256_t a = dap_chain_balance_scan("1.123e2");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, TooLongScientificInputOneSymb) {
    //one symbol more
    uint256_t a = dap_chain_balance_scan("1.157920892373161954235709850086879078532699846656405640394575840079131296399356e+78");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, TooLongScientificInputTenSymbs) {
    //ten symbols more
    uint256_t a = dap_chain_balance_scan("1.157920892373161954235709850086879078532699846656405640394575840079131296399351234567890e+88");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}


//todo: make some more tests for better coverage (see coverage on dap_chain_balance_scan)
TEST(InputTests, OverflowScientificInputBigExp) {
     uint256_t a = dap_chain_balance_scan("1.0e100");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, OverflowScientificInputOneBit) {
    //last symb changed
    uint256_t a = dap_chain_balance_scan("1.15792089237316195423570985008687907853269984665640564039457584007913129639936e+77");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTest, OverflowScientificInputHighBit) {
    uint256_t a = dap_chain_balance_scan("1.25792089237316195423570985008687907853269984665640564039457584007913129639935e+77");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST(InputTests, OverflowScientificInputHighBit2) {
    uint256_t a = dap_chain_balance_scan("2.15792089237316195423570985008687907853269984665640564039457584007913129639935e+77");

    EXPECT_EQ(a.hi, 0);
    EXPECT_EQ(a.lo, 0);
}

TEST_F(DISABLED_RandomInputTestsCoins, CoinsBase) {
    //todo: fraction part should be 18 or less symbols, not more. For now it can be more and i dont know what to do with it


//    boost::random::uniform_real_distribution<
//            boost::multiprecision::number<
//                    boost::multiprecision::cpp_bin_float<
//                            16, boost::multiprecision::backends::digit_base_10
//                            >
//                            >
//                            > ur(0, 1);
//    boost::random::independent_bits_engine<
//            boost::mt19937,
//            std::numeric_limits<
////                    boost::multiprecision::cpp_bin_float_100
//                    boost::multiprecision::number<
//                            boost::multiprecision::cpp_bin_float<
//                                    16
//                                    >
//                                    >
//                    >::digits,
//                    boost::multiprecision::cpp_int> gen;
//
//
//    for (int i = 0; i<100; i++) {
//        std::cout << ur(gen).str().c_str() << std::endl;
//    }
//
////    EXPECT_FALSE(true);
//    boost::multiprecision::cpp_bin_float_100 c(gen256().str() + ".0");
//    boost::multiprecision::cpp_bin_float_100 b = ur(gen) + c;
//
//    uint256_t a = dap_chain_coins_to_balance(b.str().c_str());
//
//    EXPECT_STREQ(dap_chain_balance_to_coins(a), b.str().c_str());
}


TEST(OutputTests, ZeroOutputBase) {
    uint256_t zero = uint256_0;
    ASSERT_STREQ(dap_chain_balance_print(zero), "0");
}

TEST(OutputTests, Max64Output) {
    uint256_t max = GET_256_FROM_64(0xffffffffffffffff);
    ASSERT_STREQ(dap_chain_balance_print(max), "18446744073709551615");
}

TEST(OutputTests, Min128Output) {
    uint256_t min = dap_chain_balance_scan("18446744073709551616");
    ASSERT_STREQ(dap_chain_balance_print(min), "18446744073709551616");
}

TEST(OutputTests, Max128Output) {
    uint256_t max = dap_chain_balance_scan("340282366920938463463374607431768211455");
    ASSERT_STREQ(dap_chain_balance_print(max), "340282366920938463463374607431768211455");
}

TEST(OutputTests, Min256Output) {
    uint256_t min = dap_chain_balance_scan("340282366920938463463374607431768211456");
    ASSERT_STREQ(dap_chain_balance_print(min), "340282366920938463463374607431768211456");
}

TEST(OutputTests, Max256Output) {
    uint256_t max = dap_chain_balance_scan("115792089237316195423570985008687907853269984665640564039457584007913129639935");
    ASSERT_STREQ(dap_chain_balance_print(max), "115792089237316195423570985008687907853269984665640564039457584007913129639935");
}

TEST_F(RandomOutputTests, Output256){
    bmp::uint256_t boost_a(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
}

TEST(InputTests, Get256From128) {
    uint128_t a = GET_128_FROM_64(123);
    uint256_t b = GET_256_FROM_128(a);
    ASSERT_EQ(b.lo, 123);
    ASSERT_EQ(b.hi, 0);
}

TEST_F(RandomInputTests, Input256) {
    bmp::uint256_t boost_a(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    ASSERT_EQ(a.hi, boost_a >> 128);
    ASSERT_EQ(a.lo, boost_a & bmp::uint256_t("0xffffffffffffffffffffffffffffffff"));
}

TEST(ComparisonTests, Equal128Eq) {
    uint128_t a, b;

    a = GET_128_FROM_64(0);
    b = GET_128_FROM_64(0);

    ASSERT_TRUE(EQUAL_128(a, b));

}

TEST(ComparisonTests, Equal128Neq) {
    uint128_t a, b;

    a = GET_128_FROM_64(1);
    b = GET_128_FROM_64(0);

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
    bmp::uint256_t boost_a(gen128());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_a.str().c_str());

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
    bmp::uint256_t boost_a(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());

    if (boost_a == 0) {
        ASSERT_TRUE(IS_ZERO_256(a));
    }
    else {
        ASSERT_FALSE(IS_ZERO_256(a));
    }

}

TEST(BitTests, And128) {
    uint128_t a = uint128_0;
    uint128_t b = uint128_1;

    ASSERT_EQ(AND_128(a, b), uint128_0);
    ASSERT_EQ(AND_128(a, a), uint128_0);
    ASSERT_EQ(AND_128(b, b), uint128_1);
}

TEST(BitTests, Or128) {
    uint128_t a = uint128_0;
    uint128_t b = uint128_1;

    ASSERT_EQ(OR_128(a, b), uint128_1);
    ASSERT_EQ(OR_128(a, a), uint128_0);
    ASSERT_EQ(OR_128(b, b), uint128_1);
}

TEST(BitTests, And256) {
    uint256_t a = uint256_0;
    uint256_t b = uint256_1;
    uint256_t c;


    //todo: shuld we use ASSERT_EQ with lo and hi? It would be bad for 32-bit only systems
    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(uint256_0));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(uint256_0));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, a)), dap_chain_balance_print(uint256_0));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, b)), dap_chain_balance_print(uint256_1));

    a = dap_chain_balance_scan(MAX64STR);               //0b1111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("12297829382473034410"); //0b1010101010101010101010101010101010101010101010101010101010101010
    c = b; //0b1010101010101010101010101010101010101010101010101010101010101010

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("18446744069414584320");             //0b1111111111111111111111111111111100000000000000000000000000000000
    c = b;             //0b1111111111111111111111111111111100000000000000000000000000000000

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));

    a = dap_chain_balance_scan("18446744069414584320");             //0b1111111111111111111111111111111100000000000000000000000000000000
    b = dap_chain_balance_scan("4294967295");                       //0b0000000000000000000000000000000011111111111111111111111111111111
    c = uint256_0;

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));



    a = dap_chain_balance_scan(MAX128STR);                                             //0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("226854911280625642308916404954512140970");             //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
    c = b;                                                                                      //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("340282366841710300967557013907638845440");             //0b11111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000
    c = b;                                                                                       //0b11111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("340282366920938463444927863358058659840");              //0b11111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000
    c = b;

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));

    a = dap_chain_balance_scan(MAX256STR);                                             //0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("77194726158210796949047323339125271902179989777093709359638389338608753093290");             //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
    c = b;                                                                                      //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("115792089210356248762697446947946071893095522863849111501270640965525260206080");             //0b1111111111111111111111111111111100000000000000000000000000000000111111111111111111111111111111110000000000000000000000000000000011111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000
    c = b;                                                                                       //0b1111111111111111111111111111111100000000000000000000000000000000111111111111111111111111111111110000000000000000000000000000000011111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("115792089237316195417293883273301227089774477609353836086800156426807153786880");              //0b1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000
    c = b;

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));

}

TEST(BitTests, Or256) {
    uint256_t a = uint256_0;
    uint256_t b = uint256_1;
    uint256_t c;


    //todo: shuld we use ASSERT_EQ with lo and hi? It would be bad for 32-bit only systems
    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(uint256_1));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(uint256_1));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, a)), dap_chain_balance_print(uint256_0));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, b)), dap_chain_balance_print(uint256_1));

    a = dap_chain_balance_scan(MAX64STR);               //0b1111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("12297829382473034410"); //0b1010101010101010101010101010101010101010101010101010101010101010
    c = a; //0b1111111111111111111111111111111111111111111111111111111111111111

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("18446744069414584320");             //0b1111111111111111111111111111111100000000000000000000000000000000
    c = a;             //0b1111111111111111111111111111111111111111111111111111111111111111

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));

    a = dap_chain_balance_scan("18446744069414584320");             //0b1111111111111111111111111111111100000000000000000000000000000000
    b = dap_chain_balance_scan("4294967295");                       //0b0000000000000000000000000000000011111111111111111111111111111111
    c = dap_chain_balance_scan(MAX64STR); //0b1111111111111111111111111111111111111111111111111111111111111111


    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));


    a = dap_chain_balance_scan(MAX128STR);                                             //0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("226854911280625642308916404954512140970");             //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
    c = a;                                                                                      //0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("340282366841710300967557013907638845440");             //0b11111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000
    c = a;                                                                                       //0b11111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));


    b = dap_chain_balance_scan("340282366920938463444927863358058659840");              //0b11111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000
    c = a;

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));

    a = dap_chain_balance_scan(MAX256STR);                                             //0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("77194726158210796949047323339125271902179989777093709359638389338608753093290");             //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
    c = a;                                                                                      //0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("115792089210356248762697446947946071893095522863849111501270640965525260206080");             //0b1111111111111111111111111111111100000000000000000000000000000000111111111111111111111111111111110000000000000000000000000000000011111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000
    c = a;                                                                                       //0b1111111111111111111111111111111100000000000000000000000000000000111111111111111111111111111111110000000000000000000000000000000011111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));

    b = dap_chain_balance_scan("115792089237316195417293883273301227089774477609353836086800156426807153786880");              //0b1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000
    c = a;

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(OR_256(b, a)), dap_chain_balance_print(c));



}

TEST(BitTests, CycleShifts) {
    bmp::uint256_t boost_a(1);
    uint256_t a = uint256_1;

    for (int i = 0; i < 256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        LEFT_SHIFT_256(a, &a, 1);
        boost_a <<= 1;
    }

    boost_a = 2;
    a = dap_chain_balance_scan("2");

    for (int i = 0; i < 256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        LEFT_SHIFT_256(a, &a, 1);
        boost_a <<= 1;
    }

    boost_a = 3;
    a = dap_chain_balance_scan("3");

    for (int i = 0; i < 256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        LEFT_SHIFT_256(a, &a, 1);
        boost_a <<= 1;
    }

    boost_a = 7;
    a = dap_chain_balance_scan("7");

    for (int i = 0; i < 256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        LEFT_SHIFT_256(a, &a, 1);
        boost_a <<= 1;
    }

    boost_a = 9;
    a = dap_chain_balance_scan("9");

    for (int i = 0; i < 256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        LEFT_SHIFT_256(a, &a, 1);
        boost_a <<= 1;
    }

    boost_a = bmp::uint256_t(MAX256STR);
    a = dap_chain_balance_scan(MAX256STR);

    for (int i = 0; i<256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        LEFT_SHIFT_256(a, &a, 1);
        boost_a <<= 1;
    }

    boost_a = bmp::uint256_t(MAX256STR);
    a = dap_chain_balance_scan(MAX256STR);

    for (int i = 0; i<256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        RIGHT_SHIFT_256(a, &a, 1);
        boost_a >>= 1;
    }

    boost_a = bmp::uint256_t("57896044618658097711785492504343953926634992332820282019728792003956564819968"); //0b10...0
    a = dap_chain_balance_scan("57896044618658097711785492504343953926634992332820282019728792003956564819968");

    for (int i = 0; i<256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        RIGHT_SHIFT_256(a, &a, 1);
        boost_a >>= 1;
    }

    boost_a = bmp::uint256_t("86844066927987146567678238756515930889952488499230423029593188005934847229952"); //0b110...0
    a = dap_chain_balance_scan("86844066927987146567678238756515930889952488499230423029593188005934847229952");

    for (int i = 0; i<256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        RIGHT_SHIFT_256(a, &a, 1);
        boost_a >>= 1;
    }
}

TEST_F(RandomBitTests, RandomShift) {
    bmp::uint256_t boost_a(gen256());
    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());

    for (int i = 0; i<256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        RIGHT_SHIFT_256(a, &a, 1);
        boost_a >>= 1;
    }

    boost_a = bmp::uint256_t(gen128()); //only 128 bits
    a = dap_chain_balance_scan(boost_a.str().c_str());

    for (int i = 0; i<256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
        LEFT_SHIFT_256(a, &a, 1);
        boost_a <<= 1;
    }
}

TEST_F(RandomBitTests, RandomShiftNotOne) {
    bmp::uint256_t boost_a(gen256());
    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());

    int sh = (int) gen128()%255;

    LEFT_SHIFT_256(a, &a, sh);
    boost_a <<= sh;

    ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());

    boost_a = bmp::uint256_t(gen256());
    a = dap_chain_balance_scan(boost_a.str().c_str());

    RIGHT_SHIFT_256(a, &a, sh);
    boost_a >>= sh;

    ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
}

TEST_F(RandomBitTests, And) {
    bmp::uint256_t boost_a(gen256());
    bmp::uint256_t boost_b(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_b.str().c_str());

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), (boost_a & boost_b).str().c_str());
}

TEST_F(RandomBitTests, Or) {
    bmp::uint256_t boost_a(gen256());
    bmp::uint256_t boost_b(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_b.str().c_str());

    ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), (boost_a | boost_b).str().c_str());
}


TEST_F(RandomBitTests, CiclycAnd) {
    bmp::uint256_t boost_a(gen256());
    bmp::uint256_t boost_b(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_b.str().c_str());

    for (int i = 0; i<256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), (boost_a & boost_b).str().c_str());
        RIGHT_SHIFT_256(a, &a, 1);
        RIGHT_SHIFT_256(b, &b, 1);
        boost_a >>= 1;
        boost_b >>= 1;
    }
}

TEST_F(RandomBitTests, CiclycOr) {
    bmp::uint256_t boost_a(gen256());
    bmp::uint256_t boost_b(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_b.str().c_str());

    for (int i = 0; i<256; i++) {
        ASSERT_STREQ(dap_chain_balance_print(OR_256(a, b)), (boost_a | boost_b).str().c_str());
        RIGHT_SHIFT_256(a, &a, 1);
        RIGHT_SHIFT_256(b, &b, 1);
        boost_a >>= 1;
        boost_b >>= 1;
    }
}


TEST(BitTests, Incr128) {
    uint128_t a = uint128_0;

    INCR_128(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a, 1);
#else
    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, 1);
#endif

    INCR_128(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a, 2);
#else
    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, 2);
#endif

#ifdef DAP_GLOBAL_IS_INT128
    a = 0xffffffffffffffff;
#else
    a.lo = 0xffffffffffffffff;
#endif

    INCR_128(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a, bmp::uint128_t(MIN128STR));
#else
    ASSERT_EQ(a.hi, 1);
    ASSERT_EQ(a.lo, 0);
#endif

//todo: implement 128MAX, overflowing
}

TEST(BitTests, Decr128) {
    uint128_t a = uint128_0;

    DECR_128(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a, bmp::uint128_t(MAX128STR));
#else
    ASSERT_EQ(a.hi, 0xffffffffffffffff);
    ASSERT_EQ(a.lo, 0xffffffffffffffff);
#endif

    DECR_128(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a, bmp::uint128_t(MAX128STR)-1);
#else
    ASSERT_EQ(a.hi, 0xffffffffffffffff);
    ASSERT_EQ(a.lo, 0xfffffffffffffffe);
#endif

#ifdef DAP_GLOBAL_IS_INT128
    a = 0xffffffffffffffff;
#else
    a.hi = 0;
    a.lo = 0xffffffffffffffff;
#endif

    DECR_128(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a, bmp::uint128_t(MAX64STR)-1);
#else
    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, 0xfffffffffffffffe);
#endif

//todo: implement 128MAX, overflowing
}

TEST(BitTests, Incr256One) {
    uint256_t a = uint256_0;

    INCR_256(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, 1);
#else
    //todo: i will not test it for now
    ASSERT_EQ(a.c, 0);
    ASSERT_EQ(a.d, 0);
    ASSERT_EQ(a.a, 0);
    ASSERT_EQ(a.b, 1);
#endif


}

TEST(BitTests, Incr256Two) {
    uint256_t a = uint256_1;

    INCR_256(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, 2);
#else
    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, 2);
#endif

}

TEST(BitTests, Incr256Max64) {
    uint256_t a = dap_chain_balance_scan(MAX64STR);

    INCR_256(&a);

    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, bmp::uint128_t(MIN128STR));
}


TEST(BitTests, Incr256Min128) {
    uint256_t a = dap_chain_balance_scan(MIN128STR);

    INCR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MIN128STR)+1).str().c_str());
}

TEST(BitTests, Incr256Max128) {
    uint256_t a = dap_chain_balance_scan(MAX128STR);

    INCR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MAX128STR)+1).str().c_str());
}

TEST(BitTests, Incr256Min256) {
    uint256_t a = dap_chain_balance_scan(MIN256STR);

    INCR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MIN256STR)+1).str().c_str());
}

TEST(BitTests, Incr256Max256) {
    uint256_t a = dap_chain_balance_scan(MAX256STR);

    INCR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MAX256STR)+1).str().c_str());
}

TEST(BitTests, Decr256One) {
    uint256_t a = uint256_0;

    DECR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(0)-1).str().c_str());
}

TEST(BitTests, Decr256Two) {
    uint256_t a = uint256_1;

    DECR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(1)-1).str().c_str());

}

TEST(BitTests, Decr256Max64) {
    uint256_t a = dap_chain_balance_scan(MAX64STR);

    DECR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MAX64STR)-1).str().c_str());
}


TEST(BitTests, Decr256Min128) {
    uint256_t a = dap_chain_balance_scan(MIN128STR);

    DECR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MIN128STR)-1).str().c_str());
}

TEST(BitTests, Decr256Max128) {
    uint256_t a = dap_chain_balance_scan(MAX128STR);

    DECR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MAX128STR)-1).str().c_str());
}

TEST(BitTests, Decr256Min256) {
    uint256_t a = dap_chain_balance_scan(MIN256STR);

    DECR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MIN256STR)-1).str().c_str());
}

TEST(BitTests, Decr256Max256) {
    uint256_t a = dap_chain_balance_scan(MAX256STR);

    DECR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), (bmp::uint256_t(MAX256STR)-1).str().c_str());
}

TEST_F(RandomBitTests, Incr256) {
    bmp::uint256_t boost_a(gen256());
    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());

    boost_a++;
    INCR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
}

TEST_F(RandomBitTests, Decr256) {
    bmp::uint256_t boost_a(gen256());
    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());

    boost_a--;
    DECR_256(&a);

    ASSERT_STREQ(dap_chain_balance_print(a), boost_a.str().c_str());
}






//TEST(BoostTest, BasicSum) {
//    bmp::uint256_t a {123};
//    bmp::uint256_t b {321};
//    bmp::uint256_t c {123+321};
//
//    uint256_t aa = GET_256_FROM_64(123);
//    uint256_t bb = GET_256_FROM_64(321);
//    uint256_t cc = uint256_0;
//    SUM_256_256(aa, bb, &cc);
//
//    ASSERT_EQ(c.str(), dap_chain_balance_print(cc));
//
//}