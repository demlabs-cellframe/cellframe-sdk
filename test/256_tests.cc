#include <gtest/gtest.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/option.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
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


uint64_t one_bits[] = {0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80,
                          0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000,
                          0x4000, 0x8000, 0x10000, 0x20000, 0x40000,
                          0x80000, 0x100000, 0x200000, 0x400000,
                          0x800000, 0x1000000, 0x2000000, 0x4000000,
                          0x8000000, 0x10000000, 0x20000000, 0x40000000,
                          0x80000000, 0x100000000, 0x200000000, 0x400000000,
                          0x800000000, 0x1000000000, 0x2000000000,
                          0x4000000000, 0x8000000000, 0x10000000000,
                          0x20000000000, 0x40000000000, 0x80000000000,
                          0x100000000000, 0x200000000000, 0x400000000000,
                          0x800000000000, 0x1000000000000, 0x2000000000000,
                          0x4000000000000, 0x8000000000000, 0x10000000000000,
                          0x20000000000000, 0x40000000000000, 0x80000000000000,
                          0x100000000000000, 0x200000000000000,
                          0x400000000000000, 0x800000000000000,
                          0x1000000000000000, 0x2000000000000000,
                          0x4000000000000000, 0x8000000000000000};

uint64_t all_bits[] = {0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff,
                       0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff, 0x3fff, 0x7fff,
                       0xffff, 0x1ffff, 0x3ffff, 0x7ffff, 0xfffff, 0x1fffff,
                       0x3fffff, 0x7fffff, 0xffffff, 0x1ffffff, 0x3ffffff, 0x7ffffff,
                       0xfffffff, 0x1fffffff, 0x3fffffff, 0x7fffffff, 0xffffffff,
                       0x1ffffffff, 0x3ffffffff, 0x7ffffffff, 0xfffffffff, 0x1fffffffff,
                       0x3fffffffff, 0x7fffffffff, 0xffffffffff, 0x1ffffffffff,
                       0x3ffffffffff, 0x7ffffffffff, 0xfffffffffff, 0x1fffffffffff,
                       0x3fffffffffff, 0x7fffffffffff, 0xffffffffffff, 0x1ffffffffffff,
                       0x3ffffffffffff, 0x7ffffffffffff, 0xfffffffffffff, 0x1fffffffffffff,
                       0x3fffffffffffff, 0x7fffffffffffff, 0xffffffffffffff, 0x1ffffffffffffff,
                       0x3ffffffffffffff, 0x7ffffffffffffff, 0xfffffffffffffff, 0x1fffffffffffffff,
                       0x3fffffffffffffff, 0x7fffffffffffffff, 0xffffffffffffffff};

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

class RandomMathTests: public RandomTests {

};

class Parameterized64Input:
public testing::TestWithParam<uint64_t> {

};


// TODO: we need some tests with math-writing, like xxx.yyyyyE+zz, xxx.yyyye+zzz done
// TODO: maybe we can use predicates for two-string-comparision? We CANT use compare256, as it can brake all tests, if it wron. Or can we?
// TODO: need to do some tests for non-native 128-bit, like on armv7_32 (like one on raspberry)
// TODO: need to check stderr (or stdout?) for logging.
// TODO: need to split tests
// TODO: need to add some tests to bit-logic, like 0b0101 & 0b1010 and 0b0101 | 0b1010
// TODO: do we need to run random tests more than one? I think yes, but not in cycle. I think Google Tests can do this, need to implement
// TODO: need to run tests without define DAP_GLOBAL_IS_INT128 (i.e on 32-bit system or with disabling this feature by hand
// TODO: Add 64 and 128 tests for arithmetics
// TODO: Rework tests for using predicates, not ASSERT_EQ chains or ASSERT_STREQ




// Comparison functions
void check_equality256(uint256_t a, bmp::uint256_t boost_a) {
#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a.lo, ((boost_a & bmp::uint256_t("0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff")) >> 0)) << "boost_a is: " << boost_a;
    ASSERT_EQ(a.hi, ((boost_a & bmp::uint256_t("0xffffffffffffffffffffffffffffffff00000000000000000000000000000000")) >> 128)) << "boost_a is: " << boost_a;
#else
    ASSERT_EQ(a.lo.lo, ((boost_a & bmp::uint256_t("0x000000000000000000000000000000000000000000000000ffffffffffffffff")) >> 0)) << "boost_a is: " << boost_a;
    ASSERT_EQ(a.lo.hi, ((boost_a & bmp::uint256_t("0x00000000000000000000000000000000ffffffffffffffff0000000000000000")) >> 64)) << "boost_a is: " << boost_a;
    ASSERT_EQ(a.hi.lo, ((boost_a & bmp::uint256_t("0x0000000000000000ffffffffffffffff00000000000000000000000000000000")) >> 128)) << "boost_a is: " << boost_a;
    ASSERT_EQ(a.hi.hi, ((boost_a & bmp::uint256_t("0xffffffffffffffff000000000000000000000000000000000000000000000000")) >> 192)) << "boost_a is: " << boost_a;
#endif
}

void check_equality256(uint256_t a, uint64_t aa) {
    bmp::uint256_t boost_a = bmp::uint256_t(aa);
    check_equality256(a, boost_a);
}

void check_equality256(uint256_t a, string aa) {
    bmp::uint256_t boost_a = bmp::uint256_t(aa);
    check_equality256(a, boost_a);
}



TEST(InputTests, ZeroInputBase) {
    uint256_t a = uint256_0;

    check_equality256(a, 0);
}

TEST_P(Parameterized64Input, Input) {
    uint64_t a = GetParam();
    check_equality256(dap_chain_uint256_from(a), a);
}
INSTANTIATE_TEST_SUITE_P(OneBit, Parameterized64Input, testing::ValuesIn(one_bits));
INSTANTIATE_TEST_SUITE_P(AllBit, Parameterized64Input, testing::ValuesIn(all_bits));

TEST(InputTests, ZeroInputFromString) {
    uint256_t a = dap_chain_balance_scan("0");

    check_equality256(a, 0);
}

TEST(InputTests, MaxInputFromString) {
    uint256_t a = dap_chain_balance_scan(MAX64STR);

    check_equality256(a, MAX64STR);
}

TEST(InputTests, Min128FromString) {
    uint256_t a = dap_chain_balance_scan(MIN128STR);

    check_equality256(a, MIN128STR);
}

TEST(InputTests, Max128FromString) {
    uint256_t a = dap_chain_balance_scan(MAX128STR);

    check_equality256(a, MAX128STR);
}

TEST(InputTests, Min256FromString) {
    uint256_t a = dap_chain_balance_scan(MIN256STR);

    check_equality256(a, MIN256STR);
}

TEST(InputTests, Max256FromString) {
    uint256_t a = dap_chain_balance_scan(MAX256STR);

    check_equality256(a, MAX256STR);
}

TEST(InputTests, EmptyInput) {
    uint256_t a = dap_chain_balance_scan("");

    check_equality256(a, 0);
}

TEST(InputTests, NullInput) {
    uint256_t a = dap_chain_balance_scan(NULL);

    check_equality256(a, 0);
}

TEST(InputTests, TooLongInputSome) {
    //some decimal symbols more
    uint256_t a = dap_chain_balance_scan("11579208923731619542357098500868790785326998466564056403945758400791312963993123465");

    check_equality256(a, 0);
}

TEST(InputTests, TooLongInputOne) {
    //one decimal symbol more
    uint256_t a = dap_chain_balance_scan("1157920892373161954235709850086879078532699846656405640394575840079131296399351");

    check_equality256(a, 0);
}

TEST(InputTests, OverflowTestLeastBit) {
    //one bit more (like decimal 6 instead of decimal 5 on last symbol)
    uint256_t a = dap_chain_balance_scan("115792089237316195423570985008687907853269984665640564039457584007913129639936");

    check_equality256(a, 0);
}

TEST(InputTests, OverflowTestsMostBit) {
    //2 instead of 1 one most-significant digit
    uint256_t a = dap_chain_balance_scan("215792089237316195423570985008687907853269984665640564039457584007913129639935");

    check_equality256(a, 0);
}

TEST(InputTests, OverflowTestsNotMostBit) {
    //2 instead of 1 one most-significant digit
    uint256_t a = dap_chain_balance_scan("125792089237316195423570985008687907853269984665640564039457584007913129639935");

    check_equality256(a, 0);
}

TEST(InputTests, NonDigitSymbolsInputHexadermical) {
    uint256_t a = dap_chain_balance_scan("123a23");
    //todo: check that this is logging

    check_equality256(a, 0);
}

TEST(InputTests, NonDigitSymbolsInputNonHexadermicalLead) {
    uint256_t a = dap_chain_balance_scan("hhh123");

    check_equality256(a, 0);
}

TEST(InputTests, NonDigitSymbolsInputNonHexadermicalTail) {
    uint256_t a = dap_chain_balance_scan("11579208923731619542357098500868790785326998466564056403945758400791312963993q");

    check_equality256(a, 0);
}


TEST(InputTests, LeadingZeroesOne) {
    uint256_t a = dap_chain_balance_scan("01");

    check_equality256(a, 1);
}

TEST(InputTests, LeadingZeroesMany) {
    uint256_t a = dap_chain_balance_scan("0000000001");

    check_equality256(a, 1);
}

TEST(InputTests, LeadingZeroesAlot) {
    //exactly 78
    uint256_t a = dap_chain_balance_scan("000000000000000000000000000000000000000000000000000000000000000000000000000001");

    check_equality256(a, 1);
}

TEST(InputTests, ScientificInputSimplePlus) {
    uint256_t a = dap_chain_balance_scan("1.0e+10");

    check_equality256(a, 10000000000);
}

TEST(InputTests, ScientificInputSimple) {
    uint256_t a = dap_chain_balance_scan("1.0e10");

    check_equality256(a, 10000000000);
}

TEST(InputTests, ScientificInputSimpleCapital) {
    uint256_t a = dap_chain_balance_scan("1.0E+10");

    check_equality256(a, 10000000000);
}

TEST(DISABLED_InputTests, ScientificInputSimpleNotImportantZeroes) {
    //todo: turn this on, when we can handle this

    uint256_t a = dap_chain_balance_scan("1.23456789000000e9");


    check_equality256(a, 1234567890);
}

TEST(DISABLED_InputTests, ScientificInputSimpleNotImportantZeroesAtAll) {

    uint256_t a = dap_chain_balance_scan("1.234000000000000000000000000000e+3");

    check_equality256(a, 1234);
}

TEST(InputTests, ScientificInputSimpleMax64) {
    uint256_t a = dap_chain_balance_scan("1.8446744073709551615e19");

    check_equality256(a, 0xffffffffffffffff);
}

TEST(InputTests, ScientificInputSimpleMax64Plus) {
    uint256_t a = dap_chain_balance_scan("1.8446744073709551615e+19");

    check_equality256(a, 0xffffffffffffffff);
}

TEST(InputTests, ScientificInputSimpleMin128) {
    uint256_t a = dap_chain_balance_scan("1.8446744073709551616e19");

    check_equality256(a, MIN128STR);
}

TEST(InputTests, ScientificIncputSimpleMin128Plus) {
    uint256_t a = dap_chain_balance_scan("1.8446744073709551616e+19");

    check_equality256(a, MIN128STR);
}

TEST(InputTests, ScientificInputSimple128Max) {
    uint256_t a = dap_chain_balance_scan("3.40282366920938463463374607431768211455e38");

    check_equality256(a, MAX128STR);
}

TEST(InputTests, ScientificInputSimple256Min) {
    uint256_t a = dap_chain_balance_scan("3.40282366920938463463374607431768211456e38");

    check_equality256(a, MIN256STR);
}

TEST(InputTests, ScientificInputSimple256Max) {
    uint256_t a = dap_chain_balance_scan("1.15792089237316195423570985008687907853269984665640564039457584007913129639935e77");

    check_equality256(a, MAX256STR);
}

TEST(InputTests, ScientificInputSimple256MaxPlus) {
    uint256_t a = dap_chain_balance_scan("1.15792089237316195423570985008687907853269984665640564039457584007913129639935e+77");

    check_equality256(a, MAX256STR);
}

TEST(InputTests, ScientificInputSimpleLessThanOne) {
    uint256_t a = dap_chain_balance_scan("0.1e1");

    check_equality256(a, 1);
}

TEST(InputTests, ScientificInputSimpleMoreThanTwo) {
    uint256_t a = dap_chain_balance_scan("123.123e3");

    check_equality256(a, 123123);
}

TEST(InputTests, ScientificInputSimpleMaxAndMoreThanTwo) {
    uint256_t a = dap_chain_balance_scan("11579208923731619542357098500868790785326998466564056403945758400791.3129639935e10");

    check_equality256(a, MAX256STR);
}

TEST(InputTests, IncorrectScientificInputMorePluses) {
    uint256_t a = dap_chain_balance_scan("1.0E+++10");

    check_equality256(a, 0);
}

TEST(InputTests, IncorrectScientificInputMoreExps) {
    uint256_t a = dap_chain_balance_scan("1.0EEE+10");

    check_equality256(a, 0);
}

TEST(InputTests, IncorrectScientificInputMoreDots) {
    uint256_t a = dap_chain_balance_scan("1.1.1e3");

    check_equality256(a, 0);
}

TEST(InputTests, IncorrectScientificInputFractionPart){
    // with fraction part
    uint256_t a = dap_chain_balance_scan("1.123e2");

    check_equality256(a, 0);
}

TEST(InputTests, TooLongScientificInputOneSymb) {
    //one symbol more
    uint256_t a = dap_chain_balance_scan("1.157920892373161954235709850086879078532699846656405640394575840079131296399356e+78");

    check_equality256(a, 0);
}

TEST(InputTests, TooLongScientificInputTenSymbs) {
    //ten symbols more
    uint256_t a = dap_chain_balance_scan("1.157920892373161954235709850086879078532699846656405640394575840079131296399351234567890e+88");

    check_equality256(a, 0);
}


//todo: make some more tests for better coverage (see coverage on dap_chain_balance_scan)
TEST(InputTests, OverflowScientificInputBigExp) {
     uint256_t a = dap_chain_balance_scan("1.0e100");

    check_equality256(a, 0);
}

TEST(InputTests, OverflowScientificInputOneBit) {
    //last symb changed
    uint256_t a = dap_chain_balance_scan("1.15792089237316195423570985008687907853269984665640564039457584007913129639936e+77");

    check_equality256(a, 0);
}

TEST(InputTests, OverflowScientificInputHighBit) {
    uint256_t a = dap_chain_balance_scan("1.25792089237316195423570985008687907853269984665640564039457584007913129639935e+77");

    check_equality256(a, 0);
}

TEST(InputTests, OverflowScientificInputHighBit2) {
    uint256_t a = dap_chain_balance_scan("2.15792089237316195423570985008687907853269984665640564039457584007913129639935e+77");

    check_equality256(a, 0);
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
////    ASSERT_FALSE(true);
//    boost::multiprecision::cpp_bin_float_100 c(gen256().str() + ".0");
//    boost::multiprecision::cpp_bin_float_100 b = ur(gen) + c;
//
//    uint256_t a = dap_chain_coins_to_balance(b.str().c_str());
//
//    ASSERT_STREQ(dap_chain_balance_to_coins(a), b.str().c_str());
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
    check_equality256(b, 123);
}

TEST_F(RandomInputTests, Input256) {
    bmp::uint256_t boost_a(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    check_equality256(a, boost_a);
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


TEST(ComparisonTests, Equal256Zeroes) {
    uint256_t a, b;

    a = GET_256_FROM_64(0);
    b = GET_256_FROM_64(0);

    ASSERT_TRUE(EQUAL_256(a, b));
}

TEST(ComparisonTests, Equal256ZeroOne) {
    uint256_t a, b;

    a = GET_256_FROM_64(1);
    b = GET_256_FROM_64(0);

    ASSERT_FALSE(EQUAL_256(a, b));
}

TEST(ComparisonTests, Equal256Min128Zero) {
    uint256_t a, b;

    a = dap_chain_balance_scan(MIN128STR);
    b = GET_256_FROM_64(0);

    ASSERT_FALSE(EQUAL_256(a, b));
}

TEST(ComparisonTests, Equal256Max64Min128) {
    uint256_t a, b;

    a = dap_chain_balance_scan(MIN128STR);
    b = dap_chain_balance_scan(MAX64STR);

    ASSERT_FALSE(EQUAL_256(a, b));
}

TEST(ComparisonTests, Equal256Min128Min128) {
    uint256_t a, b;

    a = dap_chain_balance_scan(MIN128STR);
    b = dap_chain_balance_scan(MIN128STR);

    ASSERT_TRUE(EQUAL_256(a, b));
}

TEST(ComparisonTests, Equal256Max128Min128){
    uint256_t a, b;

    a = dap_chain_balance_scan(MAX128STR);
    b = dap_chain_balance_scan(MIN128STR);

    ASSERT_FALSE(EQUAL_256(a, b));
}

TEST(ComparisonTests, Equal256Max128Min256) {
    uint256_t a, b;

    a = dap_chain_balance_scan(MAX128STR);
    b = dap_chain_balance_scan(MIN256STR);

    ASSERT_FALSE(EQUAL_256(a, b));

}

TEST(ComparisonTests, Equal256Max256Min256) {
    uint256_t a, b;

    a = dap_chain_balance_scan(MAX256STR);
    b = dap_chain_balance_scan(MIN256STR);

    ASSERT_FALSE(EQUAL_256(a, b));
}

TEST(ComparisonTests, Equal256Max256Max256) {
    uint256_t a, b;

    a = dap_chain_balance_scan(MAX256STR);
    b = dap_chain_balance_scan(MAX256STR);

    ASSERT_TRUE(EQUAL_256(a, b));
}

TEST(ComparisonTests, Equal256Max256Zero) {
    uint256_t a, b;

    a = dap_chain_balance_scan(MAX256STR);
    b = dap_chain_balance_scan("0");

    ASSERT_FALSE(EQUAL_256(a, b));
}

TEST_F(RandomComparisonTests, Equal256) {
    bmp::uint256_t boost_a(gen128());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_a.str().c_str());

    ASSERT_TRUE(EQUAL_256(a, b));
}

TEST(ComparisonTests, IsZeroTest128True) {
    uint128_t a = uint128_0;

    ASSERT_TRUE(IS_ZERO_128(a));
}

TEST(ComparisonTests, IsZeroTest128False) {
    uint128_t a = uint128_1;

    ASSERT_FALSE(IS_ZERO_128(a));
}

TEST(ComparisonTests, IsZeroTest256True) {
    uint256_t a = uint256_0;

    ASSERT_TRUE(IS_ZERO_256(a));
}

TEST(ComparisonTests, IsZeroTest256TrueChanged) {
    uint256_t a = uint256_1;

#ifdef DAP_GLOBAL_IS_INT128
    a.lo = 0;
    a.hi = 0;
#else
    a.lo.lo = 0;
    a.lo.hi = 0;
    a.hi.lo = 0;
    a.hi.hi = 0;
#endif

    ASSERT_TRUE(IS_ZERO_256(a));
}

TEST(ComparisonTests, IsZeroTest256False) {
    uint256_t a = uint256_1;

    ASSERT_FALSE(IS_ZERO_256(a));
}

TEST(ComparisonTests, IsZeroTest256FalseChangedLo) {
    uint256_t a = uint256_0;

#ifdef DAP_GLOBAL_IS_INT128
    a.lo = 1;
    a.hi = 0;
#else
    a.lo.lo = 1;
    a.lo.hi = 0;
    a.hi.lo = 0;
    a.hi.hi = 0;
#endif

    ASSERT_FALSE(IS_ZERO_256(a));
}

TEST(ComparisonTests, IsZeroTest256FalseChangedHi){
    uint256_t a = uint256_0;

#ifdef DAP_GLOBAL_IS_INT128
    a.lo = 0;
    a.hi = 1;
#else
    a.lo.lo = 0;
    a.lo.hi = 0;
    a.hi.lo = 1;
    a.hi.hi = 0;
#endif

    ASSERT_FALSE(IS_ZERO_256(a));
}

TEST(ComparisonTests, IsZeroTest256TrueFromBalance) {
    uint256_t a = dap_chain_balance_scan("0");

    ASSERT_TRUE(IS_ZERO_256(a));
}

TEST(ComparisonTests, IsZeroTest256FalseFromBalanceMax128) {
    uint256_t a = dap_chain_balance_scan(MAX128STR);

    ASSERT_FALSE(IS_ZERO_256(a));
}

TEST(ComparisonTests, IsZeroTest256FalseFromBalanceMax256) {
    uint256_t a = dap_chain_balance_scan(MAX256STR);

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
    uint128_t c = AND_128(a, b);
    uint128_t d = AND_128(b, a);
    uint128_t e = AND_128(a, a);
    uint128_t f = AND_128(b, b);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(c, uint128_0);
    ASSERT_EQ(d, uint128_0);
    ASSERT_EQ(e, uint128_0);
    ASSERT_EQ(f, uint128_1);
#else
    ASSERT_EQ(c.lo, uint128_0.lo);
    ASSERT_EQ(c.hi, uint128_0.hi);
    ASSERT_EQ(d.lo, uint128_0.lo);
    ASSERT_EQ(d.hi, uint128_0.hi);
    ASSERT_EQ(e.lo, uint128_0.lo);
    ASSERT_EQ(e.hi, uint128_0.hi);
    ASSERT_EQ(f.lo, uint128_1.lo);
    ASSERT_EQ(f.hi, uint128_1.hi);
#endif
}

TEST(BitTests, Or128) {
    uint128_t a = uint128_0;
    uint128_t b = uint128_1;
    uint128_t c = OR_128(a, b);
    uint128_t d = OR_128(b, a);
    uint128_t e = OR_128(a, a);
    uint128_t f = OR_128(b, b);


#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(c, uint128_1);
    ASSERT_EQ(d, uint128_1);
    ASSERT_EQ(e, uint128_0);
    ASSERT_EQ(f, uint128_1);
#else
    ASSERT_EQ(c.lo, uint128_1.lo);
    ASSERT_EQ(c.hi, uint128_1.hi);
    ASSERT_EQ(d.lo, uint128_1.lo);
    ASSERT_EQ(d.hi, uint128_1.hi);
    ASSERT_EQ(e.lo, uint128_0.lo);
    ASSERT_EQ(e.hi, uint128_0.hi);
    ASSERT_EQ(f.lo, uint128_1.lo);
    ASSERT_EQ(f.hi, uint128_1.hi);
#endif
}

TEST(BitTests, And256ZeroZero) {
    uint256_t a = uint256_0;
    uint256_t b = uint256_1;
    uint256_t c;

    //todo: shuld we use ASSERT_EQ with lo and hi? It would be bad for 32-bit only systems
    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, a)), dap_chain_balance_print(uint256_0));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, a)), dap_chain_balance_print(uint256_0));
}

TEST(BitTests, And256ZeroOne) {
    uint256_t a, b,c;
    a = uint256_0;
    b = uint256_1;
    c = uint256_0;

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(uint256_0));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(uint256_0));

}

TEST(BitTests, And256OneOne) {
    uint256_t a, b,c;
    a = uint256_1;
    b = uint256_1;
    c = uint256_0;

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(uint256_1));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(uint256_1));
}

TEST(BitTests, And256Max64Zebra) {
    uint256_t a, b,c;


    a = dap_chain_balance_scan(MAX64STR);               //0b1111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("12297829382473034410"); //0b1010101010101010101010101010101010101010101010101010101010101010
    c = b; //0b1010101010101010101010101010101010101010101010101010101010101010

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}

TEST(BitTests, And256Max64Halves) {
    uint256_t a, b,c;

    a = dap_chain_balance_scan(MAX64STR);               //0b1111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("18446744069414584320");             //0b1111111111111111111111111111111100000000000000000000000000000000
    c = b;             //0b1111111111111111111111111111111100000000000000000000000000000000

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}


TEST(BitTests, And256Max64DiffHalves) {
    uint256_t a, b,c;

    a = dap_chain_balance_scan("18446744069414584320");             //0b1111111111111111111111111111111100000000000000000000000000000000
    b = dap_chain_balance_scan("4294967295");                       //0b0000000000000000000000000000000011111111111111111111111111111111
    c = uint256_0;

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}


TEST(BitTests, And256Max128Zebra ) {
    uint256_t a, b,c;

    a = dap_chain_balance_scan(MAX128STR);                                             //0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("226854911280625642308916404954512140970");             //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
    c = b;                                                                                      //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}

TEST(BitTests, And256Max128Quarters) {
    uint256_t a, b,c;

    a = dap_chain_balance_scan(MAX128STR);                                             //0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("340282366841710300967557013907638845440");             //0b11111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000
    c = b;                                                                                       //0b11111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}

TEST(BitTests, And256Max128Halves) {
    uint256_t a, b,c;
    a = dap_chain_balance_scan(MAX128STR);                                             //0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("340282366920938463444927863358058659840");              //0b11111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000
    c = b;

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}

//TODO: add other tests, like diff halves

TEST(BitTests, And256Max256Zebra) {
    uint256_t a, b,c;
    a = dap_chain_balance_scan(MAX256STR);                                             //0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("77194726158210796949047323339125271902179989777093709359638389338608753093290");             //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010
    c = b;                                                                                      //0b10101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}

TEST(BitTests, And256Max256Octets) {
    uint256_t a, b,c;

    a = dap_chain_balance_scan(MAX256STR);                                             //0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("115792089210356248762697446947946071893095522863849111501270640965525260206080");             //0b1111111111111111111111111111111100000000000000000000000000000000111111111111111111111111111111110000000000000000000000000000000011111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000
    c = b;                                                                                       //0b1111111111111111111111111111111100000000000000000000000000000000111111111111111111111111111111110000000000000000000000000000000011111111111111111111111111111111000000000000000000000000000000001111111111111111111111111111111100000000000000000000000000000000

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}

TEST(BitTests, And256Max256Quarters) {
    uint256_t a, b,c;

    a = dap_chain_balance_scan(MAX256STR);                                             //0b1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
    b = dap_chain_balance_scan("115792089237316195417293883273301227089774477609353836086800156426807153786880");              //0b1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000
    c = b;

    ASSERT_STREQ(dap_chain_balance_print(AND_256(a, b)), dap_chain_balance_print(c));
    ASSERT_STREQ(dap_chain_balance_print(AND_256(b, a)), dap_chain_balance_print(c));
}

//TODO: add other tests, like halves and diff halves

TEST(BitTests, Or256) {
    uint256_t a = uint256_0;
    uint256_t b = uint256_1;
    uint256_t c;


    //todo: should we use ASSERT_EQ with lo and hi? It would be bad for 32-bit only systems
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
    ASSERT_EQ(a.lo.lo, 1);
    ASSERT_EQ(a.lo.hi, 0);
    ASSERT_EQ(a.hi.lo, 0);
    ASSERT_EQ(a.hi.hi, 0);
#endif


}

TEST(BitTests, Incr256Two) {
    uint256_t a = uint256_1;

    INCR_256(&a);

#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, 2);
#else
    ASSERT_EQ(a.lo.lo, 2);
    ASSERT_EQ(a.lo.hi, 0);
    ASSERT_EQ(a.hi.lo, 0);
    ASSERT_EQ(a.hi.hi, 0);
#endif

}

TEST(BitTests, Incr256Max64) {
    uint256_t a = dap_chain_balance_scan(MAX64STR);

    INCR_256(&a);


#ifdef DAP_GLOBAL_IS_INT128
    ASSERT_EQ(a.hi, 0);
    ASSERT_EQ(a.lo, bmp::uint128_t(MIN128STR));
#else
    ASSERT_EQ(a.lo.lo, 0);
    ASSERT_EQ(a.lo.hi, 1);
    ASSERT_EQ(a.hi.lo, 0);
    ASSERT_EQ(a.hi.hi, 0);
#endif
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

//Straight to 256-bit, exclude 64 and 128 for now
//we have some old tests, try to reimplement it here

TEST(LegacyTests, Math) {
    bmp::uint256_t i,j,k,l, msb_one=0x7fffffffffffffff, lsb_one=1, max_64=(std::numeric_limits<boost::uint64_t>::max)();
    int density_constant=40000;
    int density_index;

    uint256_t dap_test_256_one=uint256_0, dap_test_256_two=uint256_0, dap_test_256_sum=uint256_0;

    int overflow_flag;

    bmp::uint128_t hi_64{"0xffffffffffffffff0000000000000000"};
    bmp::uint128_t lo_64{"0x0000000000000000ffffffffffffffff"};
    bmp::uint128_t max_128{"0xffffffffffffffffffffffffffffffff"};

    bmp::uint128_t two_64{"0x000000000000000010000000000000000"};



    bmp::uint256_t boost_two_64{"0x00000000000000000000000000000000010000000000000000"};
    bmp::uint256_t boost_two_128{"0x0000000000000000100000000000000000000000000000000"};
    bmp::uint256_t boost_two_192{"0x1000000000000000000000000000000000000000000000000"};



    bmp::uint256_t boost_test_256_one;
    bmp::uint256_t boost_test_256_two;
    bmp::uint256_t boost_test_256_sum;

    bmp::uint256_t boost_dap_256_comparison;

    bmp::uint128_t boost_dap_64_128_comparison;

    int error_counter_sum=0;
    int error_counter_prod=0;
    int verbose_output=0;

    for (density_index = 0; density_index<density_constant; density_index+=1000){

        i=density_index;
        j=2*density_index;
        k=3*density_index;
        l=4*density_index;

        //???
//        dap_test_256_one = dap_chain_balance_scan((i + (j << 64) + (k << 128) + (l << 192)).str().c_str());



        bmp::uint256_t boost_test_256_one_coeff_2_0=i;
        bmp::uint256_t boost_test_256_one_coeff_2_64=j;
        bmp::uint256_t boost_test_256_one_coeff_2_128=k;
        bmp::uint256_t boost_test_256_one_coeff_2_192=l;



        boost_test_256_one=boost_test_256_one_coeff_2_0 + boost_test_256_one_coeff_2_64*boost_two_64
                           +boost_test_256_one_coeff_2_128*boost_two_128+boost_test_256_one_coeff_2_192*boost_two_192;

        dap_test_256_one = dap_chain_balance_scan(boost_test_256_one.str().c_str());

        i=max_64-(density_index+1);
        j=max_64-2*(density_index+1);
        k=max_64-3*(density_index+1);
        l=max_64-4*(density_index+1);


        bmp::uint256_t boost_test_256_two_coeff_2_0=i;
        bmp::uint256_t boost_test_256_two_coeff_2_64=j;
        bmp::uint256_t boost_test_256_two_coeff_2_128=k;
        bmp::uint256_t boost_test_256_two_coeff_2_192=l;


        boost_test_256_two=boost_test_256_two_coeff_2_0 + boost_test_256_two_coeff_2_64*boost_two_64
                           +boost_test_256_two_coeff_2_128*boost_two_128+boost_test_256_two_coeff_2_192*boost_two_192;


        dap_test_256_two = dap_chain_balance_scan(boost_test_256_two.str().c_str());


//        add(boost_add_256, i, j);
        overflow_flag=SUM_256_256(dap_test_256_one,dap_test_256_two,&dap_test_256_sum);
//        boost_test_256_sum=add(boost_test_256_sum,boost_test_256_one,boost_test_256_two);
        boost_test_256_sum = boost_test_256_one + boost_test_256_two;

        ASSERT_STREQ(dap_chain_balance_print(dap_test_256_sum), boost_test_256_sum.str().c_str());


        }




}

TEST(LegacyTests, Uint256) {
    uint64_t i, j, k, l, msb_one = 0x7fffffffffffffff, lsb_one = 1, max_64 = (std::numeric_limits<boost::uint64_t>::max)();

//    uint64_t  i, j;

    int density_constant = 200;
    int density_index = 0;
    int division_enabled = 0;



    uint128_t dap_test_128_shift = uint128_0;
    uint128_t dap_test_128_one = uint128_0;
    uint128_t dap_test_128_two = uint128_0;
    uint128_t dap_test_128_sub = uint128_0;
    uint256_t dap_test_256_one = uint256_0;
    uint256_t dap_test_256_two = uint256_0;
    uint256_t dap_test_256_sum = uint256_0;
    uint256_t dap_test_256_sub = uint256_0;
    uint256_t dap_test_256_prod = uint256_0;
    uint256_t dap_test_256_shift = uint256_0;
    uint512_t dap_test_512_prod = uint512_0;

    int overflow_flag;
    int overflow_flag_prod;
    int borrow_flag_128;
    int borrow_flag_256;
    int testing_mode = 0;


    boost::multiprecision::uint128_t hi_64{"0xffffffffffffffff0000000000000000"};
    boost::multiprecision::uint128_t lo_64{"0x0000000000000000ffffffffffffffff"};
    boost::multiprecision::uint128_t max_128{"0xffffffffffffffffffffffffffffffff"};
    boost::multiprecision::uint128_t two_64{"0x000000000000000010000000000000000"};

    boost::multiprecision::uint256_t boost_two_64{"0x00000000000000000000000000000000010000000000000000"};
    boost::multiprecision::uint256_t boost_two_128{"0x0000000000000000100000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_two_192{"0x1000000000000000000000000000000000000000000000000"};

    boost::multiprecision::uint512_t boost_two_64_for_512_calc{"0x00000000000000000000000000000000010000000000000000"};
    boost::multiprecision::uint512_t boost_two_128_for_512_calc{"0x0000000000000000100000000000000000000000000000000"};
    boost::multiprecision::uint512_t boost_two_192_for_512_calc{"0x1000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint512_t boost_two_256_for_512_calc{"0x000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"};

    boost::multiprecision::uint512_t boost_two_320_for_512_calc{"0x100000000000000000000000000000000000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint512_t boost_two_384_for_512_calc{"0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint512_t boost_two_448_for_512_calc{"0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};

    boost::multiprecision::uint128_t boost_two_64_for_128_calc{"0x000000000000000010000000000000000"};




    boost::multiprecision::uint256_t boost_test_256_one{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_test_256_two{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_test_256_sum{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_test_256_sub{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_test_256_prod{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_test_512_prod_hi_prod{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_test_512_prod_lo_prod{"0x0000000000000000000000000000000000000000000000000"};


    boost::multiprecision::uint512_t boost_test_2_256_quotient{"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint512_t boost_test_2_256_remainder{"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint512_t boost_test_512_prod{"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};

    boost::multiprecision::uint128_t boost_test_128_one{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_128_two{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_128_sub{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_256_one_lo{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_256_one_hi{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_256_two_lo{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_256_two_hi{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_dap_64_128_comparison{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_shift_left_128{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_shift_left_128_quotient_limb{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_shift_left_128_remainder_limb{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_dap_comparison_shift_left_128{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_test_64_128_prod{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_dap_128_prod_comparison{"0x000000000000000000000000000000000"};
    boost::multiprecision::uint128_t boost_dap_128_comparison_sub{"0x000000000000000000000000000000000"};

    boost::multiprecision::uint256_t boost_dap_256_comparison{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_dap_256_comparison_sub{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_dap_256_comparison_prod{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_test_shift_left_256{"0x0000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint256_t boost_dap_comparison_shift_left_256{"0x0000000000000000000000000000000000000000000000000"};

    boost::multiprecision::uint512_t boost_dap_512_comparison_prod{"0x0"};

    int error_counter_sum=0;
    int error_counter_prod=0;
    int error_counter_sub_128=0;
    int error_counter_sub_256=0;
    int error_counter_prod_128_128=0;
    int error_counter_prod_128_256=0;
    int error_counter_prod_256_256=0;
    int error_counter_prod_256_512=0;
    int error_counter_shift_left_128=0;
    int error_counter_shift_left_256=0;
    int error_counter_quot_128=0;


    for (density_index = 0; density_index < density_constant; density_index += 1) {
        /////////////////////output of 256+256-->256//////////////////////

        i=density_index;
        j=2*density_index;
        k=3*density_index;
        l=4*density_index;




        boost::multiprecision::uint256_t boost_test_256_one_coeff_2_0=i;
        boost::multiprecision::uint256_t boost_test_256_one_coeff_2_64=j;
        boost::multiprecision::uint256_t boost_test_256_one_coeff_2_128=k;
        boost::multiprecision::uint256_t boost_test_256_one_coeff_2_192=l;



        boost_test_256_one=boost_test_256_one_coeff_2_0 + boost_test_256_one_coeff_2_64*boost_two_64
                           +boost_test_256_one_coeff_2_128*boost_two_128+boost_test_256_one_coeff_2_192*boost_two_192;

        dap_test_256_one = dap_chain_balance_scan(boost_test_256_one.str().c_str());
//        boost_test_256_one_hi=boost_test_256_one_coeff_2_128+boost_two_64*boost_test_256_one_coeff_2_192;
//        boost_test_256_one_lo=boost_test_256_one_coeff_2_0+boost_test_256_one_coeff_2_64*boost_two_64;

        i=max_64-(density_index+1);
        j=max_64-2*(density_index+1);
        k=max_64-3*(density_index+1);
        l=max_64-4*(density_index+1);



        boost::multiprecision::uint256_t boost_test_256_two_coeff_2_0=i;
        boost::multiprecision::uint256_t boost_test_256_two_coeff_2_64=j;
        boost::multiprecision::uint256_t boost_test_256_two_coeff_2_128=k;
        boost::multiprecision::uint256_t boost_test_256_two_coeff_2_192=l;


        boost_test_256_two=boost_test_256_two_coeff_2_0 + boost_test_256_two_coeff_2_64*boost_two_64
                           +boost_test_256_two_coeff_2_128*boost_two_128+boost_test_256_two_coeff_2_192*boost_two_192;

        dap_test_256_two = dap_chain_balance_scan(boost_test_256_two.str().c_str());
        overflow_flag=SUM_256_256(dap_test_256_one,dap_test_256_two,&dap_test_256_sum);
        boost_test_256_sum = boost_test_256_one + boost_test_256_two;

        ASSERT_STREQ(dap_chain_balance_print(dap_test_256_sum), boost_test_256_sum.str().c_str()) << "incorrect output for density index=" << density_index;



        ///256 bit subtraction

        borrow_flag_256=SUBTRACT_256_256(dap_test_256_two,dap_test_256_one,&dap_test_256_sub);
        boost_test_256_sub = boost_test_256_two - boost_test_256_one;

        ASSERT_STREQ(dap_chain_balance_print(dap_test_256_sub), boost_test_256_sub.str().c_str()) << "incorrect output for density index=" << density_index;


        /////////////////////output of 256*256-->256//////////////////////

        overflow_flag_prod=MULT_256_256(dap_test_256_one,dap_test_256_two,&dap_test_256_prod);

        boost_test_256_prod = (boost_test_256_one * boost_test_256_two);

        ASSERT_STREQ(dap_chain_balance_print(dap_test_256_prod), boost_test_256_prod.str().c_str()) << "incorrect output for density index=" << density_index;


//        multiply(boost_test_256_prod,boost_test_256_one,boost_test_256_two);
//        multiply(boost_test_512_prod,boost_test_256_one,boost_test_256_two);
////        multiply(boost_test_512_prod_hi_prod,boost_test_256_one_hi,boost_test_256_two_hi);
////        multiply(boost_test_512_prod_lo_prod,boost_test_256_one_lo,boost_test_256_two_lo);
//        divide_qr(boost_test_512_prod,boost_two_256_for_512_calc,boost_test_2_256_quotient,boost_test_2_256_remainder);
//
//        boost_dap_256_comparison_prod=dap_test_256_prod.lo.lo+dap_test_256_prod.lo.hi*boost_two_64+
//                                      dap_test_256_prod.hi.lo*boost_two_128+dap_test_256_prod.hi.hi*boost_two_192;


        /////////////////////output of 256*256-->512//////////////////////
        dap_test_512_prod = uint512_0;

        uint256_t intermed_lo_prod;
        uint256_t intermed_hi_prod;

        MULT_256_512(dap_test_256_one,dap_test_256_two,&dap_test_512_prod);


        boost_dap_512_comparison_prod = boost_test_256_one * boost_test_256_two;

        char buf[512] = {0};

        //todo: Implement comparition for 512


        /////////////////////output of shift left 128/////////////////////

        if (density_index<=127){
#ifdef DAP_GLOBAL_IS_INT128
            dap_test_128_one=dap_test_256_one.lo;
            LEFT_SHIFT_128(dap_test_128_one,&dap_test_128_shift,density_index);



            boost_test_128_one=dap_test_128_one+dap_test_128_one*boost_two_64_for_128_calc;
            boost_test_shift_left_128=boost_test_128_one<<density_index;
            boost_dap_comparison_shift_left_128=dap_test_128_shift+dap_test_128_shift*boost_two_64_for_128_calc;

            divide_qr(boost_test_shift_left_128,boost_two_64_for_128_calc,boost_test_shift_left_128_quotient_limb,boost_test_shift_left_128_remainder_limb);

            ASSERT_EQ(boost_dap_comparison_shift_left_128, boost_test_shift_left_128) << "incorrect shift left 128 output for density index=" << density_index;

#else
            //todo: not implemented
#endif
        }
        /////////////////////output of shift left 256/////////////////////

        if (density_index<=255){
#ifdef DAP_GLOBAL_IS_INT128
            LEFT_SHIFT_256(dap_test_256_one,&dap_test_256_shift,density_index);

            boost_test_256_one=boost_test_256_one_coeff_2_0 + boost_test_256_one_coeff_2_64*boost_two_64
                               +boost_test_256_one_coeff_2_128*boost_two_128+boost_test_256_one_coeff_2_192*boost_two_192;
            boost_test_shift_left_256=boost_test_256_one<<density_index;
            boost_dap_comparison_shift_left_256=dap_test_256_shift.lo+
                                                dap_test_256_shift.hi*boost_two_128;

            ASSERT_EQ(boost_dap_comparison_shift_left_256, boost_test_shift_left_256) << "incorrect shift left 128 output for density index=" << density_index;
#else
            //todo: not implemented
#endif
        }

        /////////////////////output of 64*64-->128////////////////////////


        i=density_index;
        j=max_64-(density_index+1);
        uint128_t dap_test_64_128_prod;
#ifdef DAP_GLOBAL_IS_INT128
        dap_test_64_128_prod=0;
#else
        dap_test_64_128_prod.lo=0;
        dap_test_64_128_prod.hi=0;
#endif



        boost_test_64_128_prod = bmp::uint128_t(i) * bmp::uint128_t(j);


        MULT_64_128(i,j,&dap_test_64_128_prod);
#ifdef DAP_GLOBAL_IS_INT128
        boost_dap_128_prod_comparison=dap_test_64_128_prod;
#else
        boost_dap_128_prod_comparison = 0;
        boost_dap_128_prod_comparison += dap_test_64_128_prod.hi;
        boost_dap_128_prod_comparison <<= 64;
        boost_dap_128_prod_comparison += dap_test_64_128_prod.lo;
#endif

        ASSERT_EQ(boost_dap_128_prod_comparison, boost_test_64_128_prod);


        ///////////////////output of 128*128-->128////////////////////////

        uint128_t dap_test_128_128_prod_one;
        uint128_t dap_test_128_128_prod_two;
        uint128_t dap_test_128_128_prod_prod;

//        dap_test_128_128_prod_one = i + ((uint128_t) j << 64);
//        dap_test_128_128_prod_two = max_64-(i+1) + (((uint128_t) max_64 - (i+1) +  max_64-2*(j+1)) << 64);
//        dap_test_128_128_prod_prod = uint128_0;



        boost::multiprecision::uint128_t boost_test_128_128_prod;
        boost::multiprecision::uint128_t boost_test_128_128_one;
        boost::multiprecision::uint128_t boost_test_128_128_two;
        boost::multiprecision::uint128_t boost_dap_128_128_prod_comparison;

        ////compute boost "factors"
        boost_test_128_128_one=i+j*boost_two_64_for_128_calc;
        boost_test_128_128_two=max_64-(i+1)+(max_64-2*(j+1))*boost_two_64_for_128_calc;

        dap_test_128_128_prod_one = dap_chain_balance_scan(boost_test_128_128_one.str().c_str()).lo;
        dap_test_128_128_prod_two = dap_chain_balance_scan(boost_test_128_128_two.str().c_str()).lo;


        multiply(boost_test_128_128_prod, boost_test_128_128_one, boost_test_128_128_two);
        MULT_128_128(dap_test_128_128_prod_one,dap_test_128_128_prod_two,&dap_test_128_128_prod_prod);

#ifdef DAP_GLOBAL_IS_INT128
        boost_dap_128_128_prod_comparison=dap_test_128_128_prod_prod;
#else
        boost_dap_128_128_prod_comparison = 0;
        boost_dap_128_128_prod_comparison += dap_test_128_128_prod_prod.hi;
        boost_dap_128_128_prod_comparison <<= 64;
        boost_dap_128_128_prod_comparison += dap_test_128_128_prod_prod.lo;
#endif

        ASSERT_EQ(
                boost_dap_128_128_prod_comparison, boost_test_128_128_prod
                ) << boost_test_128_128_one << " * " << boost_test_128_128_two;


        ///128 bit subtraction

        dap_test_128_one = dap_chain_balance_scan(boost_test_128_one.str().c_str()).lo;
        dap_test_128_two = dap_chain_balance_scan(boost_test_128_two.str().c_str()).lo;

        borrow_flag_128=SUBTRACT_128_128(dap_test_128_one,dap_test_128_two,&dap_test_128_sub);
        subtract(boost_test_128_sub,boost_test_128_one,boost_test_128_two);


#ifdef DAP_GLOBAL_IS_INT128
        boost_dap_128_comparison_sub=dap_test_128_sub;
#else
        boost_dap_128_comparison_sub = 0;
        boost_dap_128_comparison_sub += dap_test_128_sub.hi;
        boost_dap_128_comparison_sub <<= 64;
        boost_dap_128_comparison_sub += dap_test_128_sub.lo;
#endif

        ASSERT_EQ(
                boost_dap_128_comparison_sub, boost_test_128_sub
        ) << boost_test_128_one << " - " << boost_test_128_two;









        /////////////////////output of 128*128-->256////////////////////////


        uint128_t dap_test_128_256_prod_one;
        uint128_t dap_test_128_256_prod_two;
        uint256_t dap_test_128_256_prod_prod;
//        dap_test_128_256_prod_one.lo=i;
//        dap_test_128_256_prod_one.hi=j;
//        dap_test_128_256_prod_two.lo=max_64-(i+1);
//        dap_test_128_256_prod_two.hi=max_64-2*(j+1);
//        dap_test_128_256_prod_prod.lo=zero_128;
//        dap_test_128_256_prod_prod.hi=zero_128;

        boost::multiprecision::uint256_t boost_test_128_256_prod;
        boost::multiprecision::uint128_t boost_test_128_256_one;
        boost::multiprecision::uint128_t boost_test_128_256_two;
        boost::multiprecision::uint256_t boost_dap_128_256_prod_comparison;

        ////compute boost "factors"
        boost_test_128_256_one=i+j*boost_two_64_for_128_calc;
        boost_test_128_256_two=(max_64-(i+1))+(max_64-2*(j+1))*boost_two_64_for_128_calc;

        dap_test_128_256_prod_one = dap_chain_balance_scan(boost_test_128_256_one.str().c_str()).lo;
        dap_test_128_256_prod_two = dap_chain_balance_scan(boost_test_128_256_two.str().c_str()).lo;

        multiply(boost_test_128_256_prod, boost_test_128_256_one, boost_test_128_256_two);
        MULT_128_256(dap_test_128_256_prod_one,dap_test_128_256_prod_two,&dap_test_128_256_prod_prod);

        ASSERT_EQ(bmp::uint256_t(dap_chain_balance_print(dap_test_128_256_prod_prod)), boost_test_128_256_prod) << boost_test_128_256_one << " * " << boost_test_128_256_two;



    // todo: uncomment this when divmod_impl_128 will be implemented without ifdef
//        /////////////////////output of 128/128-->128////////////////////////
//        if(division_enabled==1){
//
//            i=density_index+1;
//            j=density_index+2;
//            uint128_t dap_test_128_quot_one;
//            uint128_t dap_test_128_quot_two;
//            uint128_t dap_test_128_quot_quot;
//            uint128_t dap_test_128_quot_rem;
//
//
//            boost::multiprecision::uint128_t boost_test_128_quot_one;
//            boost::multiprecision::uint128_t boost_test_128_quot_two;
//            boost::multiprecision::uint128_t boost_test_128_quot_quot;
//            boost::multiprecision::uint128_t boost_test_128_quot_rem;
//            boost::multiprecision::uint128_t boost_dap_128_quot_comparison_quot;
//            boost::multiprecision::uint128_t boost_dap_128_quot_comparison_rem;
//
//            ////compute boost "factors"
//            boost_test_128_quot_one=i+j*boost_two_64_for_128_calc;
//            boost_test_128_quot_two=(max_64-(i+1))+(max_64-2*(j+1))*boost_two_64_for_128_calc;
//
//            dap_test_128_quot_one = dap_chain_balance_scan(boost_test_128_quot_one.str().c_str()).lo;
//            dap_test_128_quot_two = dap_chain_balance_scan(boost_test_128_quot_two.str().c_str()).lo;
//
//            divide_qr( boost_test_128_quot_two, boost_test_128_quot_one,boost_test_128_quot_quot,boost_test_128_quot_rem);
//            divmod_impl_128(dap_test_128_quot_one,dap_test_128_quot_two,&dap_test_128_quot_quot, &dap_test_128_quot_rem);
//
//
//            ASSERT_EQ(bmp::uint256_t(dap_test_128_quot_quot), boost_test_128_quot_quot) << boost_test_128_quot_two << " / " << boost_test_128_quot_one;
//            ASSERT_EQ(bmp::uint256_t(dap_test_128_quot_rem), boost_test_128_quot_rem) << boost_test_128_quot_two << " % " << boost_test_128_quot_one;
//
//
//        }


    }
}


TEST(MathTests, Sum256Zeroes) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256OneZero) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256OneOne) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Min128Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Min128One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Min128Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Max128Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Max128One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Max128Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Min256Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Min256One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Min256Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Max256Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX256STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sum256Max256One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX256STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) + bmp::uint256_t(rhs)).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) + bmp::uint256_t(lhs)).str().c_str());
}

TEST_F(RandomMathTests, Sum256) {
    bmp::uint256_t boost_a(gen256()), boost_b(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_b.str().c_str());
    uint256_t c = uint256_0;

    SUM_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (boost_a+boost_b).str().c_str());

    SUM_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (boost_b+boost_a).str().c_str());
}

/// SUBTRACTION

TEST(MathTests, Sub256Zeroes) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());

    SUBTRACT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) - bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Sub256OneZero) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256ZeroOne) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256OneOne) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Min128Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256ZeroMin128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = MIN128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Min128One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256OneMin128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = MIN128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Min128Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256TwoMin128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "2";
    string rhs = MIN128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Max128Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256ZeroMax128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = MAX128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Max128One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256OneMax128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = MAX128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Max128Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256TwoMax128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "2";
    string rhs = MAX128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Min256Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256ZeroMin256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = MIN256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Min256One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());

}

TEST(MathTests, Sub256OneMin256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = MIN256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Min256Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256TwoMin256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "2";
    string rhs = MIN256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Max256Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX256STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256ZeroMax256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = MAX256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256Max256One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX256STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Sub256OneMax256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = MAX256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) - bmp::uint256_t(rhs)).str().c_str());
}

TEST_F(RandomMathTests, Sub256) {
    bmp::uint256_t boost_a(gen256()), boost_b(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_b.str().c_str());
    uint256_t c = uint256_0;

    SUBTRACT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (boost_a-boost_b).str().c_str());
}


//// PRODUCTION
TEST(MathTests, Prod256Zeroes) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256OneZero) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256OneOne) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Min128Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Min128One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Min128Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Max128Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Max128One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Max128Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Min256Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Min256One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Min256Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Max256Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX256STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Prod256Max256One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX256STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) * bmp::uint256_t(rhs)).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) * bmp::uint256_t(lhs)).str().c_str());
}

TEST_F(RandomMathTests, Prod256) {
    bmp::uint256_t boost_a(gen256()), boost_b(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_b.str().c_str());
    uint256_t c = uint256_0;

    MULT_256_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (boost_a*boost_b).str().c_str());

    MULT_256_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (boost_b*boost_a).str().c_str());
}


//// DIVISION
//division by zero disabled for now

TEST(DISABLED_MathTests, Div256Zeroes) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());

    DIV_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) / bmp::uint256_t(lhs)).str().c_str());
}

TEST(DISABLED_MathTests, Div256OneZero) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256ZeroOne) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256OneOne) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(DISABLED_MathTests, Div256Min128Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256ZeroMin128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = MIN128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256Min128One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256OneMin128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = MIN128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256Min128Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN128STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256TwoMin128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "2";
    string rhs = MIN128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(DISABLED_MathTests, Div256Max128Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256ZeroMax128) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(b, a, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(rhs) / bmp::uint256_t(lhs)).str().c_str());
}

TEST(MathTests, Div256Max128One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256OneMax128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = MAX128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256Max128Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX128STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256TwoMax128) {
    uint256_t a, b, c = uint256_0;

    string lhs = "2";
    string rhs = MAX128STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(DISABLED_MathTests, Div256Min256Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256ZeroMin256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = MIN256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256Min256One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());

}

TEST(MathTests, Div256OneMin256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = MIN256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256Min256Two) {
    uint256_t a, b, c = uint256_0;

    string lhs = MIN256STR;
    string rhs = "2";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256TwoMin256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "2";
    string rhs = MIN256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(DISABLED_MathTests, Div256Max256Zero) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX256STR;
    string rhs = "0";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256ZeroMax256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "0";
    string rhs = MAX256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256Max256One) {
    uint256_t a, b, c = uint256_0;

    string lhs = MAX256STR;
    string rhs = "1";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, Div256OneMax256) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1";
    string rhs = MAX256STR;

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (bmp::uint256_t(lhs) / bmp::uint256_t(rhs)).str().c_str());
}

TEST(MathTests, DivMoreToLess) {
    uint256_t a, b, c = uint256_0;

    string lhs = "25000";
    string rhs = "10000";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());
    DIV_256_COIN(a, b, &c);
    ASSERT_STREQ(dap_chain_balance_to_coins(c), "2.5");
}

TEST(MathTests, DivMoreToLessPrimes) {
    uint256_t a, b, c = uint256_0;

    string lhs = "23";
    string rhs = "13";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());
    DIV_256_COIN(a, b, &c);
    ASSERT_STREQ(dap_chain_balance_to_coins(c), "1.76923076923076923");
}

TEST(MathTests, DivMoreToLessClassic) {
    uint256_t a, b, c = uint256_0;

    string lhs = "2500";
    string rhs = "1000";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());
    DIV_256_COIN(a, b, &c);
    ASSERT_STREQ(dap_chain_balance_to_coins(c), "2.5");
}

TEST(MathTests, DivMoreToLessSixFour) {
    uint256_t a, b, c = uint256_0;

    string lhs = "6";
    string rhs = "4";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());
    DIV_256_COIN(a, b, &c);
    ASSERT_STREQ(dap_chain_balance_to_coins(c), "1.5");
}

TEST(MathTests, DivMoreToLessSixThree) {
    uint256_t a, b, c = uint256_0;

    string lhs = "6";
    string rhs = "3";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());
    DIV_256_COIN(a, b, &c);
    ASSERT_STREQ(dap_chain_balance_to_coins(c), "2.0");
}

TEST(MathTests, DivMoreToLessBigBig) {
    uint256_t a, b, c = uint256_0;

    string lhs = "1.0e+57";
    string rhs = "1.0e+23";

    a = dap_chain_balance_scan(lhs.c_str());
    b = dap_chain_balance_scan(rhs.c_str());
    DIV_256_COIN(a, b, &c);
    ASSERT_STREQ(dap_chain_balance_to_coins(c), "10000000000000000000000000000000000.0");
}


TEST_F(RandomMathTests, Div256) {
    bmp::uint256_t boost_a(gen256()), boost_b(gen256());

    uint256_t a = dap_chain_balance_scan(boost_a.str().c_str());
    uint256_t b = dap_chain_balance_scan(boost_b.str().c_str());
    uint256_t c = uint256_0;

    if (boost_b == 0) {
        GTEST_SKIP() << "Division by zero";
    }

    DIV_256(a, b, &c);

    ASSERT_STREQ(dap_chain_balance_print(c), (boost_a/boost_b).str().c_str());
}

