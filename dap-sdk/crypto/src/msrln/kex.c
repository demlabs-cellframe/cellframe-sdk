#include <stdio.h>
#include <stdlib.h>
#include "msrln_priv.h"

#include "KeccakHash.h"
#include "SimpleFIPS202.h"


// N^-1 * prime_scale^-8
const int32_t MSRLN_Ninv8_ntt1024_12289 = 8350;
// N^-1 * prime_scale^-7 * omegainv_rev_ntt1024_12289[1]
const int32_t MSRLN_omegainv7N_rev_ntt1024_12289 = 795;
// N^-1 * prime_scale^-11
const int32_t MSRLN_Ninv11_ntt1024_12289 = 2585;
// N^-1 * prime_scale^-10 * omegainv_rev_ntt1024_12289[1]
const int32_t MSRLN_omegainv10N_rev_ntt1024_12289 = 10953;


// Index-reversed matrices containing powers of psi (psi_rev_nttxxx_yyy) and inverse powers of omega (omegainv_rev_nttxxx_yyy),
// where xxx is parameter N and yyy is the prime q.

const int32_t MSRLN_psi_rev_ntt1024_12289[1024] = {
8193, 493, 6845, 9908, 1378, 10377, 7952, 435, 10146, 1065, 404, 7644, 1207, 3248, 11121, 5277, 2437, 3646, 2987, 6022, 9867, 6250, 10102, 9723, 1002, 7278, 4284, 7201,
875, 3780, 1607, 4976, 8146, 4714, 242, 1537, 3704, 9611, 5019, 545, 5084, 10657, 4885, 11272, 3066, 12262, 3763, 10849, 2912, 5698, 11935, 4861, 7277, 9808, 11244, 2859,
7188, 1067, 2401, 11847, 390, 11516, 8511, 3833, 2780, 7094, 4895, 1484, 2305, 5042, 8236, 2645, 7875, 9442, 2174, 7917, 1689, 3364, 4057, 3271, 10863, 4654, 1777, 10626,
3636, 7351, 9585, 6998, 160, 3149, 4437, 12286, 10123, 3915, 7370, 12176, 4048, 2249, 2884, 1153, 9103, 6882, 2126, 10659, 3510, 5332, 2865, 9919, 9320, 8311, 9603, 9042,
3016, 12046, 9289, 11618, 7098, 3136, 9890, 3400, 2178, 1544, 5559, 420, 8304, 4905, 476, 3531, 9326, 4896, 9923, 3051, 3091, 81, 1000, 4320, 1177, 8034, 9521, 10654, 11563,
7678, 10436, 12149, 3014, 9088, 5086, 1326, 11119, 2319, 11334, 790, 2747, 7443, 3135, 3712, 1062, 9995, 7484, 8736, 9283, 2744, 11726, 2975, 9664, 949, 7468, 9650, 7266,
5828, 6561, 7698, 3328, 6512, 1351, 7311, 8155, 5736, 722, 10984, 4043, 7143, 10810, 1, 8668, 2545, 3504, 8747, 11077, 1646, 9094, 5860, 1759, 8582, 3694, 7110, 8907, 11934,
8058, 9741, 9558, 3932, 5911, 4890, 3637, 8830, 5542, 12144, 5755, 7657, 7901, 11029, 11955, 9863, 10861, 1696, 3284, 2881, 7197, 2089, 9000, 2013, 729, 9048, 11809, 2842,
11267, 9, 6498, 544, 2468, 339, 1381, 2525, 8112, 3584, 6958, 4989, 10616, 8011, 5374, 9452, 12159, 4354, 9893, 7837, 3296, 8340, 7222, 2197, 118, 2476, 5767, 827, 8541,
11336, 3434, 3529, 2908, 12071, 2361, 1843, 3030, 8174, 6147, 9842, 8326, 576, 10335, 10238, 10484, 9407, 11836, 5908, 418, 3772, 7515, 5429, 7552, 10996, 12133, 2767, 3969,
8298, 6413, 10008, 2031, 5333, 10800, 9789, 10706, 5942, 1263, 49, 5915, 10806, 11939, 10777, 1815, 5383, 3202, 4493, 6920, 10232, 1975, 8532, 2925, 347, 4754, 1858, 11863,
8974, 9551, 5868, 9634, 5735,11566, 12115, 10596, 3009, 6190, 11994, 6523, 652, 3762, 9370, 4016, 4077, 8561, 4049, 5990, 11130, 11143, 948, 325, 1404, 6992, 6119, 8333,
10929, 1200, 5184, 2555, 6122, 1594, 10327, 7183, 5961, 2692, 12121, 4298, 3329, 5919, 4433, 8455,7032, 1747, 3123, 3054, 6803, 5782, 10723, 9341, 2503, 683, 2459, 3656,
64, 4240, 3570, 835, 6065, 4046, 11580, 10970, 3150, 10331, 4322, 2078, 1112, 4079, 11231, 441, 922, 1050, 4536, 6844, 8429, 2683, 11099, 3818, 6171, 8500, 12142, 6833, 4449,
4749, 6752, 7500, 7822, 8214, 6974, 7965, 7373, 2169, 522, 5079, 3262, 10316, 6715, 1278, 9945, 3514, 11248, 11271, 5925, 468, 3988, 382, 11973, 5339, 6843, 6196, 8579, 2033,
8291, 1922, 3879, 11035, 973, 6854, 10930, 5206, 6760, 3199, 56, 3565, 654, 1702, 10302, 5862, 6153, 5415, 8646, 11889, 10561, 7341, 6152, 7232, 4698, 8844, 4780, 10240, 4912,
1321, 12097, 7048, 2920, 3127, 4169, 11502, 3482, 11279, 5468, 5874, 11612, 6055, 8953, 52, 3174, 10966, 9523, 151, 2127, 3957, 2839, 9784, 6383, 1579, 431, 7507, 5886, 3029,
6695, 4213, 504, 11684, 2302, 8689, 9026, 4624, 6212, 11868, 4080, 6221, 8687, 1003, 8757, 241, 58, 5009, 10333, 885, 6281, 3438, 9445, 11314, 8077, 6608, 3477, 142, 1105,
8841, 343, 4538, 1908, 1208, 4727, 7078, 10423, 10125, 6873, 11573, 10179, 416, 814, 1705, 2450, 8700, 717, 9307, 1373, 8186, 2429, 10568, 10753, 7228, 11071, 438, 8774, 5993,
3278, 4209, 6877, 3449, 1136, 3708, 3238, 2926, 1826, 4489, 3171, 8024, 8611, 1928, 464, 3205, 8930, 7080, 1092, 10900, 10221, 11943, 4404, 9126, 4032, 7449, 6127, 8067, 10763,
125, 540, 8921, 8062, 612, 8051, 12229, 9572, 9089, 10754, 10029, 68, 6453, 7723, 4781, 4924, 1014, 448, 3942, 5232, 1327, 8682, 3744, 7326, 3056, 9761, 5845, 5588, 412, 7187,
3975, 4883, 3087, 6454, 2257, 7784, 5676, 1417, 8400, 11710, 5596, 5987, 9175, 2769, 5966, 212, 6555, 11113, 5508, 11014, 1125, 4860, 10844, 1131, 4267, 6636, 2275, 9828, 5063,
4176, 3765, 1518, 8794, 4564, 10224, 5826, 3534, 3961, 4145, 10533, 506, 11034, 6505, 10897, 2674, 10077, 3338, 9013, 3511, 6811, 11111, 2776, 1165, 2575, 8881, 10347, 377,
4578, 11914, 10669, 10104, 392, 10453, 425, 9489, 193, 2231, 6197, 1038, 11366, 6204, 8122, 2894, 3654, 10975, 10545, 6599, 2455, 11951, 3947, 20, 5002, 5163, 4608, 8946, 8170,
10138, 1522, 8665, 10397, 3344, 5598, 10964, 6565, 11260, 1945, 11041, 9847, 7174, 4939, 2148, 6330, 3959, 5797, 4913, 3528, 8054, 3825, 8914, 9998, 4335, 8896, 9342, 3982,
6680, 11653, 7790, 6617, 1737, 622, 10485, 10886, 6195, 7100, 1687, 406, 12143, 5268, 9389, 12050, 994, 7735, 5464, 7383, 4670, 512, 364, 9929, 3028, 5216, 5518, 1226, 7550,
8038, 7043, 7814, 11053, 3017, 3121, 7584, 2600, 11232, 6780, 12085, 5219, 1409, 9600, 4605, 8151, 12109, 463, 8882, 8308, 10821, 9247, 10945, 9806, 2054, 6203, 6643, 3120,
6105, 8348, 8536, 6919, 8753, 11007, 8717, 9457, 2021, 9060, 4730, 3929, 10583, 3723, 845, 1936, 7, 5054, 3154, 3285, 4360, 3805, 11522, 2213, 4153, 12239, 12073, 5526, 769,
4099, 3944, 5604, 5530, 11024, 9282, 2171, 3480, 7434, 8520, 3232, 11996, 9656, 1406, 2945, 5349, 7207, 4590, 11607, 11309, 5202, 844, 7082, 4050, 8016, 9068, 9694, 8452, 7000,
5662, 567, 2941, 8619, 3808, 4987, 2373, 5135, 63, 7605, 3360, 11839, 10345, 578, 6921, 7628, 510, 5386, 2622, 7806, 5703, 10783, 9224, 11379, 5900, 4719, 11538, 3502, 5789,
10631, 5618, 826, 5043, 3090, 10891, 9951, 7596, 2293, 11872, 6151, 3469, 4443, 8871, 1555, 1802, 5103, 1891, 1223, 2334, 7878, 1590, 881, 365, 1927, 11274, 4510, 9652, 2946,
6828, 1280, 614, 10918, 12265, 7250, 6742, 9804, 11385, 2276, 11307, 2593, 879, 7899, 8071, 3454, 8531, 3795, 9021, 5776, 1849, 7766, 7988, 457, 8, 530, 9663, 7785, 11511, 3578,
7592, 10588, 3466, 8972, 9757, 3332, 139, 2046, 2940, 10808, 9332, 874, 2301, 5650, 12119, 150, 648, 8000, 9982, 9416, 2827, 2434, 11498, 6481, 12268, 9754, 11169, 11823, 11259,
3821, 10608, 2929, 6263, 4649, 6320, 9687, 10388, 502, 5118, 8496, 6226, 10716, 8443, 7624, 6883, 9269, 6616, 8620, 5287, 944, 7519, 6125, 1882, 11249, 10254, 5410, 1251, 1790,
5275, 8449, 10447, 4113, 72, 2828, 4352, 7455, 2712, 11048, 7911, 3451, 4094, 6508, 3045, 11194, 2643, 1783, 7211, 4974, 7724, 9811, 9449, 3019, 4194, 2730, 6878, 10421, 2253,
4518, 9195, 7469, 11129, 9173, 12100, 1763, 2209, 9617, 5170, 865, 1279, 1694, 10759, 8420, 4423, 10555, 3815, 5832, 10939
};


const int32_t MSRLN_omegainv_rev_ntt1024_12289[1024] = {
8193, 11796, 2381, 5444, 11854, 4337, 1912, 10911, 7012, 1168, 9041, 11082, 4645, 11885, 11224, 2143, 7313, 10682, 8509, 11414, 5088, 8005, 5011, 11287, 2566, 2187, 6039, 2422,
6267, 9302, 8643, 9852, 8456, 3778, 773, 11899, 442, 9888, 11222, 5101, 9430, 1045, 2481, 5012, 7428, 354, 6591, 9377, 1440, 8526, 27, 9223, 1017, 7404, 1632, 7205, 11744, 7270,
2678, 8585, 10752, 12047, 7575, 4143, 8758, 11813, 7384, 3985, 11869, 6730, 10745, 10111, 8889, 2399, 9153, 5191, 671, 3000, 243, 9273, 3247, 2686, 3978, 2969, 2370, 9424, 6957,
8779, 1630, 10163, 5407, 3186, 11136, 9405, 10040, 8241, 113, 4919, 8374, 2166, 3, 7852, 9140, 12129, 5291, 2704, 4938, 8653, 1663, 10512, 7635, 1426, 9018, 8232, 8925, 10600, 4372,
10115, 2847, 4414, 9644, 4053, 7247, 9984, 10805, 7394, 5195, 9509, 953, 3748, 11462, 6522, 9813, 12171, 10092, 5067, 3949, 8993, 4452, 2396, 7935, 130, 2837, 6915, 4278, 1673, 7300,
5331, 8705, 4177, 9764, 10908, 11950, 9821, 11745, 5791, 12280, 1022, 9447, 480, 3241, 11560, 10276, 3289, 10200, 5092, 9408, 9005, 10593, 1428, 2426, 334, 1260, 4388, 4632, 6534,
145, 6747, 3459, 8652, 7399, 6378, 8357, 2731, 2548, 4231, 355, 3382, 5179, 8595, 3707, 10530, 6429, 3195, 10643, 1212, 3542, 8785, 9744, 3621, 12288, 1479, 5146, 8246, 1305, 11567,
6553, 4134, 4978, 10938, 5777, 8961, 4591, 5728, 6461, 5023, 2639, 4821, 11340, 2625, 9314, 563, 9545, 3006, 3553, 4805, 2294, 11227, 8577, 9154, 4846, 9542, 11499, 955, 9970, 1170,
10963, 7203, 3201, 9275, 140, 1853, 4611, 726, 1635, 2768, 4255, 11112, 7969, 11289, 12208, 9198, 9238, 2366, 7393, 2963, 11184, 12147, 8812, 5681, 4212, 975, 2844, 8851, 6008, 11404,
1956, 7280, 12231, 12048, 3532, 11286, 3602, 6068, 8209, 421, 6077, 7665, 3263, 3600, 9987, 605, 11785, 8076, 5594, 9260, 6403, 4782, 11858, 10710, 5906, 2505, 9450, 8332, 10162,
12138, 2766, 1323, 9115, 12237, 3336, 6234, 677, 6415, 6821, 1010, 8807, 787, 8120, 9162, 9369, 5241, 192, 10968, 7377, 2049, 7509, 3445, 7591, 5057, 6137, 4948, 1728, 400, 3643,
6874, 6136, 6427, 1987, 10587, 11635, 8724, 12233, 9090, 5529, 7083, 1359, 5435, 11316, 1254, 8410, 10367, 3998, 10256, 3710, 6093, 5446, 6950, 316, 11907, 8301, 11821, 6364, 1018,
1041, 8775, 2344, 11011, 5574, 1973, 9027, 7210, 11767, 10120, 4916, 4324, 5315, 4075, 4467, 4789, 5537, 7540, 7840, 5456, 147, 3789, 6118, 8471, 1190, 9606, 3860, 5445, 7753, 11239,
11367, 11848, 1058, 8210, 11177, 10211, 7967, 1958, 9139, 1319, 709, 8243, 6224, 11454, 8719, 8049, 12225, 8633, 9830, 11606, 9786, 2948, 1566, 6507, 5486, 9235, 9166, 10542, 5257,
3834, 7856, 6370, 8960, 7991, 168, 9597, 6328, 5106, 1962, 10695, 6167, 9734, 7105, 11089, 1360, 3956, 6170, 5297, 10885, 11964, 11341, 1146, 1159, 6299, 8240, 3728, 8212, 8273, 2919,
8527, 11637, 5766, 295, 6099, 9280, 1693, 174, 723, 6554, 2655, 6421, 2738, 3315, 426, 10431, 7535, 11942, 9364, 3757, 10314, 2057, 5369, 7796, 9087, 6906, 10474, 1512, 350, 1483,
6374, 12240, 11026, 6347, 1583, 2500, 1489, 6956, 10258, 2281, 5876, 3991, 8320, 9522, 156, 1293, 4737, 6860, 4774, 8517, 11871, 6381, 453, 2882, 1805, 2051, 1954, 11713, 3963, 2447,
6142, 4115, 9259, 10446, 9928, 218, 9381, 8760, 8855, 1350, 6457, 8474, 1734, 7866, 3869, 1530, 10595, 11010, 11424, 7119, 2672, 10080, 10526, 189, 3116, 1160, 4820, 3094, 7771, 10036,
1868, 5411, 9559, 8095, 9270, 2840, 2478, 4565, 7315, 5078, 10506, 9646, 1095, 9244, 5781, 8195, 8838, 4378, 1241, 9577, 4834, 7937, 9461, 12217, 8176, 1842, 3840, 7014, 10499, 11038,
6879, 2035, 1040, 10407, 6164, 4770, 11345, 7002, 3669, 5673, 3020, 5406, 4665, 3846, 1573, 6063, 3793, 7171, 11787, 1901, 2602, 5969, 7640, 6026, 9360, 1681, 8468, 1030, 466, 1120,
2535, 21, 5808, 791, 9855, 9462, 2873, 2307, 4289, 11641, 12139, 170, 6639, 9988, 11415, 2957, 1481, 9349, 10243, 12150, 8957, 2532, 3317, 8823, 1701, 4697, 8711, 778, 4504, 2626,
11759, 12281, 11832, 4301, 4523, 10440, 6513, 3268, 8494, 3758, 8835, 4218, 4390, 11410, 9696, 982, 10013, 904, 2485, 5547, 5039, 24, 1371, 11675, 11009, 5461, 9343, 2637, 7779, 1015,
10362, 11924, 11408, 10699, 4411, 9955, 11066, 10398, 7186, 10487, 10734, 3418, 7846, 8820, 6138, 417, 9996, 4693, 2338, 1398, 9199, 7246, 11463, 6671, 1658, 6500, 8787, 751, 7570,
6389, 910, 3065, 1506, 6586, 4483, 9667, 6903, 11779, 4661, 5368, 11711, 1944, 450, 8929, 4684, 12226, 7154, 9916, 7302, 8481, 3670, 9348, 11722, 6627, 5289, 3837, 2595, 3221, 4273,
8239, 5207, 11445, 7087, 980, 682, 7699, 5082, 6940, 9344, 10883, 2633, 293, 9057, 3769, 4855, 8809, 10118, 3007, 1265, 6759, 6685, 8345, 8190, 11520, 6763, 216, 50, 8136, 10076, 767,
8484, 7929, 9004, 9135, 7235, 12282, 10353, 11444, 8566, 1706, 8360, 7559, 3229, 10268, 2832, 3572, 1282, 3536, 5370, 3753, 3941, 6184, 9169, 5646, 6086, 10235, 2483, 1344, 3042, 1468,
3981, 3407, 11826, 180, 4138, 7684, 2689, 10880, 7070, 204, 5509, 1057, 9689, 4705, 9168, 9272, 1236, 4475, 5246, 4251, 4739, 11063, 6771, 7073, 9261, 2360, 11925, 11777, 7619, 4906,
6825, 4554, 11295, 239, 2900, 7021, 146, 11883, 10602, 5189, 6094, 1403, 1804, 11667, 10552, 5672, 4499, 636, 5609, 8307, 2947, 3393, 7954, 2291, 3375, 8464, 4235, 8761, 7376, 6492,
8330, 5959, 10141, 7350, 5115, 2442, 1248, 10344, 1029, 5724, 1325, 6691, 8945, 1892, 3624, 10767, 2151, 4119, 3343, 7681, 7126, 7287, 12269, 8342, 338, 9834, 5690, 1744, 1314, 8635,
9395, 4167, 6085, 923, 11251, 6092, 10058, 12096, 2800, 11864, 1836, 11897, 2185, 1620, 375, 7711, 11912, 1942, 3408, 9714, 11124, 9513, 1178, 5478, 8778, 3276, 8951, 2212, 9615, 1392,
5784, 1255, 11783, 1756, 8144, 8328, 8755, 6463, 2065, 7725, 3495, 10771, 8524, 8113, 7226, 2461, 10014, 5653, 8022, 11158, 1445, 7429, 11164, 1275, 6781, 1176, 5734, 12077, 6323, 9520,
3114, 6302, 6693, 579, 3889, 10872, 6613, 4505, 10032, 5835, 9202, 7406, 8314, 5102, 11877, 6701, 6444, 2528, 9233, 4963, 8545, 3607, 10962, 7057, 8347, 11841, 11275, 7365, 7508, 4566,
5836, 12221, 2260, 1535, 3200, 2717, 60, 4238, 11677, 4227, 3368, 11749, 12164, 1526, 4222, 6162, 4840, 8257, 3163, 7885, 346, 2068, 1389, 11197, 5209, 3359, 9084, 11825, 10361, 3678,
4265, 9118, 7800, 10463, 9363, 9051, 8581, 11153, 8840, 5412, 8080, 9011, 6296, 3515, 11851, 1218, 5061, 1536, 1721, 9860, 4103, 10916, 2982, 11572, 3589, 9839, 10584, 11475, 11873,
2110, 716, 5416, 2164, 1866, 5211, 7562, 11081, 10381, 7751, 11946, 3448
};


const int32_t MSRLN_psi_rev_ntt512_12289[512] = {
8193, 493, 6845, 9908, 1378, 10377, 7952, 435, 10146, 1065, 404, 7644, 1207, 3248, 11121, 5277, 2437, 3646, 2987, 6022, 9867, 6250, 10102, 9723, 1002, 7278, 4284, 7201, 875, 3780, 1607,
4976, 8146, 4714, 242, 1537, 3704, 9611, 5019, 545, 5084, 10657, 4885, 11272, 3066, 12262, 3763, 10849, 2912, 5698, 11935, 4861, 7277, 9808, 11244, 2859, 7188, 1067, 2401, 11847, 390,
11516, 8511, 3833, 2780, 7094, 4895, 1484, 2305, 5042, 8236, 2645, 7875, 9442, 2174, 7917, 1689, 3364, 4057, 3271, 10863, 4654, 1777, 10626, 3636, 7351, 9585, 6998, 160, 3149, 4437,
12286, 10123, 3915, 7370, 12176, 4048, 2249, 2884, 1153, 9103, 6882, 2126, 10659, 3510, 5332, 2865, 9919, 9320, 8311, 9603, 9042, 3016, 12046, 9289, 11618, 7098, 3136, 9890, 3400, 2178,
1544, 5559, 420, 8304, 4905, 476, 3531, 9326, 4896, 9923, 3051, 3091, 81, 1000, 4320, 1177, 8034, 9521, 10654, 11563, 7678, 10436, 12149, 3014, 9088, 5086, 1326, 11119, 2319, 11334, 790,
2747, 7443, 3135, 3712, 1062, 9995, 7484, 8736, 9283, 2744, 11726, 2975, 9664, 949, 7468, 9650, 7266, 5828, 6561, 7698, 3328, 6512, 1351, 7311, 8155, 5736, 722, 10984, 4043, 7143, 10810,
1, 8668, 2545, 3504, 8747, 11077, 1646, 9094, 5860, 1759, 8582, 3694, 7110, 8907, 11934, 8058, 9741, 9558, 3932, 5911, 4890, 3637, 8830, 5542, 12144, 5755, 7657, 7901, 11029, 11955, 9863,
10861, 1696, 3284, 2881, 7197, 2089, 9000, 2013, 729, 9048, 11809, 2842, 11267, 9, 6498, 544, 2468, 339, 1381, 2525, 8112, 3584, 6958, 4989, 10616, 8011, 5374, 9452, 12159, 4354, 9893,
7837, 3296, 8340, 7222, 2197, 118, 2476, 5767, 827, 8541, 11336, 8855, 8760, 9381, 218, 9928, 10446, 9259, 4115, 6142, 2447, 3963, 11713, 1954, 2051, 1805, 2882, 453, 6381, 11871, 8517,
4774, 6860, 4737, 1293, 156, 9522, 8320, 3991, 5876, 2281, 10258, 6956, 1489, 2500, 1583, 6347, 11026, 12240, 6374, 1483, 350, 1512, 10474, 6906, 9087, 7796, 5369, 2057, 10314, 3757,
9364, 11942, 7535, 10431, 426, 3315, 2738, 6421, 2655, 6554, 723, 174, 1693, 9280, 6099, 295, 5766, 11637, 8527, 2919, 8273, 8212, 3728, 8240, 6299, 1159, 1146, 11341, 11964, 10885, 5297,
6170, 3956, 1360, 11089, 7105, 9734, 6167, 10695, 1962, 5106, 6328, 9597, 168, 7991, 8960, 6370, 7856, 3834, 5257, 10542, 9166, 9235, 5486, 6507, 1566, 2948, 9786, 11606, 9830, 8633,
12225, 8049, 8719, 11454, 6224, 8243, 709, 1319, 9139, 1958, 7967, 10211, 11177, 8210, 1058, 11848, 11367, 11239, 7753, 5445, 3860, 9606, 1190, 8471, 6118, 3789, 147, 5456, 7840, 7540,
5537, 4789, 4467, 4075, 5315, 4324, 4916, 10120, 11767, 7210, 9027, 1973, 5574, 11011, 2344, 8775, 1041, 1018, 6364, 11821, 8301, 11907, 316, 6950, 5446, 6093, 3710, 10256, 3998, 10367,
8410, 1254, 11316, 5435, 1359, 7083, 5529, 9090, 12233, 8724, 11635, 10587, 1987, 6427, 6136, 6874, 3643, 400, 1728, 4948, 6137, 5057, 7591, 3445, 7509, 2049, 7377, 10968, 192, 5241, 9369,
9162, 8120, 787, 8807, 1010, 6821, 6415, 677, 6234, 3336, 12237, 9115, 1323, 2766, 12138, 10162, 8332, 9450, 2505, 5906, 10710, 11858, 4782, 6403, 9260, 5594, 8076, 11785, 605, 9987, 3600,
3263, 7665, 6077, 421, 8209, 6068, 3602, 11286, 3532, 12048, 12231, 7280, 1956, 11404, 6008, 8851, 2844, 975, 4212, 5681, 8812, 12147, 11184
};


const int32_t MSRLN_omegainv_rev_ntt512_12289[512] = {
8193, 11796, 2381, 5444, 11854, 4337, 1912, 10911, 7012, 1168, 9041, 11082, 4645, 11885, 11224, 2143, 7313, 10682, 8509, 11414, 5088, 8005, 5011, 11287, 2566, 2187, 6039, 2422, 6267, 9302,
8643, 9852, 8456, 3778, 773, 11899, 442, 9888, 11222, 5101, 9430, 1045, 2481, 5012, 7428, 354, 6591, 9377, 1440, 8526, 27, 9223, 1017, 7404, 1632, 7205, 11744, 7270, 2678, 8585, 10752,
12047, 7575, 4143, 8758, 11813, 7384, 3985, 11869, 6730, 10745, 10111, 8889, 2399, 9153, 5191, 671, 3000, 243, 9273, 3247, 2686, 3978, 2969, 2370, 9424, 6957, 8779, 1630, 10163, 5407, 3186,
11136, 9405, 10040, 8241, 113, 4919, 8374, 2166, 3, 7852, 9140, 12129, 5291, 2704, 4938, 8653, 1663, 10512, 7635, 1426, 9018, 8232, 8925, 10600, 4372, 10115, 2847, 4414, 9644, 4053, 7247,
9984, 10805, 7394, 5195, 9509, 953, 3748, 11462, 6522, 9813, 12171, 10092, 5067, 3949, 8993, 4452, 2396, 7935, 130, 2837, 6915, 4278, 1673, 7300, 5331, 8705, 4177, 9764, 10908, 11950, 9821,
11745, 5791, 12280, 1022, 9447, 480, 3241, 11560, 10276, 3289, 10200, 5092, 9408, 9005, 10593, 1428, 2426, 334, 1260, 4388, 4632, 6534, 145, 6747, 3459, 8652, 7399, 6378, 8357, 2731, 2548,
4231, 355, 3382, 5179, 8595, 3707, 10530, 6429, 3195, 10643, 1212, 3542, 8785, 9744, 3621, 12288, 1479, 5146, 8246, 1305, 11567, 6553, 4134, 4978, 10938, 5777, 8961, 4591, 5728, 6461, 5023,
2639, 4821, 11340, 2625, 9314, 563, 9545, 3006, 3553, 4805, 2294, 11227, 8577, 9154, 4846, 9542, 11499, 955, 9970, 1170, 10963, 7203, 3201, 9275, 140, 1853, 4611, 726, 1635, 2768, 4255,
11112, 7969, 11289, 12208, 9198, 9238, 2366, 7393, 2963, 1105, 142, 3477, 6608, 8077, 11314, 9445, 3438, 6281, 885, 10333, 5009, 58, 241, 8757, 1003, 8687, 6221, 4080, 11868, 6212, 4624,
9026, 8689, 2302, 11684, 504, 4213, 6695, 3029, 5886, 7507, 431, 1579, 6383, 9784, 2839, 3957, 2127, 151, 9523, 10966, 3174, 52, 8953, 6055, 11612, 5874, 5468, 11279, 3482, 11502, 4169,
3127, 2920, 7048, 12097, 1321, 4912, 10240, 4780, 8844, 4698, 7232, 6152, 7341, 10561, 11889, 8646, 5415, 6153, 5862, 10302, 1702, 654, 3565, 56, 3199, 6760, 5206, 10930, 6854, 973, 11035,
3879, 1922, 8291, 2033, 8579, 6196, 6843, 5339, 11973, 382, 3988, 468, 5925, 11271, 11248, 3514, 9945, 1278, 6715, 10316, 3262, 5079, 522, 2169, 7373, 7965, 6974, 8214, 7822, 7500, 6752,
4749, 4449, 6833, 12142, 8500, 6171, 3818, 11099, 2683, 8429, 6844, 4536, 1050, 922, 441, 11231, 4079, 1112, 2078, 4322, 10331, 3150, 10970, 11580, 4046, 6065, 835, 3570, 4240, 64, 3656,
2459, 683, 2503, 9341, 10723, 5782, 6803, 3054, 3123, 1747, 7032, 8455, 4433, 5919, 3329, 4298, 12121, 2692, 5961, 7183, 10327, 1594, 6122, 2555, 5184, 1200, 10929, 8333, 6119, 6992, 1404,
325, 948, 11143, 11130, 5990, 4049, 8561, 4077, 4016, 9370, 3762, 652, 6523, 11994, 6190, 3009, 10596, 12115, 11566, 5735, 9634, 5868, 9551, 8974, 11863, 1858, 4754, 347, 2925, 8532, 1975,
10232, 6920, 4493, 3202, 5383, 1815, 10777, 11939, 10806, 5915, 49, 1263, 5942, 10706, 9789, 10800, 5333, 2031, 10008, 6413, 8298, 3969, 2767, 12133, 10996, 7552, 5429, 7515, 3772, 418, 5908,
11836, 9407, 10484, 10238, 10335, 576, 8326, 9842, 6147, 8174, 3030, 1843, 2361, 12071, 2908, 3529, 3434
};

// import external code
#ifdef RLWE_ASM_AVX2
    #include "AMD64/consts.c"
    #include "AMD64/ntt_x64.c"
#else
    #include "generic/ntt.c"
#endif

__inline void clear_words(void* mem, digit_t nwords)
{ // Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
  // This function uses the volatile type qualifier to inform the compiler not to optimize out the memory clearing.
    unsigned int i;
    volatile digit_t *v = mem; 

    for (i = 0; i < nwords; i++) {
        v[i] = 0;
    }
}


CRYPTO_MSRLN_STATUS LatticeCrypto_initialize(PLatticeCryptoStruct pLatticeCrypto, RandomBytes RandomBytesFunction, ExtendableOutput ExtendableOutputFunction, StreamOutput StreamOutputFunction)
{ // Initialize structure pLatticeCrypto with user-provided functions: RandomBytesFunction, ExtendableOutputFunction and StreamOutputFunction.

    pLatticeCrypto->RandomBytesFunction = RandomBytesFunction;
    pLatticeCrypto->ExtendableOutputFunction = ExtendableOutputFunction;
    pLatticeCrypto->StreamOutputFunction = StreamOutputFunction;

    return CRYPTO_MSRLN_SUCCESS;
}


PLatticeCryptoStruct LatticeCrypto_allocate()
{ // Dynamic allocation of memory for LatticeCrypto structure. It should be called before initialization with LatticeCrypto_initialize(). 
  // Returns NULL on error.
    PLatticeCryptoStruct LatticeCrypto = NULL;

    LatticeCrypto = (PLatticeCryptoStruct)calloc(1, sizeof(LatticeCryptoStruct));

    if (LatticeCrypto == NULL) {
        return NULL;
    }
    return LatticeCrypto;
}


const char* LatticeCrypto_get_error_message(CRYPTO_MSRLN_STATUS Status)
{ // Output error/success message for a given CRYPTO_STATUS
    struct error_mapping {
        unsigned int index;
        char*        string;
    } mapping[CRYPTO_STATUS_TYPE_SIZE] = {
        {CRYPTO_MSRLN_SUCCESS, CRYPTO_MSG_SUCCESS},
        {CRYPTO_MSRLN_ERROR, CRYPTO_MSG_ERROR},
        {CRYPTO_MSRLN_ERROR_DURING_TEST, CRYPTO_MSG_ERROR_DURING_TEST},
        {CRYPTO_MSRLN_ERROR_UNKNOWN, CRYPTO_MSG_ERROR_UNKNOWN},
        {CRYPTO_MSRLN_ERROR_NOT_IMPLEMENTED, CRYPTO_MSG_ERROR_NOT_IMPLEMENTED},
        {CRYPTO_MSRLN_ERROR_NO_MEMORY, CRYPTO_MSG_ERROR_NO_MEMORY},
        {CRYPTO_MSRLN_ERROR_INVALID_PARAMETER, CRYPTO_MSG_ERROR_INVALID_PARAMETER},
        {CRYPTO_MSRLN_ERROR_SHARED_KEY, CRYPTO_MSG_ERROR_SHARED_KEY},
        {CRYPTO_MSRLN_ERROR_TOO_MANY_ITERATIONS, CRYPTO_MSG_ERROR_TOO_MANY_ITERATIONS}
    };

    if (Status >= CRYPTO_STATUS_TYPE_SIZE || mapping[Status].string == NULL) {
        return "Unrecognized CRYPTO_STATUS";
    } else {
        return mapping[Status].string;
    }
};


void encode_A(const uint32_t* pk, const unsigned char* seed, unsigned char* m)
{ // Alice's message encoding
    unsigned int i = 0, j;
        
#if defined(GENERIC_IMPLEMENTATION)
    for (j = 0; j < 1024; j += 4) {        
        m[i]   = (unsigned char)(pk[j] & 0xFF);
        m[i+1] = (unsigned char)((pk[j] >> 8) | ((pk[j+1] & 0x03) << 6));
        m[i+2] = (unsigned char)((pk[j+1] >> 2) & 0xFF);
        m[i+3] = (unsigned char)((pk[j+1] >> 10) | ((pk[j+2] & 0x0F) << 4));
        m[i+4] = (unsigned char)((pk[j+2] >> 4) & 0xFF);
        m[i+5] = (unsigned char)((pk[j+2] >> 12) | ((pk[j+3] & 0x3F) << 2));
        m[i+6] = (unsigned char)(pk[j+3] >> 6);
        i += 7;
    }
    
#elif defined(ASM_SUPPORT) && (SIMD_SUPPORT == AVX2_SUPPORT) 
    encode_asm(pk, m);
    i = 1792;
#endif

    for (j = 0; j < 32; j++) {
        m[i+j] = seed[j];
    }
}


void decode_A(const unsigned char* m, uint32_t *pk, unsigned char* seed)
{ // Alice's message decoding 
    unsigned int i = 0, j;
    
#if defined(GENERIC_IMPLEMENTATION)
    for (j = 0; j < 1024; j += 4) {        
        pk[j]   = ((uint32_t)m[i] | (((uint32_t)m[i+1] & 0x3F) << 8));
        pk[j+1] = (((uint32_t)m[i+1] >> 6) | ((uint32_t)m[i+2] << 2) | (((uint32_t)m[i+3] & 0x0F) << 10));
        pk[j+2] = (((uint32_t)m[i+3] >> 4) | ((uint32_t)m[i+4] << 4) | (((uint32_t)m[i+5] & 0x03) << 12));
        pk[j+3] = (((uint32_t)m[i+5] >> 2) | ((uint32_t)m[i+6] << 6));
        i += 7;
    }
    
#elif defined(ASM_SUPPORT) && (SIMD_SUPPORT == AVX2_SUPPORT) 
    decode_asm(m, pk);
    i = 1792;
#endif

    for (j = 0; j < 32; j++) {
        seed[j] = m[i+j];
    }
}


void encode_B(const uint32_t* pk, const uint32_t* rvec, unsigned char* m)
{ // Bob's message encoding
    unsigned int i = 0, j;
    
#if defined(GENERIC_IMPLEMENTATION) 
    for (j = 0; j < 1024; j += 4) {        
        m[i]   = (unsigned char)(pk[j] & 0xFF);
        m[i+1] = (unsigned char)((pk[j] >> 8) | ((pk[j+1] & 0x03) << 6));
        m[i+2] = (unsigned char)((pk[j+1] >> 2) & 0xFF);
        m[i+3] = (unsigned char)((pk[j+1] >> 10) | ((pk[j+2] & 0x0F) << 4));
        m[i+4] = (unsigned char)((pk[j+2] >> 4) & 0xFF);
        m[i+5] = (unsigned char)((pk[j+2] >> 12) | ((pk[j+3] & 0x3F) << 2));
        m[i+6] = (unsigned char)(pk[j+3] >> 6);
        i += 7;
    }
    
#elif defined(ASM_SUPPORT) && (SIMD_SUPPORT == AVX2_SUPPORT) 
    encode_asm(pk, m);
#endif

    i = 0;
    for (j = 0; j < 1024/4; j++) {
        m[1792+j] = (unsigned char)(rvec[i] | (rvec[i+1] << 2) | (rvec[i+2] << 4) | (rvec[i+3] << 6));
        i += 4;
    }
}


void decode_B(unsigned char* m, uint32_t* pk, uint32_t* rvec)
{ // Bob's message decoding
    unsigned int i = 0, j;
    
#if defined(GENERIC_IMPLEMENTATION) 
    for (j = 0; j < 1024; j += 4) {        
        pk[j]   = ((uint32_t)m[i] | (((uint32_t)m[i+1] & 0x3F) << 8));
        pk[j+1] = (((uint32_t)m[i+1] >> 6) | ((uint32_t)m[i+2] << 2) | (((uint32_t)m[i+3] & 0x0F) << 10));
        pk[j+2] = (((uint32_t)m[i+3] >> 4) | ((uint32_t)m[i+4] << 4) | (((uint32_t)m[i+5] & 0x03) << 12));
        pk[j+3] = (((uint32_t)m[i+5] >> 2) | ((uint32_t)m[i+6] << 6));
        i += 7;
    }
    
#elif defined(ASM_SUPPORT) && (SIMD_SUPPORT == AVX2_SUPPORT) 
    decode_asm(m, pk);
    i = 1792;
#endif
    
    i = 0;
    for (j = 0; j < 1024/4; j++) {
        rvec[i]   = (uint32_t)(m[1792+j] & 0x03);
        rvec[i+1] = (uint32_t)((m[1792+j] >> 2) & 0x03);
        rvec[i+2] = (uint32_t)((m[1792+j] >> 4) & 0x03);
        rvec[i+3] = (uint32_t)(m[1792+j] >> 6);
        i += 4;
    }
}


static __inline uint32_t Abs(int32_t value)
{ // Compute absolute value
    uint32_t mask;

    mask = (uint32_t)(value >> 31);
    return ((mask ^ value) - mask);
}


CRYPTO_MSRLN_STATUS HelpRec(const uint32_t* x, uint32_t* rvec, const unsigned char* seed, unsigned int nonce, StreamOutput StreamOutputFunction)
{ // Reconciliation helper
    (void)seed; (void)nonce; (void)StreamOutputFunction;
    unsigned int i, j, norm;
    unsigned char bit, random_bits[32];
    uint32_t v0[4], v1[4];

    randombytes( random_bits, 32);
    CRYPTO_MSRLN_STATUS Status = CRYPTO_MSRLN_SUCCESS;

#if defined(ASM_SUPPORT) && (SIMD_SUPPORT == AVX2_SUPPORT)         
    helprec_asm(x, rvec, random_bits);
#else   

    for (i = 0; i < 256; i++) {
        bit = 1 & (random_bits[i >> 3] >> (i & 0x07));
        rvec[i]     = (x[i]     << 1) - bit;  
        rvec[i+256] = (x[i+256] << 1) - bit;
        rvec[i+512] = (x[i+512] << 1) - bit;
        rvec[i+768] = (x[i+768] << 1) - bit; 

        norm = 0;
        v0[0] = 4; v0[1] = 4; v0[2] = 4; v0[3] = 4;
        v1[0] = 3; v1[1] = 3; v1[2] = 3; v1[3] = 3; 
        for (j = 0; j < 4; j++) {
            v0[j] -= (rvec[i+256*j] - PARAMETER_Q4 ) >> 31;
            v0[j] -= (rvec[i+256*j] - PARAMETER_3Q4) >> 31;
            v0[j] -= (rvec[i+256*j] - PARAMETER_5Q4) >> 31;
            v0[j] -= (rvec[i+256*j] - PARAMETER_7Q4) >> 31;
            v1[j] -= (rvec[i+256*j] - PARAMETER_Q2 ) >> 31;
            v1[j] -= (rvec[i+256*j] - PARAMETER_Q  ) >> 31;
            v1[j] -= (rvec[i+256*j] - PARAMETER_3Q2) >> 31;
            norm += Abs(2*rvec[i+256*j] - PARAMETER_Q*v0[j]);
        }

        norm = (uint32_t)((int32_t)(norm - PARAMETER_Q) >> 31);    // If norm < q then norm = 0xff...ff, else norm = 0
        v0[0] = (norm & (v0[0] ^ v1[0])) ^ v1[0];
        v0[1] = (norm & (v0[1] ^ v1[1])) ^ v1[1];
        v0[2] = (norm & (v0[2] ^ v1[2])) ^ v1[2];
        v0[3] = (norm & (v0[3] ^ v1[3])) ^ v1[3];
        rvec[i]     = (v0[0] - v0[3]) & 0x03;
        rvec[i+256] = (v0[1] - v0[3]) & 0x03;
        rvec[i+512] = (v0[2] - v0[3]) & 0x03;
        rvec[i+768] = ((v0[3] << 1) + (1 & ~norm)) & 0x03;
    }
#endif

    return Status;
}


static __inline uint32_t LDDecode(int32_t* t)
{ // Low-density decoding
    unsigned int i, norm = 0;
    uint32_t mask1, mask2, value;
    int32_t cneg = -8*PARAMETER_Q;
    
    for (i = 0; i < 4; i++) { 
        mask1 = t[i] >> 31;                                    // If t[i] < 0 then mask2 = 0xff...ff, else mask2 = 0
        mask2 = (4*PARAMETER_Q - (int32_t)Abs(t[i])) >> 31;    // If 4*PARAMETER_Q > Abs(t[i]) then mask2 = 0, else mask2 = 0xff...ff

        value = ((mask1 & (8*PARAMETER_Q ^ cneg)) ^ cneg);
        norm += Abs(t[i] + (mask2 & value));
    }

    return ((8*PARAMETER_Q - norm) >> 31) ^ 1;                 // If norm < PARAMETER_Q then return 1, else return 0
}


void Rec(const uint32_t *x, const uint32_t* rvec, unsigned char *key)               
{ // Reconciliation

#if defined(GENERIC_IMPLEMENTATION)
    unsigned int i;
    uint32_t t[4];

    for (i = 0; i < 32; i++) {
        key[i] = 0;
    }
    for (i = 0; i < 256; i++) {        
        t[0] = 8*x[i]     - (2*rvec[i] + rvec[i+768]) * PARAMETER_Q;
        t[1] = 8*x[i+256] - (2*rvec[i+256] + rvec[i+768]) * PARAMETER_Q;
        t[2] = 8*x[i+512] - (2*rvec[i+512] + rvec[i+768]) * PARAMETER_Q;
        t[3] = 8*x[i+768] - (rvec[i+768]) * PARAMETER_Q;
      
        key[i >> 3] |= (unsigned char)LDDecode((int32_t*)t) << (i & 0x07);
    }
    
#elif defined(ASM_SUPPORT) && (SIMD_SUPPORT == AVX2_SUPPORT) 
    rec_asm(x, rvec, key);
#endif
}


CRYPTO_MSRLN_STATUS get_error(int32_t* e, unsigned char* seed, unsigned int nonce, StreamOutput StreamOutputFunction)
{ // Error sampling
    (void) seed; (void) nonce; (void) StreamOutputFunction;
    uint32_t stream[3 * PARAMETER_N / sizeof(uint32_t)];
    uint32_t *pstream = (uint32_t *) &stream;
    uint32_t acc1, acc2, temp;
    uint8_t *pacc1 = (uint8_t *) &acc1, *pacc2 = (uint8_t *) &acc2;
    unsigned int i, j;

    randombytes( stream, 3 * PARAMETER_N);

#if defined(ASM_SUPPORT) && (SIMD_SUPPORT == AVX2_SUPPORT)
    error_sampling_asm(stream, e);
#else
    for (i = 0; i < PARAMETER_N / 4; i++) {
        acc1 = 0;
        acc2 = 0;
        for (j = 0; j < 8; j++) {
            acc1 += (pstream[i] >> j) & 0x01010101;
            acc2 += (pstream[i + PARAMETER_N / 4] >> j) & 0x01010101;
        }
        for (j = 0; j < 4; j++) {
            temp = pstream[i + 2 * PARAMETER_N / 4] >> j;
            acc1 += temp & 0x01010101;
            acc2 += (temp >> 4) & 0x01010101;
        }
        e[2 * i] = pacc1[0] - pacc1[1];
        e[2 * i + 1] = pacc1[2] - pacc1[3];
        e[2 * i + PARAMETER_N / 2] = pacc2[0] - pacc2[1];
        e[2 * i + PARAMETER_N / 2 + 1] = pacc2[2] - pacc2[3];
    }
#endif

    return CRYPTO_MSRLN_SUCCESS;    
}


CRYPTO_MSRLN_STATUS generate_a(uint32_t* a, const unsigned char* seed, ExtendableOutput ExtendableOutputFunction)
{ // Generation of parameter a
    (void)ExtendableOutputFunction;
    unsigned int pos = 0, ctr = 0;
    uint16_t val;
    unsigned int nblocks = 16;
    uint8_t buf[SHAKE128_RATE * 16]; // was * nblocks, but VS doesn't like this buf init
    //Keccak_HashInstance ks;

    uint64_t state[SHA3_STATESIZE] = {0};
    shake128_absorb(state, seed, SEED_BYTES);
    shake128_squeezeblocks((unsigned char *) buf, nblocks, state);

    /*#ifdef _WIN32
        SHAKE128_InitAbsorb( &ks, seed, SEED_BYTES );
        KECCAK_HashSqueeze( &ks, (unsigned char *) buf, nblocks * 8 );
    #else 
        Keccak_HashInitialize_SHAKE128(&ks);
        Keccak_HashUpdate( &ks, seed, SEED_BYTES * 8 );
        Keccak_HashFinal( &ks, seed );
        Keccak_HashSqueeze( &ks, (unsigned char *) buf, nblocks * 8 * 8 );
    //#endif
    */
    while (ctr < PARAMETER_N) {
        val = (buf[pos] | ((uint16_t) buf[pos + 1] << 8)) & 0x3fff;
        if (val < PARAMETER_Q) {
            a[ctr++] = val;
        }
        pos += 2;
        if (pos > SHAKE128_RATE * nblocks - 2) {
            nblocks = 1;
          shake128_squeezeblocks((unsigned char *) buf, nblocks, state);
//            Keccak_HashSqueeze( &ks, (unsigned char *) buf, nblocks * 8 * 8 );
            pos = 0;
        }
    }

    return CRYPTO_MSRLN_SUCCESS;    
}


CRYPTO_MSRLN_STATUS MSRLN_KeyGeneration_A(int32_t* SecretKeyA, unsigned char* PublicKeyA, PLatticeCryptoStruct pLatticeCrypto)
{ // Alice's key generation  
  // It produces a private key SecretKeyA and computes the public key PublicKeyA.
  // Outputs: the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
  //          the public key PublicKeyA that occupies 1824 bytes
  // pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
    uint32_t a[PARAMETER_N];
    int32_t e[PARAMETER_N];
    unsigned char seed[SEED_BYTES];
    unsigned char error_seed[ERROR_SEED_BYTES];
    CRYPTO_MSRLN_STATUS Status = CRYPTO_MSRLN_ERROR_UNKNOWN;

    Status = randombytes( seed, SEED_BYTES);

    if (Status != CRYPTO_MSRLN_SUCCESS) {
        return Status;
    }   

    Status = generate_a(a, seed, pLatticeCrypto->ExtendableOutputFunction);
    if (Status != CRYPTO_MSRLN_SUCCESS) {
        goto cleanup;
    }

    Status = get_error(SecretKeyA, error_seed, 0, pLatticeCrypto->StreamOutputFunction);  
    if (Status != CRYPTO_MSRLN_SUCCESS) {
        goto cleanup;
    }
    Status = get_error(e, error_seed, 1, pLatticeCrypto->StreamOutputFunction);   
    if (Status != CRYPTO_MSRLN_SUCCESS) {
        goto cleanup;
    }
    NTT_CT_std2rev_12289(SecretKeyA, MSRLN_psi_rev_ntt1024_12289, PARAMETER_N);
    NTT_CT_std2rev_12289(e, MSRLN_psi_rev_ntt1024_12289, PARAMETER_N);
    smul(e, 3, PARAMETER_N);

    pmuladd((int32_t*)a, SecretKeyA, e, (int32_t*)a, PARAMETER_N); 
    correction((int32_t*)a, PARAMETER_Q, PARAMETER_N);
    encode_A(a, seed, PublicKeyA);
    
cleanup:
    clear_words((void*)e, NBYTES_TO_NWORDS(4*PARAMETER_N));
    clear_words((void*)error_seed, NBYTES_TO_NWORDS(ERROR_SEED_BYTES));

    return Status;
}


CRYPTO_MSRLN_STATUS MSRLN_SecretAgreement_B(unsigned char* PublicKeyA, unsigned char* SharedSecretB, unsigned char* PublicKeyB, PLatticeCryptoStruct pLatticeCrypto)
{ // Bob's key generation and shared secret computation  
  // It produces a private key and computes the public key PublicKeyB. In combination with Alice's public key PublicKeyA, it computes 
  // the shared secret SharedSecretB.
  // Input:   Alice's public key PublicKeyA that consists of 1824 bytes
  // Outputs: the public key PublicKeyB that occupies 2048 bytes.
  //          the 256-bit shared secret SharedSecretB.
  // pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
    uint32_t pk_A[PARAMETER_N], a[PARAMETER_N], v[PARAMETER_N], r[PARAMETER_N];
    int32_t sk_B[PARAMETER_N], e[PARAMETER_N];
    unsigned char seed[SEED_BYTES], error_seed[ERROR_SEED_BYTES];
    CRYPTO_MSRLN_STATUS Status = CRYPTO_MSRLN_ERROR_UNKNOWN;

    decode_A(PublicKeyA, pk_A, seed);

    Status = generate_a(a, seed, pLatticeCrypto->ExtendableOutputFunction);
    if (Status != CRYPTO_MSRLN_SUCCESS) {
        goto cleanup;
    }

    Status = get_error(sk_B, error_seed, 0, pLatticeCrypto->StreamOutputFunction);  
    if (Status != CRYPTO_MSRLN_SUCCESS) {
        goto cleanup;
    }
    Status = get_error(e, error_seed, 1, pLatticeCrypto->StreamOutputFunction);
    if (Status != CRYPTO_MSRLN_SUCCESS) {
        goto cleanup;
    }   
    NTT_CT_std2rev_12289(sk_B, MSRLN_psi_rev_ntt1024_12289, PARAMETER_N);
    NTT_CT_std2rev_12289(e, MSRLN_psi_rev_ntt1024_12289, PARAMETER_N);
    smul(e, 3, PARAMETER_N);

    pmuladd((int32_t*)a, sk_B, e, (int32_t*)a, PARAMETER_N); 
    correction((int32_t*)a, PARAMETER_Q, PARAMETER_N);
     
    Status = get_error(e, error_seed, 2, pLatticeCrypto->StreamOutputFunction);  
    if (Status != CRYPTO_MSRLN_SUCCESS) {
        goto cleanup;
    }   
    NTT_CT_std2rev_12289(e, MSRLN_psi_rev_ntt1024_12289, PARAMETER_N);
    smul(e, 81, PARAMETER_N);
    
    pmuladd((int32_t*)pk_A, sk_B, e, (int32_t*)v, PARAMETER_N);    
    INTT_GS_rev2std_12289((int32_t*)v, MSRLN_omegainv_rev_ntt1024_12289, MSRLN_omegainv10N_rev_ntt1024_12289, MSRLN_Ninv11_ntt1024_12289, PARAMETER_N);
    two_reduce12289((int32_t*)v, PARAMETER_N);
#if defined(GENERIC_IMPLEMENTATION)
    correction((int32_t*)v, PARAMETER_Q, PARAMETER_N); 
#endif

    Status = HelpRec(v, r, error_seed, 3, pLatticeCrypto->StreamOutputFunction); 
    if (Status != CRYPTO_MSRLN_SUCCESS) {
        goto cleanup;
    }   
    Rec(v, r, SharedSecretB);
    encode_B(a, r, PublicKeyB);
    
cleanup:
    clear_words((void*)sk_B, NBYTES_TO_NWORDS(4*PARAMETER_N));
    clear_words((void*)e, NBYTES_TO_NWORDS(4*PARAMETER_N));
    clear_words((void*)error_seed, NBYTES_TO_NWORDS(ERROR_SEED_BYTES));
    clear_words((void*)a, NBYTES_TO_NWORDS(4*PARAMETER_N));
    clear_words((void*)v, NBYTES_TO_NWORDS(4*PARAMETER_N));
    clear_words((void*)r, NBYTES_TO_NWORDS(4*PARAMETER_N));

    return Status;
}


CRYPTO_MSRLN_STATUS MSRLN_SecretAgreement_A(unsigned char* PublicKeyB, int32_t* SecretKeyA, unsigned char* SharedSecretA)
{ // Alice's shared secret computation  
  // It computes the shared secret SharedSecretA using Bob's public key PublicKeyB and Alice's private key SecretKeyA.
  // Inputs: Bob's public key PublicKeyB that consists of 2048 bytes
  //         the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
  // Output: the 256-bit shared secret SharedSecretA.
  // pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
    uint32_t u[PARAMETER_N], r[PARAMETER_N];
    CRYPTO_MSRLN_STATUS Status = CRYPTO_MSRLN_SUCCESS;

    decode_B(PublicKeyB, u, r);
    
    pmul(SecretKeyA, (int32_t*)u, (int32_t*)u, PARAMETER_N);       
    INTT_GS_rev2std_12289((int32_t*)u, MSRLN_omegainv_rev_ntt1024_12289, MSRLN_omegainv10N_rev_ntt1024_12289, MSRLN_Ninv11_ntt1024_12289, PARAMETER_N);
    two_reduce12289((int32_t*)u, PARAMETER_N);
#if defined(GENERIC_IMPLEMENTATION)
    correction((int32_t*)u, PARAMETER_Q, PARAMETER_N); 
#endif

    Rec(u, r, SharedSecretA);
    
// Cleanup
    clear_words((void*)u, NBYTES_TO_NWORDS(4*PARAMETER_N));
    clear_words((void*)r, NBYTES_TO_NWORDS(4*PARAMETER_N));

    return Status;
}
