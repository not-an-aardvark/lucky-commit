void scatter_padding(ulong padding_specifier, __private uint* w);
void sha1_compress(__private uint* h, __private const uint* w);

__constant ulong PADDING_CHUNKS[256] = {
    0x2020202020202020, 0x2020200920202020, 0x2020092020202020, 0x2020090920202020,
    0x2009202020202020, 0x2009200920202020, 0x2009092020202020, 0x2009090920202020,
    0x0920202020202020, 0x0920200920202020, 0x0920092020202020, 0x0920090920202020,
    0x0909202020202020, 0x0909200920202020, 0x0909092020202020, 0x0909090920202020,
    0x2020202020202009, 0x2020200920202009, 0x2020092020202009, 0x2020090920202009,
    0x2009202020202009, 0x2009200920202009, 0x2009092020202009, 0x2009090920202009,
    0x0920202020202009, 0x0920200920202009, 0x0920092020202009, 0x0920090920202009,
    0x0909202020202009, 0x0909200920202009, 0x0909092020202009, 0x0909090920202009,
    0x2020202020200920, 0x2020200920200920, 0x2020092020200920, 0x2020090920200920,
    0x2009202020200920, 0x2009200920200920, 0x2009092020200920, 0x2009090920200920,
    0x0920202020200920, 0x0920200920200920, 0x0920092020200920, 0x0920090920200920,
    0x0909202020200920, 0x0909200920200920, 0x0909092020200920, 0x0909090920200920,
    0x2020202020200909, 0x2020200920200909, 0x2020092020200909, 0x2020090920200909,
    0x2009202020200909, 0x2009200920200909, 0x2009092020200909, 0x2009090920200909,
    0x0920202020200909, 0x0920200920200909, 0x0920092020200909, 0x0920090920200909,
    0x0909202020200909, 0x0909200920200909, 0x0909092020200909, 0x0909090920200909,
    0x2020202020092020, 0x2020200920092020, 0x2020092020092020, 0x2020090920092020,
    0x2009202020092020, 0x2009200920092020, 0x2009092020092020, 0x2009090920092020,
    0x0920202020092020, 0x0920200920092020, 0x0920092020092020, 0x0920090920092020,
    0x0909202020092020, 0x0909200920092020, 0x0909092020092020, 0x0909090920092020,
    0x2020202020092009, 0x2020200920092009, 0x2020092020092009, 0x2020090920092009,
    0x2009202020092009, 0x2009200920092009, 0x2009092020092009, 0x2009090920092009,
    0x0920202020092009, 0x0920200920092009, 0x0920092020092009, 0x0920090920092009,
    0x0909202020092009, 0x0909200920092009, 0x0909092020092009, 0x0909090920092009,
    0x2020202020090920, 0x2020200920090920, 0x2020092020090920, 0x2020090920090920,
    0x2009202020090920, 0x2009200920090920, 0x2009092020090920, 0x2009090920090920,
    0x0920202020090920, 0x0920200920090920, 0x0920092020090920, 0x0920090920090920,
    0x0909202020090920, 0x0909200920090920, 0x0909092020090920, 0x0909090920090920,
    0x2020202020090909, 0x2020200920090909, 0x2020092020090909, 0x2020090920090909,
    0x2009202020090909, 0x2009200920090909, 0x2009092020090909, 0x2009090920090909,
    0x0920202020090909, 0x0920200920090909, 0x0920092020090909, 0x0920090920090909,
    0x0909202020090909, 0x0909200920090909, 0x0909092020090909, 0x0909090920090909,
    0x2020202009202020, 0x2020200909202020, 0x2020092009202020, 0x2020090909202020,
    0x2009202009202020, 0x2009200909202020, 0x2009092009202020, 0x2009090909202020,
    0x0920202009202020, 0x0920200909202020, 0x0920092009202020, 0x0920090909202020,
    0x0909202009202020, 0x0909200909202020, 0x0909092009202020, 0x0909090909202020,
    0x2020202009202009, 0x2020200909202009, 0x2020092009202009, 0x2020090909202009,
    0x2009202009202009, 0x2009200909202009, 0x2009092009202009, 0x2009090909202009,
    0x0920202009202009, 0x0920200909202009, 0x0920092009202009, 0x0920090909202009,
    0x0909202009202009, 0x0909200909202009, 0x0909092009202009, 0x0909090909202009,
    0x2020202009200920, 0x2020200909200920, 0x2020092009200920, 0x2020090909200920,
    0x2009202009200920, 0x2009200909200920, 0x2009092009200920, 0x2009090909200920,
    0x0920202009200920, 0x0920200909200920, 0x0920092009200920, 0x0920090909200920,
    0x0909202009200920, 0x0909200909200920, 0x0909092009200920, 0x0909090909200920,
    0x2020202009200909, 0x2020200909200909, 0x2020092009200909, 0x2020090909200909,
    0x2009202009200909, 0x2009200909200909, 0x2009092009200909, 0x2009090909200909,
    0x0920202009200909, 0x0920200909200909, 0x0920092009200909, 0x0920090909200909,
    0x0909202009200909, 0x0909200909200909, 0x0909092009200909, 0x0909090909200909,
    0x2020202009092020, 0x2020200909092020, 0x2020092009092020, 0x2020090909092020,
    0x2009202009092020, 0x2009200909092020, 0x2009092009092020, 0x2009090909092020,
    0x0920202009092020, 0x0920200909092020, 0x0920092009092020, 0x0920090909092020,
    0x0909202009092020, 0x0909200909092020, 0x0909092009092020, 0x0909090909092020,
    0x2020202009092009, 0x2020200909092009, 0x2020092009092009, 0x2020090909092009,
    0x2009202009092009, 0x2009200909092009, 0x2009092009092009, 0x2009090909092009,
    0x0920202009092009, 0x0920200909092009, 0x0920092009092009, 0x0920090909092009,
    0x0909202009092009, 0x0909200909092009, 0x0909092009092009, 0x0909090909092009,
    0x2020202009090920, 0x2020200909090920, 0x2020092009090920, 0x2020090909090920,
    0x2009202009090920, 0x2009200909090920, 0x2009092009090920, 0x2009090909090920,
    0x0920202009090920, 0x0920200909090920, 0x0920092009090920, 0x0920090909090920,
    0x0909202009090920, 0x0909200909090920, 0x0909092009090920, 0x0909090909090920,
    0x2020202009090909, 0x2020200909090909, 0x2020092009090909, 0x2020090909090909,
    0x2009202009090909, 0x2009200909090909, 0x2009092009090909, 0x2009090909090909,
    0x0920202009090909, 0x0920200909090909, 0x0920092009090909, 0x0920090909090909,
    0x0909202009090909, 0x0909200909090909, 0x0909092009090909, 0x0909090909090909,
};

__kernel void scatter_padding_and_find_match(
    __global uint* desired_prefix_data,
    __global uint* desired_prefix_mask,
    __global uint* h,
    __global uchar* block_ending,
    ulong base_padding_specifier,
    __global ulong* successful_match_receiver
) {
    __private uint w[16];
    scatter_padding(base_padding_specifier + get_global_id(0), w);

    for (int i = 0; i < 4; i++) {
        w[i + 12] = as_uint(
            as_uchar4(
                ((uint*)block_ending)[i]
            ).s3210);
    }

    uint finalized_hash[5] = {h[0], h[1], h[2], h[3], h[4]};
    sha1_compress(finalized_hash, w);
    if (
        (finalized_hash[0] & desired_prefix_mask[0]) == desired_prefix_data[0] &&
        (finalized_hash[1] & desired_prefix_mask[1]) == desired_prefix_data[1] &&
        (finalized_hash[2] & desired_prefix_mask[2]) == desired_prefix_data[2] &&
        (finalized_hash[3] & desired_prefix_mask[3]) == desired_prefix_data[3] &&
        (finalized_hash[4] & desired_prefix_mask[4]) == desired_prefix_data[4]
    ) {
        *successful_match_receiver = base_padding_specifier + get_global_id(0);
    }
}

void scatter_padding(ulong padding_specifier, __private uint* w) {
    for (int i = 0; i < 6; i ++) {
        ((ulong*)w)[i] = PADDING_CHUNKS[((uchar*)&padding_specifier)[i]];
    }
}

/*
The sha1 implementation below is mostly adapted from hashcat (https://hashcat.net/hashcat).

The MIT License (MIT)

Copyright (c) 2015-2020 Jens Steube

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define SHA1_F1(x,y,z)  ((x) ^ (y) ^ (z))
#define SHA1_F0o(x,y,z) (bitselect((z), (y), (x)))
#define SHA1_F2o(x,y,z) (bitselect((x), (y), ((x) ^ (z))))

#define SHA1_STEP_S(f,a,b,c,d,e,x) \
{ \
    e += x + f(b, c, d) + K + rotate(a, 5u); \
    b = rotate(b, 30u); \
}

void sha1_compress(__private uint* h, __private const uint* w) {
    uint a = h[0];
    uint b = h[1];
    uint c = h[2];
    uint d = h[3];
    uint e = h[4];

    uint w0_t = w[0];
    uint w1_t = w[1];
    uint w2_t = w[2];
    uint w3_t = w[3];
    uint w4_t = w[4];
    uint w5_t = w[5];
    uint w6_t = w[6];
    uint w7_t = w[7];
    uint w8_t = w[8];
    uint w9_t = w[9];
    uint wa_t = w[10];
    uint wb_t = w[11];
    uint wc_t = w[12];
    uint wd_t = w[13];
    uint we_t = w[14];
    uint wf_t = w[15];

    #define K 0x5a827999

    SHA1_STEP_S(SHA1_F0o, a, b, c, d, e, w0_t);
    SHA1_STEP_S(SHA1_F0o, e, a, b, c, d, w1_t);
    SHA1_STEP_S(SHA1_F0o, d, e, a, b, c, w2_t);
    SHA1_STEP_S(SHA1_F0o, c, d, e, a, b, w3_t);
    SHA1_STEP_S(SHA1_F0o, b, c, d, e, a, w4_t);
    SHA1_STEP_S(SHA1_F0o, a, b, c, d, e, w5_t);
    SHA1_STEP_S(SHA1_F0o, e, a, b, c, d, w6_t);
    SHA1_STEP_S(SHA1_F0o, d, e, a, b, c, w7_t);
    SHA1_STEP_S(SHA1_F0o, c, d, e, a, b, w8_t);
    SHA1_STEP_S(SHA1_F0o, b, c, d, e, a, w9_t);
    SHA1_STEP_S(SHA1_F0o, a, b, c, d, e, wa_t);
    SHA1_STEP_S(SHA1_F0o, e, a, b, c, d, wb_t);
    SHA1_STEP_S(SHA1_F0o, d, e, a, b, c, wc_t);
    SHA1_STEP_S(SHA1_F0o, c, d, e, a, b, wd_t);
    SHA1_STEP_S(SHA1_F0o, b, c, d, e, a, we_t);
    SHA1_STEP_S(SHA1_F0o, a, b, c, d, e, wf_t);
    w0_t = rotate((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S(SHA1_F0o, e, a, b, c, d, w0_t);
    w1_t = rotate((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S(SHA1_F0o, d, e, a, b, c, w1_t);
    w2_t = rotate((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S(SHA1_F0o, c, d, e, a, b, w2_t);
    w3_t = rotate((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S(SHA1_F0o, b, c, d, e, a, w3_t);

    #undef K
    #define K 0x6ed9eba1

    w4_t = rotate((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S(SHA1_F1, a, b, c, d, e, w4_t);
    w5_t = rotate((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S(SHA1_F1, e, a, b, c, d, w5_t);
    w6_t = rotate((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S(SHA1_F1, d, e, a, b, c, w6_t);
    w7_t = rotate((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S(SHA1_F1, c, d, e, a, b, w7_t);
    w8_t = rotate((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S(SHA1_F1, b, c, d, e, a, w8_t);
    w9_t = rotate((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S(SHA1_F1, a, b, c, d, e, w9_t);
    wa_t = rotate((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S(SHA1_F1, e, a, b, c, d, wa_t);
    wb_t = rotate((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S(SHA1_F1, d, e, a, b, c, wb_t);
    wc_t = rotate((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S(SHA1_F1, c, d, e, a, b, wc_t);
    wd_t = rotate((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S(SHA1_F1, b, c, d, e, a, wd_t);
    we_t = rotate((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S(SHA1_F1, a, b, c, d, e, we_t);
    wf_t = rotate((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S(SHA1_F1, e, a, b, c, d, wf_t);
    w0_t = rotate((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S(SHA1_F1, d, e, a, b, c, w0_t);
    w1_t = rotate((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S(SHA1_F1, c, d, e, a, b, w1_t);
    w2_t = rotate((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S(SHA1_F1, b, c, d, e, a, w2_t);
    w3_t = rotate((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S(SHA1_F1, a, b, c, d, e, w3_t);
    w4_t = rotate((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S(SHA1_F1, e, a, b, c, d, w4_t);
    w5_t = rotate((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S(SHA1_F1, d, e, a, b, c, w5_t);
    w6_t = rotate((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S(SHA1_F1, c, d, e, a, b, w6_t);
    w7_t = rotate((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S(SHA1_F1, b, c, d, e, a, w7_t);

    #undef K
    #define K 0x8f1bbcdc

    w8_t = rotate((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S(SHA1_F2o, a, b, c, d, e, w8_t);
    w9_t = rotate((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S(SHA1_F2o, e, a, b, c, d, w9_t);
    wa_t = rotate((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S(SHA1_F2o, d, e, a, b, c, wa_t);
    wb_t = rotate((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S(SHA1_F2o, c, d, e, a, b, wb_t);
    wc_t = rotate((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S(SHA1_F2o, b, c, d, e, a, wc_t);
    wd_t = rotate((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S(SHA1_F2o, a, b, c, d, e, wd_t);
    we_t = rotate((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S(SHA1_F2o, e, a, b, c, d, we_t);
    wf_t = rotate((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S(SHA1_F2o, d, e, a, b, c, wf_t);
    w0_t = rotate((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S(SHA1_F2o, c, d, e, a, b, w0_t);
    w1_t = rotate((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S(SHA1_F2o, b, c, d, e, a, w1_t);
    w2_t = rotate((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S(SHA1_F2o, a, b, c, d, e, w2_t);
    w3_t = rotate((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S(SHA1_F2o, e, a, b, c, d, w3_t);
    w4_t = rotate((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S(SHA1_F2o, d, e, a, b, c, w4_t);
    w5_t = rotate((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S(SHA1_F2o, c, d, e, a, b, w5_t);
    w6_t = rotate((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S(SHA1_F2o, b, c, d, e, a, w6_t);
    w7_t = rotate((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S(SHA1_F2o, a, b, c, d, e, w7_t);
    w8_t = rotate((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S(SHA1_F2o, e, a, b, c, d, w8_t);
    w9_t = rotate((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S(SHA1_F2o, d, e, a, b, c, w9_t);
    wa_t = rotate((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S(SHA1_F2o, c, d, e, a, b, wa_t);
    wb_t = rotate((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S(SHA1_F2o, b, c, d, e, a, wb_t);

    #undef K
    #define K 0xca62c1d6

    wc_t = rotate((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S(SHA1_F1, a, b, c, d, e, wc_t);
    wd_t = rotate((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S(SHA1_F1, e, a, b, c, d, wd_t);
    we_t = rotate((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S(SHA1_F1, d, e, a, b, c, we_t);
    wf_t = rotate((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S(SHA1_F1, c, d, e, a, b, wf_t);
    w0_t = rotate((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S(SHA1_F1, b, c, d, e, a, w0_t);
    w1_t = rotate((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S(SHA1_F1, a, b, c, d, e, w1_t);
    w2_t = rotate((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S(SHA1_F1, e, a, b, c, d, w2_t);
    w3_t = rotate((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S(SHA1_F1, d, e, a, b, c, w3_t);
    w4_t = rotate((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S(SHA1_F1, c, d, e, a, b, w4_t);
    w5_t = rotate((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S(SHA1_F1, b, c, d, e, a, w5_t);
    w6_t = rotate((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S(SHA1_F1, a, b, c, d, e, w6_t);
    w7_t = rotate((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S(SHA1_F1, e, a, b, c, d, w7_t);
    w8_t = rotate((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S(SHA1_F1, d, e, a, b, c, w8_t);
    w9_t = rotate((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S(SHA1_F1, c, d, e, a, b, w9_t);
    wa_t = rotate((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S(SHA1_F1, b, c, d, e, a, wa_t);
    wb_t = rotate((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S(SHA1_F1, a, b, c, d, e, wb_t);
    wc_t = rotate((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S(SHA1_F1, e, a, b, c, d, wc_t);
    wd_t = rotate((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S(SHA1_F1, d, e, a, b, c, wd_t);
    we_t = rotate((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S(SHA1_F1, c, d, e, a, b, we_t);
    wf_t = rotate((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S(SHA1_F1, b, c, d, e, a, wf_t);

    #undef K

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}
