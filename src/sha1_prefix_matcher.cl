uint16 arrange_padding_block(ulong padding_specifier, uint4 padding_block_ending);
void sha1_compress(__private uint* h, uint16 w);

__constant uint PADDING_CHUNKS[16] = {
    0x20202020, 0x20202009, 0x20200920, 0x20200909,
    0x20092020, 0x20092009, 0x20090920, 0x20090909,
    0x09202020, 0x09202009, 0x09200920, 0x09200909,
    0x09092020, 0x09092009, 0x09090920, 0x09090909,
};

__kernel void scatter_padding_and_find_match(
    __global uint* desired_prefix_data,
    __global uint* desired_prefix_mask,
    __global uint* h,
    __global uint16* dynamic_blocks,
    size_t num_dynamic_blocks,
    __global uint* successful_match_receiver
) {
    uint finalized_hash[5] = {h[0], h[1], h[2], h[3], h[4]};
    sha1_compress(
        finalized_hash,
        arrange_padding_block(
            get_global_id(0),
            dynamic_blocks[0].sCDEF
        )
    );
    for (size_t i = 1; i < num_dynamic_blocks; i++) {
        sha1_compress(finalized_hash, dynamic_blocks[i]);
    }

    if (
        (finalized_hash[0] & desired_prefix_mask[0]) == desired_prefix_data[0] &&
        (finalized_hash[1] & desired_prefix_mask[1]) == desired_prefix_data[1] &&
        (finalized_hash[2] & desired_prefix_mask[2]) == desired_prefix_data[2] &&
        (finalized_hash[3] & desired_prefix_mask[3]) == desired_prefix_data[3] &&
        (finalized_hash[4] & desired_prefix_mask[4]) == desired_prefix_data[4]
    ) {
        atomic_cmpxchg(successful_match_receiver, UINT_MAX, get_global_id(0) % get_global_size(0));
    }
}

uint16 arrange_padding_block(ulong padding_specifier, uint4 padding_block_ending) {
    return (uint16)(
        PADDING_CHUNKS[(padding_specifier >> 4) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 0) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 12) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 8) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 20) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 16) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 28) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 24) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 36) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 32) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 40) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 44) & 0xf],
        padding_block_ending[0],
        padding_block_ending[1],
        padding_block_ending[2],
        padding_block_ending[3]
    );
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

void sha1_compress(__private uint* h, uint16 w) {
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
