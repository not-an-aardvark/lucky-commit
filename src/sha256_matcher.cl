// Note: A lot of code is duplicated between this file and sha1_matcher.cl.
uint16 arrange_padding_block(ulong padding_specifier, uint4 padding_block_ending);
void sha256_compress(__private uint* h, uint16 w);

__constant uint PADDING_CHUNKS[16] = {
    0x20202020, 0x20202009, 0x20200920, 0x20200909,
    0x20092020, 0x20092009, 0x20090920, 0x20090909,
    0x09202020, 0x09202009, 0x09200920, 0x09200909,
    0x09092020, 0x09092009, 0x09090920, 0x09090909,
};

__kernel void scatter_padding_and_find_match(
    __global uint* hash_spec_data,
    __global uint* hash_spec_mask,
    __global uint* h,
    ulong base_padding_specifier,
    __global uint16* dynamic_blocks,
    ulong num_dynamic_blocks,
    __global uint* successful_match_receiver
) {
    uint finalized_hash[8] = {h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]};
    sha256_compress(
        finalized_hash,
        arrange_padding_block(
            base_padding_specifier + get_global_id(0),
            dynamic_blocks[0].sCDEF
        )
    );
    for (size_t i = 1; i < num_dynamic_blocks; i++) {
        sha256_compress(finalized_hash, dynamic_blocks[i]);
    }

    if (
        (finalized_hash[0] & hash_spec_mask[0]) == hash_spec_data[0] &&
        (finalized_hash[1] & hash_spec_mask[1]) == hash_spec_data[1] &&
        (finalized_hash[2] & hash_spec_mask[2]) == hash_spec_data[2] &&
        (finalized_hash[3] & hash_spec_mask[3]) == hash_spec_data[3] &&
        (finalized_hash[4] & hash_spec_mask[4]) == hash_spec_data[4] &&
        (finalized_hash[5] & hash_spec_mask[5]) == hash_spec_data[5] &&
        (finalized_hash[6] & hash_spec_mask[6]) == hash_spec_data[6] &&
        (finalized_hash[7] & hash_spec_mask[7]) == hash_spec_data[7]
    ) {
        atomic_cmpxchg(successful_match_receiver, UINT_MAX, get_global_id(0));
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
        PADDING_CHUNKS[(padding_specifier >> 44) & 0xf],
        PADDING_CHUNKS[(padding_specifier >> 40) & 0xf],
        padding_block_ending.s0,
        padding_block_ending.s1,
        padding_block_ending.s2,
        padding_block_ending.s3
    );
}

/*
The sha256 implementation below is mostly adapted from hashcat (https://hashcat.net/hashcat).

The MIT License (MIT)

Copyright (c) 2015-2021 Jens Steube

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

__constant uint k_sha256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,

    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,

    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,

    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define hc_rotl32_S rotate
#define SHA256_S0_S(x) (rotate((x), 25u) ^ rotate((x), 14u) ^ ((x) >> 3u))
#define SHA256_S1_S(x) (rotate((x), 15u) ^ rotate((x), 13u) ^ ((x) >> 10u))
#define SHA256_S2_S(x) (rotate((x), 30u) ^ rotate((x), 19u) ^ rotate((x), 10u))
#define SHA256_S3_S(x) (rotate((x), 26u) ^ rotate((x), 21u) ^ rotate((x),  7u))

#define SHA256_F0o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#define SHA256_F1o(x,y,z) (bitselect ((z), (y), (x)))

#define SHA256_STEP_S(F0,F1,a,b,c,d,e,f,g,h,x,K) \
{                                                \
    h += K + x + SHA256_S3_S (e) + F1 (e,f,g);   \
    d += h;                                      \
    h += SHA256_S2_S (a) + F0 (a,b,c);           \
}
#define SHA256_EXPAND_S(x,y,z,w) (SHA256_S1_S (x) + y + SHA256_S0_S (z) + w)

void sha256_compress(__private uint* hash, uint16 w) {
    uint a = hash[0];
    uint b = hash[1];
    uint c = hash[2];
    uint d = hash[3];
    uint e = hash[4];
    uint f = hash[5];
    uint g = hash[6];
    uint h = hash[7];

    uint w0_t = w.s0;
    uint w1_t = w.s1;
    uint w2_t = w.s2;
    uint w3_t = w.s3;
    uint w4_t = w.s4;
    uint w5_t = w.s5;
    uint w6_t = w.s6;
    uint w7_t = w.s7;
    uint w8_t = w.s8;
    uint w9_t = w.s9;
    uint wa_t = w.sA;
    uint wb_t = w.sB;
    uint wc_t = w.sC;
    uint wd_t = w.sD;
    uint we_t = w.sE;
    uint wf_t = w.sF;

    #define ROUND_EXPAND_S()                             \
    {                                                    \
        w0_t = SHA256_EXPAND_S (we_t, w9_t, w1_t, w0_t); \
        w1_t = SHA256_EXPAND_S (wf_t, wa_t, w2_t, w1_t); \
        w2_t = SHA256_EXPAND_S (w0_t, wb_t, w3_t, w2_t); \
        w3_t = SHA256_EXPAND_S (w1_t, wc_t, w4_t, w3_t); \
        w4_t = SHA256_EXPAND_S (w2_t, wd_t, w5_t, w4_t); \
        w5_t = SHA256_EXPAND_S (w3_t, we_t, w6_t, w5_t); \
        w6_t = SHA256_EXPAND_S (w4_t, wf_t, w7_t, w6_t); \
        w7_t = SHA256_EXPAND_S (w5_t, w0_t, w8_t, w7_t); \
        w8_t = SHA256_EXPAND_S (w6_t, w1_t, w9_t, w8_t); \
        w9_t = SHA256_EXPAND_S (w7_t, w2_t, wa_t, w9_t); \
        wa_t = SHA256_EXPAND_S (w8_t, w3_t, wb_t, wa_t); \
        wb_t = SHA256_EXPAND_S (w9_t, w4_t, wc_t, wb_t); \
        wc_t = SHA256_EXPAND_S (wa_t, w5_t, wd_t, wc_t); \
        wd_t = SHA256_EXPAND_S (wb_t, w6_t, we_t, wd_t); \
        we_t = SHA256_EXPAND_S (wc_t, w7_t, wf_t, we_t); \
        wf_t = SHA256_EXPAND_S (wd_t, w8_t, w0_t, wf_t); \
    }

    #define ROUND_STEP_S(i)                                                                     \
    {                                                                                           \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
        SHA256_STEP_S (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
    }

    ROUND_STEP_S (0);

    for (int i = 16; i < 64; i += 16) {
        ROUND_EXPAND_S (); ROUND_STEP_S (i);
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}
