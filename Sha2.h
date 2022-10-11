/*
*
* Copyright (c) 2022 ruslan@muhlinin.com
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*/

#ifndef SHA2_H
#define SHA2_H

#include <vector>
#include <string>
#include <inttypes.h>

#define SR(word, bits) ((word) >> (bits))
#define RL(word, bits) (((word) << (bits)) | ((word) >> (32-(bits))))
#define RR(word, bits) (((word) >> (bits)) | ((word) << (32-(bits))))
#define RL64(word, bits) (((word) << (bits)) | ((word) >> (64-(bits))))
#define RR64(word, bits) (((word) >> (bits)) | ((word) << (64-(bits))))
#define MIN(n1,n2) ((n1) < (n2) ? (n1) : (n2))


namespace Sha2Cpp
{

enum class HashType
{
    Sha256,
    Sha224,
    Sha512,
    Sha384,
    Sha512_256,
    Sha512_224
};

template <HashType T>
class Sha2Base;

class Sha32Data
{
protected:
    const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

    uint32_t sigma0(uint32_t wj) { return RR(wj, 7) ^ RR(wj, 18) ^ SR(wj, 3); }
    uint32_t sigma1(uint32_t wj) { return  RR(wj, 17) ^ RR(wj, 19) ^ SR(wj, 10); }
    uint32_t sum1(uint32_t e) { return RR(e, 6) ^ RR(e, 11) ^ RR(e, 25); }
    uint32_t sum0(uint32_t a) { return RR(a, 2) ^ RR(a, 13) ^ RR(a, 22); }
};

#ifdef WITH_SHA256
template<> class Sha2Base<HashType::Sha256> : public Sha32Data
{
protected:
    using BaseType = uint32_t;
    constexpr static size_t BlockSize = 64;
    constexpr static size_t RoundCount = 64;
    constexpr static size_t ResultBytes = 32;

    const BaseType H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
};
#endif

#ifdef WITH_SHA224
template<> class Sha2Base<HashType::Sha224>: public Sha32Data
{
protected:
    using BaseType = uint32_t;
    constexpr static size_t BlockSize = 64;
    constexpr static size_t RoundCount = 64;
    constexpr static size_t ResultBytes = 28;

    const BaseType H[8] = { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };
};
#endif

class Sha64Data
{
protected:
    const uint64_t K[128] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };

    uint64_t sigma0(uint64_t wj) { return RR64(wj, 1) ^ RR64(wj, 8) ^ SR(wj, 7); }
    uint64_t sigma1(uint64_t wj) { return RR64(wj, 19) ^ RR64(wj, 61) ^ SR(wj, 6); }
    uint64_t sum1(uint64_t e) { return RR64(e, 14) ^ RR64(e, 18) ^ RR64(e, 41); }
    uint64_t sum0(uint64_t a) { return RR64(a, 28) ^ RR64(a, 34) ^ RR64(a, 39); }
};

#ifdef WITH_SHA512
template<> class Sha2Base<HashType::Sha512>: public Sha64Data
{
protected:
    using BaseType = uint64_t;
    constexpr static size_t BlockSize = 128;
    constexpr static size_t RoundCount = 80;
    constexpr static size_t ResultBytes = 64;

    const BaseType H[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
};

#endif

#ifdef WITH_SHA384
template<> class Sha2Base<HashType::Sha384>: public Sha64Data
{
protected:
    using BaseType = uint64_t;
    constexpr static size_t BlockSize = 128;
    constexpr static size_t RoundCount = 80;
    constexpr static size_t ResultBytes = 48;

    const BaseType H[8] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
                            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4 };
};
#endif

#ifdef WITH_SHA512_256
template<> class Sha2Base<HashType::Sha512_256>: public Sha64Data
{
protected:
    using BaseType = uint64_t;
    constexpr static size_t BlockSize = 128;
    constexpr static size_t RoundCount = 80;
    constexpr static size_t ResultBytes = 32;

    const BaseType H[8] = { 0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
                            0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2 };
};
#endif

#ifdef WITH_SHA512_224
template<> class Sha2Base<HashType::Sha512_224>: public Sha64Data
{
protected:
    using BaseType = uint64_t;
    constexpr static size_t BlockSize = 128;
    constexpr static size_t RoundCount = 80;
    constexpr static size_t ResultBytes = 28;

    const BaseType H[8] = { 0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,
                            0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1 };
};
#endif

template<HashType T>
class Sha2: public Sha2Base<T>
{
public:
    std::string Hash(const std::string &str)
    {
        return Hash(reinterpret_cast<const uint8_t *>(str.data()), str.length());
    }

    std::string Hash(const uint8_t *message, uint64_t length)
    {
        if(length & 0xE000000000000000)
        {
            // actually the sha512 length can be up to 2^128-1 bits but it seems logical to me
            // to limit the length to 64 bits (or 61 bytes) in order to avoid unnecessary conversions
            // anyway, that's still 1048576 TB
            return "";
        }

        // messageLength + 8 + padLength + sizeBlockLength = BlockSize
        uint64_t messageLength = length * 8;
        const size_t sizeBlockLength = BaseTypeSize * 2;
        BaseType padLength = ((BlockSize - 1 - sizeBlockLength) * 8) - (messageLength % (BlockSize * 8));

        ByteArray padding;
        padding.push_back(0b10000000);
        // fill with padding zeroes
        auto pad1 = ByteArray(padLength / 8, 0);
        padding.insert(padding.end(), pad1.begin(), pad1.end());

        // copy message length bytes
        auto pad2 = ByteArray(sizeBlockLength, 0);
        for(size_t i = 0;i < sizeof(uint64_t);i ++)
        {
            pad2[sizeBlockLength - i - 1] = ((messageLength >> (i * 8)) & 0xFF);
        }
        padding.insert(padding.end(), pad2.begin(), pad2.end());

        size_t total = length + padding.size();
        size_t pos = 0;
        size_t dpos = 0;

        const uint8_t *ptr = message;
        BaseType W[RoundCount] = {};
        BaseType Hlocal[8];
        BaseType value[8];

        for(size_t i = 0;i < 8;i ++)
        {
            Hlocal[i] = H[i];
        }

        while(pos < total)
        {
            if(pos == length) // all the message bytes are copied, now copy the padding bytes
            {
                ptr = padding.data();
                dpos = 0;
            }
            // copy chunk bytes into schedule array
            W[pos % BlockSize / BaseTypeSize] |= static_cast<BaseType>(ptr[dpos]) << ((BaseTypeSize * 8 - 8) - ((pos % BaseTypeSize) * 8));
            dpos ++;
            pos ++;

            if((pos % BlockSize) == 0)
            {
                for(size_t i = 16;i < RoundCount;i ++)
                {
                    BaseType wk = W[i - 16];
                    BaseType wl = W[i - 7];
                    BaseType wi = W[i - 15];
                    BaseType wj = W[i - 2];
                    BaseType sig0 = sigma0(wi);
                    BaseType sig1 = sigma1(wj);
                    W[i] = wk + sig0 + wl + sig1;
                }

                for(size_t i = 0;i < 8;i ++)
                {
                    value[i] = Hlocal[i];
                }

                for(size_t i = 0;i < RoundCount;i ++)
                {
                    BaseType s1 = sum1(value[4]);
                    BaseType choice = (value[4] & value[5]) ^ ((~ value[4]) & value[6]);
                    BaseType s0 = sum0(value[0]);
                    BaseType majority = (value[0] & value[1]) ^ (value[0] & value[2]) ^ (value[1] & value[2]);
                    BaseType temp1 = value[7] + s1 + choice + K[i] + W[i];
                    BaseType temp2 = s0 + majority;

                    value[7] = value[6];
                    value[6] = value[5];
                    value[5] = value[4];
                    value[4] = value[3] + temp1;
                    value[3] = value[2];
                    value[2] = value[1];
                    value[1] = value[0];
                    value[0] = temp1 + temp2;
                }

                for(size_t i = 0;i < 8;i ++)
                {
                    Hlocal[i] += value[i];
                }

                if(pos < total)
                {
                    clear(W, RoundCount);
                }
            }
        }

        // convert byte array into hex string
        std::string str;
        for(size_t i = 0; i < ResultBytes; i+= BaseTypeSize)
        {
            str += hex2str(Hlocal[i/BaseTypeSize], MIN(ResultBytes - i, BaseTypeSize));
        }

        return str;
    }

private:
    using BaseType = typename Sha2Base<T>::BaseType;
    using Sha2Base<T>::K;
    using Sha2Base<T>::H;
    using Sha2Base<T>::BlockSize;
    using Sha2Base<T>::RoundCount;
    using Sha2Base<T>::ResultBytes;
    using Sha2Base<T>::sigma0;
    using Sha2Base<T>::sigma1;
    using Sha2Base<T>::sum0;
    using Sha2Base<T>::sum1;
    typedef std::vector<uint8_t> ByteArray;
    const size_t BaseTypeSize = sizeof(BaseType);

protected:
    void clear(BaseType *arr, size_t size)
    {
        for(size_t i = 0;i < size;i ++)
        {
            arr[i] = 0;
        }
    }
    std::string hex2str(BaseType n, size_t len)
    {
        static char hex[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
        size_t typeSize = sizeof(n) * 2;
        std::string s;
        for(size_t i = 0;i < len * 2; i++)
        {
            size_t byte = static_cast<size_t>((n >> ((typeSize - i - 1) * 4)) & 0x0F);
            s += hex[byte];
        }

        return s;
    }
};

}

#endif // SHA2_H
