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

#include <iostream>
#include "Sha2.h"


struct TestInstance
{
    std::string Hash(Hash::HashType type, const std::string &data)
    {
        switch(type)
        {
#ifdef WITH_SHA256
            case Hash::HashType::Sha256:
                return hash256.Hash(data);
#endif
#ifdef WITH_SHA224
            case Hash::HashType::Sha224:
                return hash224.Hash(data);
#endif
#ifdef WITH_SHA512
            case Hash::HashType::Sha512:
                return hash512.Hash(data);
#endif
#ifdef WITH_SHA384
            case Hash::HashType::Sha384:
                return hash384.Hash(data);
#endif
#ifdef WITH_SHA512_256
            case Hash::HashType::Sha512_256:
                return hash512_256.Hash(data);
#endif
#ifdef WITH_SHA512_224
            case Hash::HashType::Sha512_224:
                return hash512_224.Hash(data);
#endif
            default:
                break;
        }

        return "";
    }
#ifdef WITH_SHA224
    Hash::Sha2<Hash::HashType::Sha224> hash224;
#endif
#ifdef WITH_SHA256
    Hash::Sha2<Hash::HashType::Sha256> hash256;
#endif
#ifdef WITH_SHA384
    Hash::Sha2<Hash::HashType::Sha384> hash384;
#endif
#ifdef WITH_SHA512
    Hash::Sha2<Hash::HashType::Sha512> hash512;
#endif
#ifdef WITH_SHA512_224
    Hash::Sha2<Hash::HashType::Sha512_224> hash512_224;
#endif
#ifdef WITH_SHA512_256
    Hash::Sha2<Hash::HashType::Sha512_256> hash512_256;
#endif
} testInstances;

struct TestCase
{
    Hash::HashType type;
    std::string name;
    std::string str;
    std::string sample;
};

std::vector<TestCase> testCases = {
    #ifdef WITH_SHA224
    {
        Hash::HashType::Sha224,
        "Sha224 empty string",
        "",
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    },
    {
        Hash::HashType::Sha224,
        "Sha224 long string",
        "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
        "f7c057c13f78cd64044e92c7f7b3fa07fba6138ff0058ce78e9343f7"
    },
    {
        Hash::HashType::Sha224,
        "Sha224 short string",
        "abc",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    },
    #endif
    #ifdef WITH_SHA384
    {
        Hash::HashType::Sha384,
        "Sha384 empty string",
        "",
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    },
    {
        Hash::HashType::Sha384,
        "Sha384 long string",
        "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
        "7040c7f666b8a3d05a04ee777d55f2ddd4a5ae810499d0edfbe9c4fd1df6c0cd3e1f5c8a3ee503090ca85fd388a67591"
    },
    {
        Hash::HashType::Sha384,
        "Sha384 short string",
        "abc",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    },
    #endif
    #ifdef WITH_SHA256
    {
        Hash::HashType::Sha256,
        "Sha256 empty string",
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
        Hash::HashType::Sha256,
        "Sha256 long string",
        "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
        "8858bc0042cab8709532bca29a09277be67160d7aa27a59cf0f94f03b088846d"
    },
    {
        Hash::HashType::Sha256,
        "Sha256 short string",
        "abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    #endif
    #ifdef WITH_SHA512
    {
        Hash::HashType::Sha512,
        "Sha512 empty string",
        "",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    },
    {
        Hash::HashType::Sha512,
        "Sha512 long string",
        "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
        "1bc122cfc53bdd47955cc8e8e7e387635c49dfb11866773eebc888a7cfe5c3dac4a34d8c5d156344f31c3a3b7dbcf3f7c26576729912c68123526ce9da294dee"
    },
    {
        Hash::HashType::Sha512,
        "Sha512 short string",
        "abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    },
    #endif
    #ifdef WITH_SHA512_224
    {
        Hash::HashType::Sha512_224,
        "Sha512/224 empty string",
        "",
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
    },
    {
        Hash::HashType::Sha512_224,
        "Sha512/224 long string",
        "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
        "11b05ae590e40bbf05a1aea7fba8224a41b8d1c4ed92d66ebf99d8c2"
    },
    {
        Hash::HashType::Sha512_224,
        "Sha512/224 short string",
        "abc",
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
    },
    #endif
    #ifdef WITH_SHA512_256
    {
        Hash::HashType::Sha512_256,
        "Sha512/256 empty string",
        "",
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
    },
    {
        Hash::HashType::Sha512_256,
        "Sha512/256 long string",
        "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
        "4763514282b12374e225224f49c6dec80097713b12144a999a4abf8132019937"
    },
    {
        Hash::HashType::Sha512_256,
        "Sha512/256 short string",
        "abc",
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    },
    #endif
};

#ifdef __linux__
#define FgWhite   "\033[1;39m"
#define FgBlack   "\033[1;30m"
#define FgGreen   "\033[1;32m"
#define FgRed     "\033[1;31m"
#define FgYellow  "\033[1;33m"
#define FgBlue    "\033[1;34m"
#define FgMagenta "\033[1;35m"
#define FgCyan    "\033[1;36m"
#define FgClear   "\033[0m"
#else
#define FgWhite   ""
#define FgBlack   ""
#define FgGreen   ""
#define FgRed     ""
#define FgYellow  ""
#define FgBlue    ""
#define FgMagenta ""
#define FgCyan    ""
#define FgClear   ""
#endif

int main()
{
    int i = 1;
    for(auto const &test: testCases)
    {
        std::string hash = testInstances.Hash(test.type, test.str);
        std::cout << (i++) << ". Executing test:  " << FgBlue << test.name << FgClear << std::endl;
        std::cout << "original string: " << FgCyan << test.str << FgClear << std::endl;
        std::cout << "expected hash:   " << FgYellow << test.sample << FgClear << std::endl;
        std::cout << "calculated hash: " << FgMagenta << hash << FgClear << std::endl;
        std::cout << "result: " << (hash.compare(test.sample) == 0 ? (std::string(FgGreen) + "passed") : (std::string(FgRed) + "failed")) << FgClear << std::endl;
        std::cout << std::endl;
    }
    return 0;
}
