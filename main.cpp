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

#include "Sha2.h"
#include <iostream>

struct TestInstance
{
    std::vector<uint8_t> Hash(Sha2Cpp::HashType type, const std::string &data)
    {
        switch (type)
        {
#ifdef WITH_SHA256
        case Sha2Cpp::HashType::Sha256:
            return hash256.Hash(data);
#endif
#ifdef WITH_SHA224
        case Sha2Cpp::HashType::Sha224:
            return hash224.Hash(data);
#endif
#ifdef WITH_SHA512
        case Sha2Cpp::HashType::Sha512:
            return hash512.Hash(data);
#endif
#ifdef WITH_SHA384
        case Sha2Cpp::HashType::Sha384:
            return hash384.Hash(data);
#endif
#ifdef WITH_SHA512_256
        case Sha2Cpp::HashType::Sha512_256:
            return hash512_256.Hash(data);
#endif
#ifdef WITH_SHA512_224
        case Sha2Cpp::HashType::Sha512_224:
            return hash512_224.Hash(data);
#endif
        default:
            break;
        }

        return {};
    }

    std::vector<uint8_t> HMAC(Sha2Cpp::HashType type, const std::string &data, const std::string &key)
    {
        switch (type)
        {
#ifdef WITH_SHA256
        case Sha2Cpp::HashType::Sha256:
            return hash256.HMAC(data, key);
#endif
#ifdef WITH_SHA224
        case Sha2Cpp::HashType::Sha224:
            return hash224.HMAC(data, key);
#endif
#ifdef WITH_SHA512
        case Sha2Cpp::HashType::Sha512:
            return hash512.HMAC(data, key);
#endif
#ifdef WITH_SHA384
        case Sha2Cpp::HashType::Sha384:
            return hash384.HMAC(data, key);
#endif
#ifdef WITH_SHA512_256
        case Sha2Cpp::HashType::Sha512_256:
            return hash512_256.HMAC(data, key);
#endif
#ifdef WITH_SHA512_224
        case Sha2Cpp::HashType::Sha512_224:
            return hash512_224.HMAC(data, key);
#endif
        default:
            break;
        }

        return {};
    }

#ifdef WITH_SHA224
    Sha2Cpp::Sha2<Sha2Cpp::HashType::Sha224> hash224;
#endif
#ifdef WITH_SHA256
    Sha2Cpp::Sha2<Sha2Cpp::HashType::Sha256> hash256;
#endif
#ifdef WITH_SHA384
    Sha2Cpp::Sha2<Sha2Cpp::HashType::Sha384> hash384;
#endif
#ifdef WITH_SHA512
    Sha2Cpp::Sha2<Sha2Cpp::HashType::Sha512> hash512;
#endif
#ifdef WITH_SHA512_224
    Sha2Cpp::Sha2<Sha2Cpp::HashType::Sha512_224> hash512_224;
#endif
#ifdef WITH_SHA512_256
    Sha2Cpp::Sha2<Sha2Cpp::HashType::Sha512_256> hash512_256;
#endif
} testInstances;

struct TestCase
{
    Sha2Cpp::HashType type;
    std::string name;
    std::string str;
    std::string sample;
    std::string key;
};

std::vector<TestCase> testCases = {
#ifdef WITH_SHA224
    {Sha2Cpp::HashType::Sha224, "Sha224 empty string", "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
    {Sha2Cpp::HashType::Sha224,
     "Sha224 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "f7c057c13f78cd64044e92c7f7b3fa07fba6138ff0058ce78e9343f7"},
    {Sha2Cpp::HashType::Sha224, "Sha224 short string", "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
#endif
#ifdef WITH_SHA384
    {Sha2Cpp::HashType::Sha384,
     "Sha384 empty string",
     "",
     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b"
     "95b"},
    {Sha2Cpp::HashType::Sha384,
     "Sha384 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "7040c7f666b8a3d05a04ee777d55f2ddd4a5ae810499d0edfbe9c4fd1df6c0cd3e1f5c8a3ee503090ca85fd388a67"
     "591"},
    {Sha2Cpp::HashType::Sha384,
     "Sha384 short string",
     "abc",
     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c82"
     "5a7"},
#endif
#ifdef WITH_SHA256
    {Sha2Cpp::HashType::Sha256,
     "Sha256 empty string",
     "",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {Sha2Cpp::HashType::Sha256,
     "Sha256 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "8858bc0042cab8709532bca29a09277be67160d7aa27a59cf0f94f03b088846d"},
    {Sha2Cpp::HashType::Sha256,
     "Sha256 short string",
     "abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
#endif
#ifdef WITH_SHA512
    {Sha2Cpp::HashType::Sha512,
     "Sha512 empty string",
     "",
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877ee"
     "c2f63b931bd47417a81a538327af927da3e"},
    {Sha2Cpp::HashType::Sha512,
     "Sha512 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "1bc122cfc53bdd47955cc8e8e7e387635c49dfb11866773eebc888a7cfe5c3dac4a34d8c5d156344f31c3a3b7dbcf"
     "3f7c26576729912c68123526ce9da294dee"},
    {Sha2Cpp::HashType::Sha512,
     "Sha512 short string",
     "abc",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3fee"
     "bbd454d4423643ce80e2a9ac94fa54ca49f"},
#endif
#ifdef WITH_SHA512_224
    {Sha2Cpp::HashType::Sha512_224,
     "Sha512/224 empty string",
     "",
     "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"},
    {Sha2Cpp::HashType::Sha512_224,
     "Sha512/224 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "11b05ae590e40bbf05a1aea7fba8224a41b8d1c4ed92d66ebf99d8c2"},
    {Sha2Cpp::HashType::Sha512_224,
     "Sha512/224 short string",
     "abc",
     "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"},
#endif
#ifdef WITH_SHA512_256
    {Sha2Cpp::HashType::Sha512_256,
     "Sha512/256 empty string",
     "",
     "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
    {Sha2Cpp::HashType::Sha512_256,
     "Sha512/256 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "4763514282b12374e225224f49c6dec80097713b12144a999a4abf8132019937"},
    {Sha2Cpp::HashType::Sha512_256,
     "Sha512/256 short string",
     "abc",
     "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"},
#endif
};

std::vector<TestCase> testCases_HMAC = {
#ifdef WITH_SHA224
    {Sha2Cpp::HashType::Sha224,
     "HMAC using Sha224 empty string",
     "",
     "a84e79b95e355b88ce19d4e6724f280dde66e9660ea0c0f992d18303",
     "c492bbf7b4b113ee3bb1b9359af465a0"},
    {Sha2Cpp::HashType::Sha224,
     "Sha224 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "a9639b8753c7c7acf2e5cfa61e9cdf99ed4517f2fbfad9d9671b5342",
     "aadb20b5bd6c5a1cd262c09f85c47512"},
    {Sha2Cpp::HashType::Sha224,
     "HMAC using Sha224 short string",
     "abc",
     "7967521493fff3f9462f2e43ab7ad744b26d2c993aa1fc57a7725caf",
     "6ecf0d24d2a5804e060788cc803a6efa"},
#endif
#ifdef WITH_SHA384
    {Sha2Cpp::HashType::Sha384,
     "HMAC using Sha384 empty string",
     "",
     "0e0536228e785231ac515d9876cfebdbec7769bb4ac6f31844984e106861a0c3d07c1bfd3207c2db46da83b1d49a3"
     "e8a",
     "f5bc264cb1ecf6bf2c831db933b876b4"},
    {Sha2Cpp::HashType::Sha384,
     "HMAC using Sha384 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "514011e41567b10aeac133b14173dd9ea5b30b2f52dca3019c467a9ffd4c98c050bf7f827cc506c64a2c7c44e1978"
     "278",
     "cc02f6361d2ed85d1caa5755f8e32b44"},
    {Sha2Cpp::HashType::Sha384,
     "HMAC using Sha384 short string",
     "abc",
     "f6bfe040bbaf8f30269d57027a3360af5efcab22c5a889c73db743cf3a4593cbd9015e36e60ee5858cc614aaeaad1"
     "242",
     "27600a30d310376d99f610faa46b1786"},
#endif
#ifdef WITH_SHA256
    {Sha2Cpp::HashType::Sha256,
     "HMAC using Sha256 empty string",
     "",
     "ec8ac7591b4ac7d208e9214db8259328c71492d73ce6434372a4664dc96d3abf",
     "27600a30d310376d99f610faa46b1786"},
    {Sha2Cpp::HashType::Sha256,
     "HMAC using Sha256 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "7110f2210041d2193aa988ba02fc2de61a9ed6e6b4ba8663218649cac1c4f14a",
     "c4bbf803f5c40a7da640aed6779ea649"},
    {Sha2Cpp::HashType::Sha256,
     "HMAC using Sha256 short string",
     "abc",
     "a7ed1ec240362d027133e1aa0d33d85f0d6f09723b28f27cc93f85a609b6fec9",
     "5adc20d03201d3d6ee8aa97a81408b29"},
#endif
#ifdef WITH_SHA512
    {Sha2Cpp::HashType::Sha512,
     "HMAC using Sha512 empty string",
     "",
     "17137e96a6f7309d32df23fb24b7ba59a26ef37465a1b188439ab3e071213e5b2fa7c00b46e1a2ec158cbe52f2982"
     "32451c240c8a268c3719c41d4ef60770ef9",
     "c2f63b931bd47417a81a538327af927da3e"},
    {Sha2Cpp::HashType::Sha512,
     "HMAC using Sha512 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "ee0d927d491e5a14d1e1d0fce54a49c42cc267e549c60c9e155faed393d843ab122bd47d6fcb95769c3e777e4aca7"
     "5ff4bda50306687689668716739cc925099",
     "70be5827a5c3ec30d9df6c0682403ab2"},
    {Sha2Cpp::HashType::Sha512,
     "HMAC using Sha512 short string",
     "abc",
     "2af2075ad00b9d712e79cee5370e2a571a8bb08858d12f090976aac8677256137553d08107e3df0e3a677e8a20f59"
     "c1e80d5d403991155e3fe8513f752809b08",
     "0b8a422db7765fba10364084841f9ec6"},
#endif
#ifdef WITH_SHA512_224
    {Sha2Cpp::HashType::Sha512_224,
     "HMAC using Sha512/224 empty string",
     "",
     "f207872b23caa9d7b46895f81a386e866f7308ae8ae436fcc4535dc8",
     "9f94959bc6722dd41eac1b647641cf4b"},
    {Sha2Cpp::HashType::Sha512_224,
     "HMAC using Sha512/224 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "ca6362b63de5e601783fef3a4c24b11364812b492316d6c208db6324",
     "a7caa86336145be406c1b23d179dddaf"},
    {Sha2Cpp::HashType::Sha512_224,
     "HMAC using Sha512/224 short string",
     "abc",
     "fc957b5878111f1950fabf588ba83a61fea706890aced69881ccb87e",
     "5af55fff9f91f4ed742f50a47b588335"},
#endif
#ifdef WITH_SHA512_256
    {Sha2Cpp::HashType::Sha512_256,
     "HMAC using Sha512/256 empty string",
     "",
     "adebd96b0554805d86c0eccd2fb66b411d6ec844607830b88c08f8088c5db7eb",
     "834016231f8be27d17659d7351bd0087"},
    {Sha2Cpp::HashType::Sha512_256,
     "HMAC using Sha512/256 long string",
     "01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghij"
     "klmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz012345"
     "67890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnop"
     "qrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz01234567890abcdefghijklmnopqrsuvwxyz",
     "b4afa22d05a16db402d58a09f2d8ee96e8c6911c835da6e28d30ef4810121eb9",
     "8df53e4454d62b0e2b38d8f02288a4ae"},
    {Sha2Cpp::HashType::Sha512_256,
     "HMAC using Sha512/256 short string",
     "abc",
     "2a3198d427eb61a6e2aa98ff7c463b1bc0a847e749eb09426b8c8df72258ec24",
     "3d61f4e6a345077da7824dbdc960a22e"},
#endif
};

#ifdef __linux__

#define FgBlack "\e[1;30m"
#define FgRed "\e[1;31m"
#define FgGreen "\e[1;32m"
#define FgYellow "\e[1;33m"
#define FgBlue "\e[1;34m"
#define FgMagenta "\e[1;35m"
#define FgCyan "\e[1;36m"
#define FgWhite "\e[1;37m"
#define BgBlack "\e[40m"
#define BgRed "\e[41m"
#define BgGreen "\e[42m"
#define BgYellow "\e[43m"
#define BgBlue "\e[44m"
#define BgMagenta "\e[45m"
#define BgCyan "\e[46m"
#define BgWhite "\e[47m"
#define Clear "\e[0m"

#else
#define FgWhite ""
#define FgBlack ""
#define FgGreen ""
#define FgRed ""
#define FgYellow ""
#define FgBlue ""
#define FgMagenta ""
#define FgCyan ""
#define FgWhite ""
#define BgBlack ""
#define BgGreen ""
#define BgRed ""
#define BgYellow ""
#define BgBlue ""
#define BgMagenta ""
#define BgCyan ""
#define Clear ""
#endif

static std::string byte2hex(uint8_t byte)
{
    static char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    return std::string(1, hex[byte >> 4]) + hex[byte & 0x0F];
}

static std::string array2string(const std::vector<uint8_t> &arr)
{
    std::string str;
    for (const uint8_t &ch : arr)
    {
        str += byte2hex(ch);
    }

    return str;
}

int main()
{
    size_t i = 0;
    size_t failed = 0;

    std::cout << BgWhite << FgBlack << "---------------- Hashes tests ----------------\n" << Clear << std::endl;
    for (auto const &test : testCases)
    {
        std::vector<uint8_t> hash = testInstances.Hash(test.type, test.str);
        std::cout << (++i) << ". Executing test:  " << FgBlue << test.name << Clear << std::endl;
        std::cout << "original string: " << FgCyan << test.str << Clear << std::endl;
        std::cout << "expected hash:   " << FgYellow << test.sample << Clear << std::endl;
        std::cout << "calculated hash: " << FgMagenta << array2string(hash) << Clear << std::endl;

        bool is_pass = (array2string(hash).compare(test.sample) == 0);
        std::cout << "result: "
                  << (is_pass ? (std::string(FgGreen) + "passed") : (failed++, std::string(FgRed) + "failed")) << Clear
                  << std::endl;
        std::cout << std::endl;
    }

    std::cout << BgWhite << FgBlack << "---------------- HMAC tests ----------------\n" << Clear << std::endl;
    for (auto const &test : testCases_HMAC)
    {
        std::vector<uint8_t> hash = testInstances.HMAC(test.type, test.str, test.key);
        std::cout << (++i) << ". Executing test:  " << FgBlue << test.name << Clear << std::endl;
        std::cout << "original string: " << FgCyan << test.str << Clear << std::endl;
        std::cout << "key string: " << FgCyan << test.key << Clear << std::endl;
        std::cout << "expected hash:   " << FgYellow << test.sample << Clear << std::endl;
        std::cout << "calculated hash: " << FgMagenta << array2string(hash) << Clear << std::endl;
        bool is_pass = (array2string(hash).compare(test.sample) == 0);
        std::cout << "result: "
                  << (is_pass ? (std::string(FgGreen) + "passed") : (failed++, std::string(FgRed) + "failed")) << Clear
                  << std::endl;
        std::cout << std::endl;
    }

    std::cout << "total: " << i << " tests, " << (failed > 0 ? FgRed : FgGreen) << failed << " failed" << Clear
              << std::endl;

    return 0;
}
