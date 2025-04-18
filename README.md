# sha2cpp
## Sha2 hash functions library

_Small C++11 header-only library implements Sha2 hash functions_

Supported hash types:
- Sha256
- Sha224
- Sha512
- Sha384
- Sha512/256
- Sha512/224
- HMAC
# Usage

```cpp
#include "Sha2.h"

using namespace Sha2Cpp;

Sha2<HashType::Sha256> hash256;
std::vector<uint8_t> hash = hash256.Hash("The quick brown fox jumps over the lazy dog");

std::vector<uint8_t> hmac = hash256.HMAC("The quick brown fox jumps over the lazy dog", "some key");
```

Run the test application to test that
```bash
cmake .
make
./sha2cpp
```
