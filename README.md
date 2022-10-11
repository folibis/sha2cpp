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

# Usage

```cpp
#include "Sha2.h"

using namespace Sha2Cpp;

Sha2<HashType::Sha256> hash256;
std::cout << hash256.Hash("The quick brown fox jumps over the lazy dog") << std::endl;
>>> d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
```

Run the test application to test that
```bash
cmake .
make
./sha2cpp
```
