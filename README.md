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

using namespace Hash;

Sha2<HashType::Sha256> hash256;
std::cout << hash256.Hash("The quick brown fox jumps over the lazy dog") << std::endl;
```
