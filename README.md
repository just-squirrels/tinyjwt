# tinyjwt
A little scrappy JWT helper.

## Use
Add keys. Sign or verify. Sorta fits [RFC7519](https://www.rfc-editor.org/rfc/rfc7519). Example (TypeScript):

```typescript
import { sign, verify } from "@sqrls/tinyjwt"

// Sign with a secret key and key ID
const signedJwt = sign({ sub: "bob", exp: Date.now() + 23, other: "data" }, "super secret", "key id");

// And verify
const contents = tinyjwt.verify(signedJwt, (keyId) => {
    if (keyId === "key id") return "super secret";
});

// If contents are undefined, verification failed
if (!contents) {
    throw new Exception("Invalid!")
}

// Don't care about key IDs? They're optional
const jwt = sign({ sub: "bob", exp: Date.now() + 23, other: "data" }, "super secret");
const contents = verify(jwt, () => "super secret")
```