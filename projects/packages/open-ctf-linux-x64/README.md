# @wae/open-ctf-linux-x64

Linux x64 native addon for `@wae/open-ctf`. **Not a public import target.**

Installed automatically as an optional dependency of `@wae/open-ctf` on a
matching host. The package contains one staged `.node` file.

## Example

Application code imports the main package; this artifact loads underneath it:

```ts
import { OpenCTF } from '@wae/open-ctf';

const ctf = new OpenCTF({ path: '/samples/app' });
console.log(ctf.info().format);
ctf.close();
```

The addon is not published yet. See the
[root README](../../../readme.md) for the product overview.
