# @wae/open-ctf-ui

Static Studio shell for OpenCTF, built on VMZ. It is the window opened by
`open-ctf gui`; it holds no analysis logic and renders only what the connected
host reports.

The build emits `dist/static`, which the repository stages into
`projects/packages/open-ctf/dist/gui`. When the shell runs without a connected
host it shows an empty state instead of sample data.

## Example

The app does not import this package. Run the Studio through the main package:

```bash
open-ctf gui
```

The package is private and is not an installation target.
