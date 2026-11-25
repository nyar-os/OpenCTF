// Nifty project configuration.
// See @doki-land/nifty for defineConfig, format presets, authorMap path, and lint rules.
export default {
    // No `publish.packages` subset: the publishable set is exactly the
    // workspace packages without `private: true`, which is the five platform
    // addon packages. `nifty publish --placeholder` claims those names at
    // 0.0.0 and `nifty trust` binds them to this repository.
    // `nifty trust` configures npm Trusted Publisher from this block, and the
    // release workflow must match these three values exactly.
    trust: {
        npm: {
            repo: "nyar-os/OpenCTF",
            file: "publish-npm.yml",
            environment: "NPM_PUBLISH",
        },
    },
};
