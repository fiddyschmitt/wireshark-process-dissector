# Releasing

The version lives in one place: `local VERSION` near the top of `process_dissector.lua`.
Bump it **first**, tag locally, then create the release — so the tag, the source, and the
`.lua` people download always agree.

1. Set `VERSION` in `process_dissector.lua` to the new `X.Y.Z`.
2. `tshark -X lua_script:process_dissector.lua -X lua_script:tests/run_tests.lua -r tests/empty.pcap` → all pass.
3. `git commit -am "Bump version to X.Y.Z" && git push`
4. `git tag vX.Y.Z && git push origin vX.Y.Z` — the pre-push hook checks `VERSION == X.Y.Z` and blocks a mismatch.
5. `gh release create vX.Y.Z process_dissector.lua --title "wireshark-process-dissector vX.Y.Z" --notes "..."`
   — the tag already exists (step 4), so `gh` reuses it instead of cutting a new, unchecked one.

Enable the hook once per clone: `git config core.hooksPath .githooks`
