# Hit rate — 2026-09-02

`python3 tests/hitrate.py`: top-starred non-archived GitHub repos with a
manifest at the root (python: requirements.txt/pyproject.toml/setup.py; npm:
package.json), shallow clone, `blanket sync` with zero config, throwaway
store, 600 s cap. Raw data: `tests/fixtures/hitrate-2026-09-02.csv`.
Binary: release build at commit bf7014c (before this session's fixes).

## What the number says

- **Python 10 percent.** The dominant miss is not strictness: 16 of 30
  repos have no `requirements.txt` at all (pyproject.toml projects), and
  blanket did not read pyproject.toml. Item 3 adds `[project].dependencies`
  as an input. After that the real classes are: sdist builds that need
  Rust/numpy/cython at build time (tokenizers, insightface, wgpu), the
  default interpreter (3.12) being newer than what the project pins,
  self-installs (`.`) and direct URL requirements, and a wheel-selector
  bug (`py3-none-macosx_*_arm64`, fixed in 1a1308c).
- **npm 56 percent.** 8 of 13 misses are pnpm (7) or yarn (1) monorepos
  where `npm install --package-lock-only` cannot resolve `workspace:` /
  `catalog:` protocols. A pnpm-lock.yaml importer is the single largest
  npm lever and is not on the original list. The rest: install scripts
  that download binaries (puppeteer, canvas, sqlite3 — items 3 and 5), a
  git+ssh dependency (item 4), a sha1-integrity lock (item 3), and an
  empty dependency set crashing projection (fixed in 1a1308c).
- Ecosystems other than Python and npm were not measured.

## python: 3/30 ok (10%)

| class | n |
|---|---|
| no_inputs | 16 |
| other | 6 |
| py_sdist_build_failed | 3 |
| ok | 3 |
| npm_script_failed | 1 |
| py_uv_resolve_failed | 1 |

| repo | class | s | inputs | error |
|---|---|---|---|---|
| yt-dlp/yt-dlp | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| AUTOMATIC1111/stable-diffusion-webui | py_sdist_build_failed | 24 | requirements.txt,pyproject.toml,package.json | sandboxed build of tokenizers==0.13.3 failed: sandboxed command failed (exit status: 1): ["<store obj> "-m", " |
| ytdl-org/youtube-dl | no_inputs | 0 | setup.py | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| github/spec-kit | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| Comfy-Org/ComfyUI | other | 1 | requirements.txt,pyproject.toml | comfy-angle==0.1.1: no file compatible with cp312 on macOS arm64 among hash-matched files: comfy_angle-0.1.1-p |
| Graphify-Labs/graphify | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| browser-use/browser-use | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| openai/whisper | ok | 8 | requirements.txt,pyproject.toml |  |
| TauricResearch/TradingAgents | other | 0 | requirements.txt,pyproject.toml | only exact '==' pins are supported: . |
| fastapi/fastapi | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| nvbn/thefuck | ok | 5 | requirements.txt,setup.py |  |
| hacksider/Deep-Live-Cam | py_sdist_build_failed | 7 | requirements.txt,pyproject.toml | sandboxed build of insightface==0.7.3 failed: sandboxed command failed (exit status: 1): ["<store obj> "-m", " |
| karpathy/autoresearch | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| 3b1b/manim | py_sdist_build_failed | 10 | requirements.txt,pyproject.toml,setup.py | sandboxed build of wgpu==0.32.0 failed: sandboxed command failed (exit status: 2): ["<store obj> "-m", "pip",  |
| sherlock-project/sherlock | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| vllm-project/vllm | no_inputs | 0 | pyproject.toml,setup.py | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| django/django | npm_script_failed | 24 | pyproject.toml,package.json | node_modules/puppeteer: postinstall script failed under the network-denied build sandbox: sandboxed command fa |
| odysseus-dev/odysseus | other | 15 | requirements.txt,pyproject.toml,setup.py,package.json,package-lock.json | file collision: /private/tmp/claude-501/-Users-ethanabbate-Desktop-System-package-manager/7bbf35c4-b384-4d1f-8 |
| unclecode/crawl4ai | other | 3 | requirements.txt,pyproject.toml,setup.py | patchright==1.62.2: no file compatible with cp312 on macOS arm64 among hash-matched files: patchright-1.62.2-p |
| Z4nzu/hackingtool | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| opendatalab/MinerU | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| D4Vinci/Scrapling | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| Panniantong/Agent-Reach | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| unslothai/unsloth | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| hiyouga/LlamaFactory | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| pallets/flask | no_inputs | 0 | pyproject.toml | nothing to sync here (need requirements.txt, package-lock.json, Cargo.toml, or go.mod) |
| binary-husky/gpt_academic | other | 7 | requirements.txt | only exact '==' pins are supported: gradio@https://public.agent-matrix.com/publish/gradio-3.32.15-py3-none-any |
| ansible/ansible | ok | 1 | requirements.txt,pyproject.toml |  |
| FoundationAgents/MetaGPT | py_uv_resolve_failed | 0 | requirements.txt,setup.py | uv pip compile failed |
| headroomlabs-ai/headroom | other | 0 | pyproject.toml | /private/tmp/claude-501/-Users-ethanabbate-Desktop-System-package-manager/7bbf35c4-b384-4d1f-8219-0025685820ea |

## npm: 17/30 ok (56%)

| class | n |
|---|---|
| ok | 17 |
| npm_resolve_failed | 8 |
| other | 3 |
| npm_script_failed | 2 |

| repo | class | s | inputs | error |
|---|---|---|---|---|
| affaan-m/ECC | ok | 24 | pyproject.toml,package.json,package-lock.json,yarn.lock |  |
| vuejs/vue | npm_resolve_failed | 0 | package.json,pnpm-lock.yaml | npm install --package-lock-only failed |
| deepseek-ai/deepseek-harness | npm_resolve_failed | 9 | package.json,pnpm-lock.yaml | npm install --package-lock-only failed |
| airbnb/javascript | ok | 7 | package.json |  |
| clash-verge-rev/clash-verge-rev | other | 18 | package.json,pnpm-lock.yaml | node_modules/tauri-plugin-mihomo-api: only https registry tarballs supported (v0), got git+ssh://git@github.co |
| garrytan/gstack | ok | 31 | package.json,bun.lock |  |
| excalidraw/excalidraw | ok | 152 | package.json,yarn.lock |  |
| shadcn-ui/ui | npm_resolve_failed | 7 | package.json,pnpm-lock.yaml | npm install --package-lock-only failed |
| DietrichGebert/ponytail | other | 0 | package.json | No such file or directory (os error 2) |
| axios/axios | ok | 59 | package.json,package-lock.json |  |
| google-gemini/gemini-cli | ok | 131 | package.json,package-lock.json |  |
| react/create-react-app | other | 0 | package.json,package-lock.json | unsupported integrity algorithm: sha1 |
| earendil-works/pi | npm_script_failed | 35 | package.json,package-lock.json | node_modules/canvas: install script failed under the network-denied build sandbox: sandboxed command failed (e |
| ant-design/ant-design | ok | 416 | package.json |  |
| tailwindlabs/tailwindcss | npm_resolve_failed | 1 | package.json,pnpm-lock.yaml | npm install --package-lock-only failed |
| microsoft/playwright | ok | 62 | package.json,package-lock.json |  |
| louislam/uptime-kuma | npm_script_failed | 122 | package.json,package-lock.json | node_modules/@louislam/sqlite3: install script failed under the network-denied build sandbox: sandboxed comman |
| mermaid-js/mermaid | ok | 162 | package.json,pnpm-lock.yaml |  |
| modelcontextprotocol/servers | ok | 27 | package.json,package-lock.json |  |
| ChatGPTNextWeb/NextChat | ok | 351 | package.json,yarn.lock |  |
| sveltejs/svelte | npm_resolve_failed | 2 | package.json,pnpm-lock.yaml | npm install --package-lock-only failed |
| koala73/worldmonitor | ok | 185 | package.json,package-lock.json |  |
| vitejs/vite | npm_resolve_failed | 3 | package.json,pnpm-lock.yaml | npm install --package-lock-only failed |
| Egonex-AI/Understand-Anything | ok | 19 | package.json,pnpm-lock.yaml |  |
| hoppscotch/hoppscotch | npm_resolve_failed | 11 | package.json,pnpm-lock.yaml | npm install --package-lock-only failed |
| paperclipai/paperclip | ok | 10 | package.json,pnpm-lock.yaml |  |
| anuraghazra/github-readme-stats | ok | 55 | package.json,package-lock.json |  |
| coder/code-server | ok | 46 | package.json,package-lock.json |  |
| typicode/json-server | ok | 13 | package.json,pnpm-lock.yaml |  |
| Eugeny/tabby | npm_resolve_failed | 5 | package.json,yarn.lock | npm install --package-lock-only failed |

## After item 3 (commit 3a3d96c) — re-run of the 28 fixable misses

Raw data: `tests/fixtures/hitrate-2026-09-02-after.csv`. The 4 sdist/uv-resolve
failures were not re-run (unchanged by item 3).

| lang | before | after |
|---|---|---|
| python | 3/30 (10%) | 18/30 (60%) |
| npm | 17/30 (56%) | 21/30 (70%) |

Remaining misses after item 3:

- python AUTOMATIC1111/stable-diffusion-webui: py_sdist_build_failed — blanket: error: sandboxed build of tokenizers==0.13.3 failed: sandboxed command failed (exit status: 1): ["/pr
- python ytdl-org/youtube-dl: no_inputs — blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project].dependencies, packa
- python fastapi/fastapi: other — blanket: error: no pinned CPython matching '3.11'
- python hacksider/Deep-Live-Cam: py_sdist_build_failed — blanket: error: sandboxed build of insightface==0.7.3 failed: sandboxed command failed (exit status: 1): ["/pr
- python karpathy/autoresearch: other — blanket: error: no pinned CPython matching '3.10'
- python 3b1b/manim: py_sdist_build_failed — blanket: error: sandboxed build of wgpu==0.32.0 failed: sandboxed command failed (exit status: 2): ["/private/
- python sherlock-project/sherlock: no_inputs — blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project].dependencies, packa
- python vllm-project/vllm: no_inputs — blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project].dependencies, packa
- python unclecode/crawl4ai: other — blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/greenlet.h
- python binary-husky/gpt_academic: other — blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/greenlet.h
- python FoundationAgents/MetaGPT: py_uv_resolve_failed — blanket: error: uv pip compile failed
- python headroomlabs-ai/headroom: other — blanket: error: /private/tmp/claude-501/-Users-ethanabbate-Desktop-System-package-manager/7bbf35c4-b384-4d1f-8
- npm vuejs/vue: npm_resolve_failed — blanket: error: npm install --package-lock-only failed
- npm deepseek-ai/deepseek-harness: npm_resolve_failed — blanket: error: npm install --package-lock-only failed
- npm clash-verge-rev/clash-verge-rev: other — blanket: error: node_modules/tauri-plugin-mihomo-api: only https registry tarballs supported (v0), got git+ssh
- npm shadcn-ui/ui: npm_resolve_failed — blanket: error: npm install --package-lock-only failed
- npm tailwindlabs/tailwindcss: npm_resolve_failed — blanket: error: npm install --package-lock-only failed
- npm sveltejs/svelte: npm_resolve_failed — blanket: error: npm install --package-lock-only failed
- npm vitejs/vite: npm_resolve_failed — blanket: error: npm install --package-lock-only failed
- npm hoppscotch/hoppscotch: npm_resolve_failed — blanket: error: npm install --package-lock-only failed
- npm Eugeny/tabby: npm_resolve_failed — blanket: error: npm install --package-lock-only failed

## Linux x86_64 — 2026-09-05 (m6-fedora, Fedora 44, blanket at 496c612)
Same 60 repos, pinned via `tests/fixtures/hitrate-repos.lock` to their default-branch commit as of the macOS measurement day (2026-09-02); `python3 tests/hitrate.py --repos … --timeout 600`, throwaway store on disk, release build. The macOS column is the 2026-09-02 run with the 'after item 3' re-run overlaid (18/30 python, 21/30 npm). Raw data: `tests/fixtures/hitrate-linux-2026-09-05.csv`.

### python: Linux 16/30 (53%) vs macOS 18/30 (60%); 4 of the Linux oks carried permissive exceptions
| class (Linux) | n |
|---|---|
| ok | 16 |
| other | 5 |
| py_sdist_build_failed | 3 |
| no_inputs | 3 |
| platform_unsupported | 2 |
| py_uv_resolve_failed | 1 |

| repo | macOS | Linux | Linux exceptions | Linux error (truncated) |
|---|---|---|---|---|
| 3b1b/manim | py_sdist_build_failed | py_sdist_build_failed |  | blanket: error: sandboxed build of manimpango==0.6.1 failed: sandboxed command failed (exi |
| ansible/ansible | ok | ok |  |  |
| AUTOMATIC1111/stable-diffusion-webui | py_sdist_build_failed | py_sdist_build_failed |  | blanket: error: sandboxed build of tokenizers==0.13.3 failed: sandboxed command failed (ex |
| binary-husky/gpt_academic | other | other |  | blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/ |
| browser-use/browser-use | ok | ok |  |  |
| Comfy-Org/ComfyUI | ok | other **↓** |  | blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/ |
| D4Vinci/Scrapling | ok | ok |  |  |
| django/django | ok | ok | install-script-failed |  |
| fastapi/fastapi | other | platform_unsupported |  | blanket: error: no cpython 3.11 pinned for x86_64-unknown-linux-gnu (LINUX_PORT.md stage 2 |
| FoundationAgents/MetaGPT | py_uv_resolve_failed | py_uv_resolve_failed |  | blanket: error: uv pip compile failed |
| github/spec-kit | ok | ok |  |  |
| Graphify-Labs/graphify | ok | ok |  |  |
| hacksider/Deep-Live-Cam | py_sdist_build_failed | py_sdist_build_failed |  | blanket: error: sandboxed build of insightface==0.7.3 failed: sandboxed command failed (ex |
| headroomlabs-ai/headroom | other | other |  | blanket: error: /home/ethan/scratch/hitrate/work/repo/rust-toolchain.toml: unsupported Rus |
| hiyouga/LlamaFactory | ok | ok | file-collision,file-collision |  |
| karpathy/autoresearch | other | platform_unsupported |  | blanket: error: no cpython 3.10 pinned for x86_64-unknown-linux-gnu (LINUX_PORT.md stage 2 |
| nvbn/thefuck | ok | ok |  |  |
| odysseus-dev/odysseus | ok | other **↓** |  | blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/ |
| openai/whisper | ok | ok |  |  |
| opendatalab/MinerU | ok | ok | file-collision,file-collision |  |
| pallets/flask | ok | ok |  |  |
| Panniantong/Agent-Reach | ok | ok |  |  |
| sherlock-project/sherlock | no_inputs | no_inputs |  | blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project] |
| TauricResearch/TradingAgents | ok | ok | requirement-skipped |  |
| unclecode/crawl4ai | other | other |  | blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/ |
| unslothai/unsloth | ok | ok |  |  |
| vllm-project/vllm | no_inputs | no_inputs |  | blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project] |
| yt-dlp/yt-dlp | ok | ok |  |  |
| ytdl-org/youtube-dl | no_inputs | no_inputs |  | blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project] |
| Z4nzu/hackingtool | ok | ok |  |  |

### npm: Linux 14/30 (46%) vs macOS 21/30 (70%); 2 of the Linux oks carried permissive exceptions
| class (Linux) | n |
|---|---|
| ok | 14 |
| other | 8 |
| npm_resolve_failed | 8 |

| repo | macOS | Linux | Linux exceptions | Linux error (truncated) |
|---|---|---|---|---|
| affaan-m/ECC | ok | ok |  |  |
| airbnb/javascript | ok | ok |  |  |
| ant-design/ant-design | ok | other **↓** |  | blanket: error: node_modules/pixelmatch/node_modules/pngjs: tarball extraction failed |
| anuraghazra/github-readme-stats | ok | ok |  |  |
| axios/axios | ok | other **↓** |  | blanket: error: node_modules/pngjs: tarball extraction failed |
| ChatGPTNextWeb/NextChat | ok | ok |  |  |
| clash-verge-rev/clash-verge-rev | other | other |  | blanket: error: node_modules/tauri-plugin-mihomo-api: only https registry tarballs support |
| coder/code-server | ok | ok |  |  |
| deepseek-ai/deepseek-harness | npm_resolve_failed | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| DietrichGebert/ponytail | ok | ok |  |  |
| earendil-works/pi | ok | ok | install-script-failed |  |
| Egonex-AI/Understand-Anything | ok | ok |  |  |
| Eugeny/tabby | npm_resolve_failed | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| excalidraw/excalidraw | ok | other **↓** |  | blanket: error: node_modules/@excalidraw/random-username: tarball extraction failed |
| garrytan/gstack | ok | ok | install-script-failed |  |
| google-gemini/gemini-cli | ok | ok |  |  |
| hoppscotch/hoppscotch | npm_resolve_failed | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| koala73/worldmonitor | ok | other **↓** |  | blanket: error: node_modules/@amcharts/amcharts5: tarball extraction failed |
| louislam/uptime-kuma | ok | other **↓** |  | blanket: error: node_modules/pngjs: tarball extraction failed |
| mermaid-js/mermaid | ok | ok |  |  |
| microsoft/playwright | ok | other **↓** |  | blanket: error: node_modules/pngjs: tarball extraction failed |
| modelcontextprotocol/servers | ok | ok |  |  |
| paperclipai/paperclip | ok | ok |  |  |
| react/create-react-app | ok | other **↓** |  | blanket: error: node_modules/eta: tarball extraction failed |
| shadcn-ui/ui | npm_resolve_failed | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| sveltejs/svelte | npm_resolve_failed | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| tailwindlabs/tailwindcss | npm_resolve_failed | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| typicode/json-server | ok | ok |  |  |
| vitejs/vite | npm_resolve_failed | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| vuejs/vue | npm_resolve_failed | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |

### After the GNU tar fix — re-run of the 7 Linux-only npm misses

All seven Linux-only npm misses were one bug: `tarball extraction failed`
on packages whose tarball directories carry mode 0666 (pngjs in four of
them, eta 1.x, `@amcharts/amcharts5`, `@excalidraw/random-username`).
bsdtar on macOS descends into such directories anyway; GNU tar 1.35
creates the directory 0666 and then cannot open its children. Fix:
`--delay-directory-restore` on Linux only (`src/npm.rs`; `normalize_modes`
rewrites every mode afterwards, so store content and ids are unchanged).
Raw data: `tests/fixtures/hitrate-linux-2026-09-05-after.csv`.

| lang | Linux before | Linux after | macOS |
|---|---|---|---|
| python | 16/30 (53%) | 16/30 (53%) | 18/30 (60%) |
| npm | 14/30 (46%) | 21/30 (70%) | 21/30 (70%) |

Re-run: ant-design/ant-design, axios/axios, excalidraw/excalidraw,
koala73/worldmonitor, louislam/uptime-kuma, microsoft/playwright,
react/create-react-app — 7/7 ok, 2 with permissive install-script
exceptions. The remaining nine npm misses are the same nine repos that
miss on macOS (lockfile-less pnpm/yarn monorepos and the git+ssh
dependency).

### What the Linux numbers say

- **npm is at parity** after the tar fix: 21/30 on both platforms, same
  nine misses (NEXT.md item 7 covers most of them).
- **Python is two repos short of parity.** The two Linux-only misses
  (ComfyUI, odysseus) are `unsupported wheel .data scheme 'headers'` from
  greenlet 3.5.5 — the same bug that already misses crawl4ai and
  gpt_academic on macOS; on Linux the manylinux resolution picks that
  greenlet where macOS picked a different one. Fixing `.data/headers`
  handling lifts both platforms. The two `platform_unsupported` rows
  (fastapi, autoresearch: no pinned CPython 3.10/3.11) miss on macOS too,
  just classed as `other` there. Everything else is the same class on
  both hosts: sdists needing Rust/numpy/cython at build time and repos
  without a readable manifest.
- Exceptions are counted separately from clean oks; the macOS column
  never distinguished them, so treat the macOS `ok` as an upper bound.
- Wall time on the 12-core box was well under the 600 s cap for every
  repo that did not hit a build wall; re-measure here, not on the Mac.
### NEXT item 7 measurement — 2026-09-05

Command: `python3 tests/hitrate.py --repos $HOME/scratch/tmp/nx7-repos.tsv
--work $HOME/scratch/tmp/nx7-hr --out $HOME/scratch/tmp/nx7-hr.csv
--timeout 900 --only npm` after `cargo build --release`.

| repo | result | class | one-line reason |
|---|---|---|---|
| vuejs/vue | fail | npm_ws_nested | `@types/estree` 0.0.39 vs 0.0.48 would need a nested workspace install in `packages/compiler-sfc` |
| deepseek-ai/deepseek-harness | fail | npm_ws_nested | `commander` 8.3.0 vs 15.0.0 would need a nested workspace install in `apps/cli` |
| shadcn-ui/ui | fail | npm_ws_nested | `@typescript-eslint/parser` 8.54.0 vs 8.39.0 would need a nested workspace install in `apps/v4` |
| tailwindlabs/tailwindcss | fail | npm_ws_nested | `@emnapi/core` 2.0.0-alpha.3 vs 1.11.3 would need a nested workspace install in `crates/node` |
| sveltejs/svelte | fail | npm_ws_nested | `esbuild` 0.27.7 vs 0.28.1 would need a nested workspace install in `packages/svelte` |
| vitejs/vite | fail | npm_ws_nested | `magic-string` 0.30.21 vs 1.2.3 would need a nested workspace install in `packages/plugin-legacy` |
| hoppscotch/hoppscotch | fail | npm_ws_nested | `rollup` 2.80.0 vs 4.59.0 would need a nested workspace install in `packages/codemirror-lang-graphql` |
| Eugeny/tabby | fail | npm_script_failed | Yarn’s `@electron/node-gyp` GitHub tarball did not match its lock hash during realization |

This run is 0/8, below the requested 5/8 target. The seven workspace
failures are the deliberately fail-closed branch required when the existing
forest cannot project a package-local `node_modules`; the Yarn miss is an
artifact/hash failure after direct import, not npm re-resolution.

### After item 7, round 2 — 2026-09-06

Command: `cargo build --release`; then
`python3 tests/hitrate.py --repos $HOME/scratch/tmp/nx7-repos.tsv
--work $HOME/scratch/tmp/nx7-hr2 --out $HOME/scratch/tmp/nx7-hr2-rerun3.csv
--timeout 900 --only npm`. This is the eight pinned repositories from the
round-1 table, with a fresh CSV. Result: **5/8 syncs ok (62%)**, including
three with permissive `install-script-failed` exceptions.

| repo | result | class | one-line reason |
|---|---|---|---|
| vuejs/vue | ok | ok | pnpm v6 synthetic `file:` root link and workspace-local importer trees projected |
| deepseek-ai/deepseek-harness | ok | ok | workspace-local version conflicts projected |
| shadcn-ui/ui | ok | ok | workspace-local version conflicts projected |
| tailwindlabs/tailwindcss | fail | npm_script_failed | an install script hit `Permission denied (os error 13)` in the required sandbox |
| sveltejs/svelte | ok | ok | workspace-local version conflicts projected |
| vitejs/vite | ok | ok | aliased local `file:` dependency projected and workspace trees resolved |
| hoppscotch/hoppscotch | fail | npm_git_dep | codeload GitHub dependency is deferred to NEXT.md item 4 |
| Eugeny/tabby | fail | npm_git_dep | GitHub `@electron/node-gyp` dependency is deferred to NEXT.md item 4 |

The measurement exceeded the requested 5/8 target. The tailwind failure is
not a workspace-placement failure; its exact script-side operation remains
unverified beyond the sandbox's permission diagnostic. The hoppscotch and
Tabby misses are intentional future git-source coverage.

**Stale since 2026-09-06:** item 4 shipped after this run (git dependencies are
realized from their commit in npm, python and cargo, PRs #14–#16), so the
`npm_git_dep` blocker behind the hoppscotch and Tabby rows no longer exists.
Neither repo has been re-measured — the rows above are what was true on the
day, not what is true now. Re-run before quoting this table's hit rate.
