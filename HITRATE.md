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
Same 60 repos, pinned via `tests/fixtures/hitrate-repos.lock` to their default-branch commit as of the macOS measurement day (2026-09-02); `python3 tests/hitrate.py --repos … --timeout 600`, throwaway store on disk, release build. The macOS column is the 2026-09-02 'after item 3' run. Raw data: `tests/fixtures/hitrate-linux-2026-09-05.csv`.

### python: Linux 16/30 (53%) vs macOS 15/30 (50%); 4 of the Linux oks carried permissive exceptions
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
| 3b1b/manim | — | py_sdist_build_failed |  | blanket: error: sandboxed build of manimpango==0.6.1 failed: sandboxed command failed (exi |
| AUTOMATIC1111/stable-diffusion-webui | — | py_sdist_build_failed |  | blanket: error: sandboxed build of tokenizers==0.13.3 failed: sandboxed command failed (ex |
| Comfy-Org/ComfyUI | ok | other **↓** |  | blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/ |
| D4Vinci/Scrapling | ok | ok |  |  |
| FoundationAgents/MetaGPT | — | py_uv_resolve_failed |  | blanket: error: uv pip compile failed |
| Graphify-Labs/graphify | ok | ok |  |  |
| Panniantong/Agent-Reach | ok | ok |  |  |
| TauricResearch/TradingAgents | ok | ok | requirement-skipped |  |
| Z4nzu/hackingtool | ok | ok |  |  |
| ansible/ansible | — | ok **↑** |  |  |
| binary-husky/gpt_academic | other | other |  | blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/ |
| browser-use/browser-use | ok | ok |  |  |
| django/django | ok | ok | install-script-failed |  |
| fastapi/fastapi | other | platform_unsupported |  | blanket: error: no cpython 3.11 pinned for x86_64-unknown-linux-gnu (LINUX_PORT.md stage 2 |
| github/spec-kit | ok | ok |  |  |
| hacksider/Deep-Live-Cam | — | py_sdist_build_failed |  | blanket: error: sandboxed build of insightface==0.7.3 failed: sandboxed command failed (ex |
| headroomlabs-ai/headroom | other | other |  | blanket: error: /home/ethan/scratch/hitrate/work/repo/rust-toolchain.toml: unsupported Rus |
| hiyouga/LlamaFactory | ok | ok | file-collision,file-collision |  |
| karpathy/autoresearch | other | platform_unsupported |  | blanket: error: no cpython 3.10 pinned for x86_64-unknown-linux-gnu (LINUX_PORT.md stage 2 |
| nvbn/thefuck | — | ok **↑** |  |  |
| odysseus-dev/odysseus | ok | other **↓** |  | blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/ |
| openai/whisper | — | ok **↑** |  |  |
| opendatalab/MinerU | ok | ok | file-collision,file-collision |  |
| pallets/flask | ok | ok |  |  |
| sherlock-project/sherlock | no_inputs | no_inputs |  | blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project] |
| unclecode/crawl4ai | other | other |  | blanket: error: unsupported wheel .data scheme 'headers' in greenlet-3.5.5.data/headers/ |
| unslothai/unsloth | ok | ok |  |  |
| vllm-project/vllm | no_inputs | no_inputs |  | blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project] |
| yt-dlp/yt-dlp | ok | ok |  |  |
| ytdl-org/youtube-dl | no_inputs | no_inputs |  | blanket: error: nothing to sync here (need requirements.txt, pyproject.toml with [project] |

### npm: Linux 14/30 (46%) vs macOS 4/30 (13%); 2 of the Linux oks carried permissive exceptions
| class (Linux) | n |
|---|---|
| ok | 14 |
| npm_resolve_failed | 8 |
| other | 8 |

| repo | macOS | Linux | Linux exceptions | Linux error (truncated) |
|---|---|---|---|---|
| ChatGPTNextWeb/NextChat | — | ok **↑** |  |  |
| DietrichGebert/ponytail | ok | ok |  |  |
| Egonex-AI/Understand-Anything | — | ok **↑** |  |  |
| Eugeny/tabby | — | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| affaan-m/ECC | — | ok **↑** |  |  |
| airbnb/javascript | — | ok **↑** |  |  |
| ant-design/ant-design | — | other |  | blanket: error: node_modules/pixelmatch/node_modules/pngjs: tarball extraction failed |
| anuraghazra/github-readme-stats | — | ok **↑** |  |  |
| axios/axios | — | other |  | blanket: error: node_modules/pngjs: tarball extraction failed |
| clash-verge-rev/clash-verge-rev | other | other |  | blanket: error: node_modules/tauri-plugin-mihomo-api: only https registry tarballs support |
| coder/code-server | — | ok **↑** |  |  |
| deepseek-ai/deepseek-harness | — | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| earendil-works/pi | ok | ok | install-script-failed |  |
| excalidraw/excalidraw | — | other |  | blanket: error: node_modules/@excalidraw/random-username: tarball extraction failed |
| garrytan/gstack | — | ok **↑** | install-script-failed |  |
| google-gemini/gemini-cli | — | ok **↑** |  |  |
| hoppscotch/hoppscotch | — | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| koala73/worldmonitor | — | other |  | blanket: error: node_modules/@amcharts/amcharts5: tarball extraction failed |
| louislam/uptime-kuma | ok | other **↓** |  | blanket: error: node_modules/pngjs: tarball extraction failed |
| mermaid-js/mermaid | — | ok **↑** |  |  |
| microsoft/playwright | — | other |  | blanket: error: node_modules/pngjs: tarball extraction failed |
| modelcontextprotocol/servers | — | ok **↑** |  |  |
| paperclipai/paperclip | — | ok **↑** |  |  |
| react/create-react-app | ok | other **↓** |  | blanket: error: node_modules/eta: tarball extraction failed |
| shadcn-ui/ui | — | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| sveltejs/svelte | — | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| tailwindlabs/tailwindcss | — | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| typicode/json-server | — | ok **↑** |  |  |
| vitejs/vite | — | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |
| vuejs/vue | — | npm_resolve_failed |  | blanket: error: npm install --package-lock-only failed |

### What the Linux numbers say

- **Python is close to parity** (Linux vs macOS above). Linux-only misses
  are dominated by the same classes as macOS — sdists needing Rust/numpy/
  cython at build time and repos without a readable manifest — plus a
  new class, `platform_unsupported`, which is blanket refusing something
  loudly on Linux (read the error column; each is a follow-up, not a
  silent failure). Where Linux wins, it is manylinux wheels existing
  where macOS arm64 wheels did not.
- **npm is lower on Linux** and the delta is concentrated in
  `npm_resolve_failed` / `other`: install scripts and platform packages
  that behave differently under the bubblewrap sandbox than under
  Seatbelt, and pnpm/yarn monorepos (NEXT.md item 7) which miss on both.
  Each Linux-only npm miss is listed above with its error; these are the
  stage 5 follow-ups.
- Exceptions are now counted separately from clean oks; the macOS
  column never distinguished them, so treat the macOS `ok` as an upper
  bound.
- Wall time on the 12-core box was well under the 600 s cap for every
  repo that did not hit a build wall.
