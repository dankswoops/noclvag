## Smelly-noclvag (a NOSTR vanity Npub farmer)

Optimized noclvag for RX 7900 XTX OC.

This could was created by the [Gleasonator](https://codeberg.org/ardraidi/noclvag) himself.

I am not claiming any of his work as my own, only using this repo to A/B hardware hack for faster outputs.

Use this software at your own risk, it was already `as is` software before I played with it.

After upgrading my GPU and 2.5 hours of agentic cooking, I went from <i><small>186m</small></i> key/s to almost <i><strong>900m</strong></i> keys/s.

<p align="center">
  <img alt="Views" src="https://komarev.com/ghpvc/?username=dankswoops-noclvag&style=flat&color=97CA00&label=Views"/>
</p>

## Setup

```
# Choose your name
023456789acdefghjklmnpqrstuvwxyz

# Not availble 
1,b,i,o,

# Open a terminal in the root of the project
cd ~/Documents/Code/noclvag

# Compile if you haven't
make

# Verify both platforms show up
./noclvag-search -l

# Clear the last run if you already ran
rm -f noclvag-secrets.txt noclvag-request.txt noclvag-response.txt

# Generate the search request
./noclvag-tool --step1 npub1danksw00ps
# required "npub1" afterwards is your vanity name.

# Run the search on ROCm at ~898 Mkey/s
./noclvag-search -p 1 -d 0 -w 1024 -2

# Finalize the key once a match is found
./noclvag-tool --step3
```

## Personal conclusion on npub char number

As you can see below, it is a privlage to have a 10 char name. Given moores law, in time this will become more normal. Anything beyond 10 is either a FANNG level company getting into NOSTR for brand reasons or absolute SPOONED rng where you hit 11 and maybe 12 while looking for 10. There will be very few who farm beyond 10 and client devs should not encourage npub vanity beyond 10 chars for reasonable engagement with all users. 10 seems to be the magic number to age into gracefully but not be too exclusive in modern day.

50% probability = 0.693 x 32^N keys. Based on ~900 Mkey/s per RX 7900 XTX.

#### Time required for the user to hit around 10 days.

| Chars | key/s needed | Spec range | Price range |
|-------|-------------|------------|-------------|
| 1 | instant | Any device | $0 |
| 2 | instant | Any device | $0 |
| 3 | instant | Any device | $0 |
| 4 | ~1 /s | Any device | $0 |
| 5 | ~27 /s | Any device | $0 |
| 6 | ~861 /s | Any CPU | $0 |
| 7 | ~28 Kkey/s | Any CPU | $0 |
| 8 | ~882 Kkey/s | Low-end GPU | $200-300 |
| 9 | ~28 Mkey/s | Budget GPU (RX 6600) | $200-350 |
| 10 | ~903 Mkey/s | High-end GPU (RX 7900 XTX) | $800-1500 |
| 11 | ~29 Gkey/s | ~32 high-end GPUs | $25K-50K |
| 12 | ~925 Gkey/s | ~1,000 GPUs | Not feasible |
| 13 | ~30 Tkey/s | ~33,000 GPUs | Not feasible |
| 14 | ~947 Tkey/s | ~1,000,000 GPUs | Not feasible |

#### Time required for the user to hit around 1 year.

| Chars | key/s needed | Spec range | Price range |
|-------|-------------|------------|-------------|
| 1 | instant | Any device | $0 |
| 2 | instant | Any device | $0 |
| 3 | instant | Any device | $0 |
| 4 | instant | Any device | $0 |
| 5 | ~1 /s | Any device | $0 |
| 6 | ~24 /s | Any device | $0 |
| 7 | ~755 /s | Any CPU | $0 |
| 8 | ~24 Kkey/s | Multi-core CPU | $0 |
| 9 | ~773 Kkey/s | Low-end GPU | $200-300 |
| 10 | ~25 Mkey/s | Budget GPU (RX 6600) | $200-350 |
| 11 | ~792 Mkey/s | High-end GPU (RX 7900 XTX) | $800-1500 |
| 12 | ~25 Gkey/s | ~28 high-end GPUs | $22K-42K |
| 13 | ~811 Gkey/s | ~900 GPUs | Not feasible |
| 14 | ~26 Tkey/s | ~29,000 GPUs | Not feasible |

## noclvag Optimization Notes

#### Hardware Profile
- GPU: Asus TUF RX 7900 XTX OC 24GB (RDNA 3, navi31, gfx1100, 96 CUs, wave32)
- CPU: AMD Ryzen 7 3700X, RAM: 32GB, Mobo: Asus TUF B450M (PCIe 3.0 x16)

#### Performance (2026-02-11)
- **Baseline: 595 Mkey/s** (rusticl, unmodified code)
- **Current: 898 Mkey/s** (ROCm, optimized code) — **+51%**
- Rusticl fallback: 717 Mkey/s (+20%)

#### Usage
```bash
# Step 1: Generate search request
./noclvag-tool --step1 npub1<pattern>

# Step 2: Search (ROCm, 898 Mkey/s)
./noclvag-search -p 1 -d 0 -w 1024 -2

# Step 3: Finalize key
./noclvag-tool --step3

# Rusticl fallback (no ROCm needed)
./noclvag-search -p 0 -d 0 -2

# List available platforms
./noclvag-search -l
```

#### Code Changes (all in oclengine.c)

##### 1. Skip DEEP_VLIW on GCN/RDNA GPUs (line ~428)
VLIW-style 3-pass add/subtract was designed for pre-GCN TeraScale (HD 2000-6000).
RDNA 3 is scalar — VLIW codegen is actively harmful. Detection checks device name
for navi/gfx9/gfx10/gfx11/Vega/Polaris/RX 5/6/7 strings.

##### 2. Skip VERY_EXPENSIVE_BRANCHES on GCN/RDNA GPUs (same block)
Full unrolling of Montgomery multiplication outer loop causes register spilling
on wave32 SIMD, killing occupancy. Same detection logic as above.

##### 3. Default GPU worksize 2048 -> 8192 (line 2442)
Lets auto-tuner pick larger grids before hitting the worksize cap.

##### 4. VRAM utilization 50% -> 75% (line 2453)
`memsize /= 2` changed to `memsize = memsize * 3 / 4`. Uses ~18GB of 24GB.

##### 5. Fixed rekey_max infinite loop bug (lines 1808, 1834-1839)
**Root cause:** `rekey_max` was hardcoded to 100M. When grid round size
(rows * cols) exceeded it, the condition `(npoints + round) < rekey_at`
was never true, creating an infinite CPU-only rekey loop with 0% GPU work.
ROCm auto-selected 12288x8192 = 100.7M which crossed this threshold.
**Fix:** Base increased to 1B, plus safety: `if (rekey_max < round * 2) rekey_max = round * 2`.

#### Tuning Rules Learned

##### ROCm vs Rusticl
- ROCm is 25% faster than rusticl for this kernel on RDNA 3
- ROCm prefers **small** worksize (`-w 1024` = 898), rusticl prefers **large** (`-w 65536` = 717)
- ROCm reports 48 CUs (WGPs), rusticl reports 96 CUs — different grid auto-selection

##### Grid Size
- Auto-selected 6144x4096 is near-optimal for both platforms
- Smaller grids (4096x4096) lose ~8% throughput
- Larger grids hit rusticl's 2GB CL_DEVICE_MAX_MEM_ALLOC_SIZE limit and crash
- Never override `-i` (iteration count) — defaults are optimal

##### What Doesn't Help
- `RUSTICL_FEATURES=fp64` — no measurable improvement
- `ACCESS_STRIDE` changes — current 1024/128 already coalesces for wave32
- Manual `-i` override — auto-selected values beat all manual settings

#### ROCm Installation
```bash
wget https://repo.radeon.com/amdgpu-install/7.1.1/ubuntu/noble/amdgpu-install_7.1.1.70101-1_all.deb
sudo apt install ./amdgpu-install_7.1.1.70101-1_all.deb
sudo apt update
sudo amdgpu-install --usecase=opencl --no-dkms
sudo usermod -a -G render,video $LOGNAME
# Reboot required. Platforms: 0=rusticl, 1=ROCm
```

#### Debugging Notes
- Progress output uses `\r` not `\n` — pipe through `tr '\r' '\n'` to parse
- `-v` flag spams "GPU idle" lines that hide Mkey/s — omit for clean output
- .oclbin files are kernel caches keyed by MD5(platform+device+flags+source) — safe to delete
- First run after deleting .oclbin takes minutes for kernel JIT compilation
- If GPU hangs after failed CL_INVALID_BUFFER_SIZE, `pkill -9 noclvag-search` and retry
