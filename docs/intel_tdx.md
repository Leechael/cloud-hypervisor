# Intel TDX on q35

Intel Trust Domain Extensions (TDX) isolate a guest VM from the VMM,
hypervisor, and any other software on the host platform. This fork of
Cloud Hypervisor adds TDX-on-q35 support: a TDX guest can be launched
on Cloud Hypervisor's q35 machine type with the same SMBIOS, fw_cfg,
ACPI, and PCIe topology that QEMU emits, while still going through KVM's
TDX ioctls for measurement and entry/exit.

## 1. Overview

- Both legacy and new KVM TDX ABIs are supported. The hypervisor layer
  detects which ioctl set the running kernel exposes and adapts at
  runtime; no build-time flag is needed.
- Tested on:
  - `phala-tdx-prod1` (kernel `7.0.0-14`, **new** TDX KVM ABI)
  - `phala-tdx-lab` (kernel `6.8.0-1028`, **legacy** TDX KVM ABI)
- Only `x86_64` + `kvm` is maintained in this fork. The `mshv` and
  `aarch64` paths are not validated for TDX here.

Useful upstream references:

- [TDX homepage](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [KVM TDX tree](https://github.com/intel/tdx/tree/kvm)
- [Guest TDX tree](https://github.com/intel/tdx/tree/guest)
- [EDK2](https://github.com/tianocore/edk2) — TDVF firmware
- [td-shim](https://github.com/confidential-containers/td-shim) — minimal TDVF for direct kernel boot
- [tdx-linux](https://github.com/intel/tdx-linux) — host/guest setup helpers

## 2. Building

Build with the `tdx` and `fw_cfg` features (the latter is required for
the SMBIOS / ACPI tables that TDVF measures into RTMR0):

```bash
cargo build --release --features tdx,fw_cfg
```

For explicit clarity (the default backend on Linux x86_64 is `kvm`
already, but spelling it out helps when cross-targeting):

```bash
cargo build --release --features 'tdx,fw_cfg,kvm'
```

The `tdx` feature pulls in the TDX-specific KVM bindings and CPU
init paths. The `fw_cfg` feature is what makes Cloud Hypervisor expose
the QEMU-compatible `fw_cfg` IO port that TDVF queries for SMBIOS,
ACPI, and option ROM blobs.

### TDVF

The latest TDVF tested is
[`13b9773`](https://github.com/tianocore/edk2/commit/13b97736c876919b9786055829caaa4fa46984b7).
Build it with:

```bash
sudo apt-get update
sudo apt-get install uuid-dev nasm iasl build-essential python3-distutils git

git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout 13b97736c876919b9786055829caaa4fa46984b7
source ./edksetup.sh
git submodule update --init --recursive
make -C BaseTools -j "$(nproc)"
build -p OvmfPkg/IntelTdx/IntelTdxX64.dsc -a X64 -t GCC5 -b RELEASE
```

For verbose firmware logs over serial, build with
`-D DEBUG_ON_SERIAL_PORT=TRUE` instead.

### td-shim (optional)

For containerized direct-kernel-boot scenarios, td-shim is a smaller
Rust-based alternative to TDVF. Latest tested is
[`v0.8.0`](https://github.com/confidential-containers/td-shim/releases/tag/v0.8.0).

```bash
git clone https://github.com/confidential-containers/td-shim
cd td-shim
git checkout v0.8.0
cargo install cargo-xbuild
export CC=clang AR=llvm-ar
export CC_x86_64_unknown_none=clang
export AR_x86_64_unknown_none=llvm-ar
git submodule update --init --recursive
./sh_script/preparation.sh
cargo image --release
```

The resulting `target/release/final.bin` is a drop-in for
`--tdx firmware=...`.

## 3. Minimal launch (single-vCPU TDX guest)

```bash
cloud-hypervisor \
  --tdx firmware=/path/ovmf.fd \
  --kernel /path/bzImage \
  --initramfs /path/initramfs.cpio.gz \
  --cmdline "console=ttyS0 init=/init panic=1 random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock" \
  --memory size=512M \
  --cpus boot=1,max=1 \
  --platform num_pci_segments=1,tdx=on \
  --fw-cfg-config '' \
  --serial tty \
  --console off
```

Flag-by-flag:

- `--tdx firmware=...` — enables the TDX path and supplies the TDVF
  binary that TDX module measures into MRTD.
- `--kernel` / `--initramfs` / `--cmdline` — direct kernel boot. TDVF
  will jump to the supplied bzImage.
  - `random.trust_cpu=y` lets RDRAND seed the CRNG (required for TDX
    where there is no host-trusted virtio-rng path).
  - `random.trust_bootloader=n` keeps the firmware out of the trust
    chain for entropy.
  - `tsc=reliable no-kvmclock` keeps timekeeping inside the TD.
- `--memory size=512M` — total guest memory; TDX private memory is
  carved out of this.
- `--cpus boot=1,max=1` — TDX does not currently support vCPU hotplug,
  so `boot == max`.
- `--platform num_pci_segments=1,tdx=on` — legacy q35-compatible TDX
  platform with a single PCI segment. Omit this option to use the
  non-q35/i440fx-compatible TDX PC platform.
- `--fw-cfg-config ''` — enables the fw_cfg IO port with no extra
  user-supplied entries (required for SMBIOS / ACPI delivery to TDVF).
- `--serial tty --console off` — route the guest's `ttyS0` to the
  controlling terminal and disable the virtio-console device.

The preferred style declares the TD object and keeps the non-q35/i440fx
platform:

```bash
# Preferred (this fork)
--tdx firmware=/path/ovmf.fd

# Legacy, still supported
--platform tdx=on --firmware /path/ovmf.fd
```

## 4. `--tdx` configuration

Everything that can go inside `--tdx` (comma-separated `key=value`
pairs):

| Key | Type | Default | Meaning |
|---|---|---|---|
| `firmware` | path | required | Path to the TDVF / td-shim binary. |
| `sept_ve_disable` | `on`/`off` | `on` | Sets attribute bit 28 (SEPT_VE_DISABLE). Required by most production TDX guests. |
| `debug` | `on`/`off` | `off` | Sets attribute bit 0. Enables debug visibility but **changes the measurement** (the TD report binds the attributes). |
| `perfmon` | `on`/`off` | `off` | Sets attribute bit 63 (PERFMON). |
| `mrconfigid` | hex | all-zero | 48 bytes (96 hex chars; dashes allowed) used as MRCONFIGID — image-identity field measured into the TD report. |
| `mrowner` | hex | all-zero | 48 bytes used as MROWNER — owner identity. |
| `mrownerconfig` | hex | all-zero | 48 bytes used as MROWNERCONFIG — owner config. |
| `xfam` | `0xHEX` | derived | XFAM mask override. Default is the intersection of `cpuid 0xd` and `caps.supported_xfam`. |

Example with custom owner / config measurement bindings:

```bash
--tdx firmware=ovmf.fd,sept_ve_disable=on,\
mrconfigid=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,\
mrowner=00...00,\
mrownerconfig=00...00
```

The hypervisor validates `attributes` and `xfam` against
`KVM_TDX_CAPABILITIES` before issuing `KVM_TDX_INIT_VM`; mismatches are
rejected at boot.

## 5. Quote / attestation

The current quote backend is **synchronous AF_VSOCK** to host CID 2:

- Default port: `4050`
- Override via env: `CH_TDX_QGS_PORT`
- The vCPU thread blocks during `connect`/`send`/`recv`. A production
  async backend with a proper `--tdx quote_socket=...` knob is on the
  P2 roadmap.

For the quote path to work, the host must run a Quote Generation
Service (QGS) reachable over AF_VSOCK CID 2 on the configured port,
or have a userspace bridge.

### Bridging Cloud Hypervisor's vsock to the host QGS

Cloud Hypervisor's vsock device terminates inside an AF_UNIX socket on
the host (it does **not** speak native AF_VSOCK to the kernel vsock
stack). To reach a real QGS daemon listening on AF_VSOCK CID 2:

```bash
RUN_DIR=/run/ch-tdx
mkdir -p "$RUN_DIR"
socat \
  UNIX-LISTEN:$RUN_DIR/ch-vsock.sock_4050,fork,reuseaddr \
  VSOCK-CONNECT:2:4050 &

cloud-hypervisor \
  --tdx firmware=ovmf.fd \
  --vsock cid=33,socket=$RUN_DIR/ch-vsock.sock \
  ...
```

The CH-side vsock backend appends `_<port>` to the unix socket path for
each guest-initiated connection, which `socat` then forwards into the
host's AF_VSOCK CID 2.

## 6. SMBIOS attestation strings

Cloud Hypervisor's default SMBIOS table identifies the platform as
"Cloud Hypervisor". For deployments that bind to a specific OEM/SKU,
override per-VM via:

```bash
--platform smbios.bios_vendor=...,smbios.system_uuid=...,smbios.system_product=...,...
```

Full key list (mirrors `vmm/src/vm_config.rs::SmbiosConfig`):

- `bios_vendor`
- `bios_version`
- `bios_release_date` (format: `MM/DD/YYYY`)
- `system_manufacturer`
- `system_product`
- `system_version`
- `system_serial`
- `system_uuid` (32 hex chars or canonical dashed form)
- `system_sku`
- `system_family`
- `chassis_manufacturer`
- `chassis_version`
- `chassis_serial`
- `chassis_asset_tag`
- `processor_manufacturer`
- `processor_version`
- `oem_strings` (colon-separated list)

> SMBIOS strings are delivered through `fw_cfg` and **are measured
> into RTMR0**. Changing any field changes the TD report. Pin the
> values you want bound to your attestation policy and treat them
> as part of the launch identity.

## 7. QEMU equivalence

| QEMU | Cloud Hypervisor |
|---|---|
| `-object tdx-guest,id=tdx,sept-ve-disable=on` | `--tdx firmware=...,sept_ve_disable=on` |
| `-object tdx-guest,debug=on` | `--tdx firmware=...,debug=on` |
| `-object tdx-guest,mrconfigid=BASE64` | `--tdx firmware=...,mrconfigid=HEX` (note: hex, not base64) |
| `-machine confidential-guest-support=tdx` | `--platform tdx=on` |
| `-bios /path/ovmf.fd` | `--tdx firmware=/path/ovmf.fd` |
| `-machine q35,kernel-irqchip=split` | `--platform num_pci_segments=1` (split irqchip is implicit) |
| `-device vhost-vsock-pci,guest-cid=N` | `--vsock cid=N,socket=...` |
| `-virtfs local,path=...,mount_tag=...` | no direct equivalent in this branch |
| `-smbios type=N,...` | `--platform smbios.<field>=...` |

### Minimal QEMU comparison command

The equivalent QEMU q35/TDX launch used for benchmarking
`minimal-tdx-image` examples is:

```bash
qemu-system-x86_64 \
  -accel kvm \
  -cpu host \
  -nographic \
  -nodefaults \
  -chardev file,id=com0,path=/tmp/tdx-serial.log \
  -serial chardev:com0 \
  -kernel /path/bzImage \
  -initrd /path/initramfs.cpio.gz \
  -append "console=ttyS0 init=/init panic=1 random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock out_tag=out out_dir=/mnt/out initrd=initrd" \
  -smp 1 \
  -m 512M \
  -bios /path/ovmf.fd \
  -machine q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off \
  -object tdx-guest,id=tdx
```

For quote tests, add the QGS object and a guest vsock device:

```bash
qemu-system-x86_64 \
  ... \
  -object '{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type":"vsock","cid":"2","port":"4050"}}' \
  -device vhost-vsock-pci,guest-cid=33
```

## 8. Validated benchmark commands

The following commands were used to validate Cloud Hypervisor q35/TDX
against `minimal-tdx-image` hello/memfill/quote examples on both
`phala-tdx-lab` and `phala-tdx-prod1`.

Hello / memfill:

```bash
cloud-hypervisor \
  --tdx firmware=/path/ovmf.fd \
  --kernel /path/bzImage \
  --initramfs /path/initramfs.cpio.gz \
  --cmdline "console=ttyS0 init=/init panic=1 random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock out_tag=out out_dir=/mnt/out" \
  --memory size=512M \
  --cpus boot=1,max=1 \
  --platform num_pci_segments=1,tdx=on \
  --fw-cfg-config '' \
  --serial file=/tmp/ch-tdx-serial.log \
  --console off
```

Quote:

```bash
RUN_DIR=/run/ch-tdx
mkdir -p "$RUN_DIR"

socat \
  UNIX-LISTEN:$RUN_DIR/ch-vsock.sock_4050,fork,reuseaddr \
  VSOCK-CONNECT:2:4050 &

cloud-hypervisor \
  --tdx firmware=/path/ovmf.fd \
  --kernel /path/bzImage \
  --initramfs /path/initramfs.cpio.gz \
  --cmdline "console=ttyS0 init=/init panic=1 random.trust_cpu=y random.trust_bootloader=n tsc=reliable no-kvmclock out_tag=out out_dir=/mnt/out" \
  --memory size=512M \
  --cpus boot=1,max=1 \
  --platform num_pci_segments=1,tdx=on \
  --fw-cfg-config '' \
  --vsock cid=33,socket=$RUN_DIR/ch-vsock.sock \
  --serial file=/tmp/ch-tdx-serial.log \
  --console off
```

Benchmark binaries and hosts:

```text
Cloud Hypervisor branch: lee/tdx-kvm-uapi-supermicro
Cloud Hypervisor head:   ea70e118c kvm: gate legacy guest_memfd hugepage flag
TDX binary sha256:       75ed94c4346a08ff8df504df2a9af578a4618f05c59d0008a5fa357828f0708f

phala-tdx-lab:
  kernel: 6.8.0-1028-intel
  qemu:   8.2.2+tdx1.1

phala-tdx-prod1:
  kernel: 7.0.0-14-generic
  qemu:   10.2.1
```

Median hello wall-time from the q35/no-tdx and q35/TDX matrix:

```text
phala-tdx-lab:
  CH q35/no-tdx direct-kernel:     1.435s
  QEMU q35/no-tdx direct-kernel:   2.162s
  QEMU q35/no-tdx OVMF:            2.701s
  CH q35/TDX OVMF:                 2.980s
  QEMU q35/TDX OVMF:               3.815s

phala-tdx-prod1:
  CH q35/no-tdx direct-kernel:     1.362s
  QEMU q35/no-tdx direct-kernel:   2.054s
  QEMU q35/no-tdx OVMF:            2.310s
  CH q35/TDX OVMF:                 4.432s
  QEMU q35/TDX OVMF:               5.823s
```

Interpretation:

- Cloud Hypervisor keeps a measurable q35/no-tdx advantage over QEMU.
- Enabling TDX dominates total wall time on the new prod1 kernel.
- On the same host and payload, CH q35/TDX remains faster than QEMU
  q35/TDX, but both are dominated by kernel/TDX private-memory work.

Kernel bpftrace comparison for hello showed the prod1 slowdown comes
from nearly full-RAM private page lifecycle work:

```text
phala-tdx-prod1 CH q35/TDX:
  tdh_mem_page_aug              132459
  tdx_sept_set_private_spte     133509
  tdx_sept_remove_private_spte  133509
  kvm_gmem_release              ~1.57s

phala-tdx-prod1 QEMU q35/TDX:
  tdh_mem_page_aug              132459
  tdx_sept_set_private_spte     133509
  tdx_sept_remove_private_spte  133509
  kvm_gmem_release              ~1.07s

phala-tdx-lab QEMU q35/TDX:
  tdx_mem_page_aug              9308
  tdx_sept_set_private_spte     10358
  tdx_sept_remove_private_spte  29776
```

This means the prod1 result is not a Cloud Hypervisor-only hard-coded
path. QEMU on the same host performs the same order of TDX page AUG and
teardown work. The difference is the newer kernel / TDX stack causing
almost the full 512 MiB guest memory range to be populated and later
removed as 4 KiB private pages.

Hugepage backing does not remove this bottleneck on prod1's current
kernel: `arch/x86/kvm/vmx/tdx.c` still forces private SPTE add/remove
to `PG_LEVEL_4K` (`TODO: handle large pages`), and
`virt/kvm/guest_memfd.c::kvm_gmem_populate()` iterates page-by-page.
The older `phala-tdx-lab` kernel has private S-EPT promote/demote code
and does not have the same hard `PG_LEVEL_4K` checks, but current
measurements still show thousands of private 4 KiB operations rather
than hundreds of 2 MiB operations.

## 9. GPU passthrough (P4 status)

The plumbing for VFIO + TDX is in place:

- `RamDiscardManager` + `VfioRamDiscardListener` coordinate share/private
  flips against VFIO DMA mappings (commit `43cd0e095`).
- `KVM_DEV_VFIO_FILE` wiring lets the TDX module see VFIO container
  state at the same point QEMU does (commit `5f3e9d681`).

End-to-end GPU passthrough was **not validated** in this branch due to
lack of a test environment with a TDX-capable host wired to a
passthrough-capable GPU. When such an environment is available, the
expected sequence is:

```bash
# host: bind GPU to vfio-pci (replace vendor:device with your card)
echo "10de 26b1" > /sys/bus/pci/drivers/vfio-pci/new_id

# launch CH with TDX + VFIO
cloud-hypervisor \
  --tdx firmware=ovmf.fd \
  --kernel /path/bzImage \
  --initramfs /path/initramfs.cpio.gz \
  --cmdline "..." \
  --memory size=8G \
  --cpus boot=4 \
  --platform num_pci_segments=1,tdx=on \
  --device path=/sys/bus/pci/devices/<RTX-bdf> \
  --vsock cid=33,socket=/run/ch-tdx/ch-vsock.sock \
  --serial tty --console off
```

`--platform iommu_segments=...` is **supported but not required** for
TDX VFIO. The `RamDiscardListener` fans out DMA-map / DMA-unmap as the
guest flips share/private state, so the standard `--device` path is
sufficient.

## 10. Known limitations

- **No SMM emulation.** OVMF/TDVF must be built non-SMM
  (`SMM_REQUIRE=FALSE` or equivalent). This is consistent with TDX's
  threat model — SMM is host-side and would be outside the TCB anyway.
- **No TDX live migration.** The TDX module does not support migration
  primitives; Cloud Hypervisor will not either.
- **No `KVM_TDX_TERMINATE_VM`.** The fast-teardown ioctl is still at
  RFC stage upstream. Shutdown of large TDX VMs (100+ GiB) takes the
  same time it takes QEMU on the same kernel.
- **No prod1 TDX private hugepage fast path.** On the tested
  `7.0.0-14` kernel, private TDX S-EPT add/remove is still forced to
  4 KiB pages, so hugepage-backed RAM does not collapse the observed
  ~133k per-page AUG/remove operations.
- **PIT/PIC userspace emulation is stub-only.** q35 + split irqchip +
  `KVM_CREATE_PIT2` are mutually exclusive at the KVM ABI level. The
  current `PicStub` / `PitStub` / `Port61` cover OVMF + Linux probe
  but will not satisfy guests that program the i8259 / i8254 in
  detail. A full userspace 8259A / 8254 path is on the P3.1 roadmap.
- **Quote backend is synchronous vsock.** The vCPU thread blocks
  during connect / send / recv. Production async backend is on the P2
  roadmap.
- **`mshv` and `aarch64` paths are not maintained for TDX in this
  fork.** Only `x86_64` + `kvm` is validated.

## 11. Roadmap and references

The full project plan, including completed phases (P0, P1, P3.2, P3.3,
P3.4, P3.5, P4 main framework) and deferred items (P2 quote async,
P3.1 PIT/PIC userspace, P5 legacy CPUID full port), lives in
`CLOUD_HYPERVISOR_TDX_Q35_PLAN.md` in the parent of this checkout
(`/Users/leechael/workshop/phala/supermicro-rtx-6000/CLOUD_HYPERVISOR_TDX_Q35_PLAN.md`
in the development setup this branch was prepared on).

### Guest kernel notes (carried over from upstream)

- The pre-built `td-guest-rhel8.5.raw` image disables serial-port
  output; use virtio-console (`console=hvc0`) when booting that image.
- Without `tdx_disable_filter` on the guest cmdline, the TDX guest
  kernel filters ACPI devices used for PCI hotplug (PCI hotplug
  controller, PCIe Bus, Generic Event Device); PCI hotplug will
  therefore not work in such guests.
