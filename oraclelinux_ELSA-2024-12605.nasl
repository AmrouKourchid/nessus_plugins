#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12605.
##

include('compat.inc');

if (description)
{
  script_id(206427);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2021-3638",
    "CVE-2021-3750",
    "CVE-2023-0664",
    "CVE-2023-3019",
    "CVE-2023-4135",
    "CVE-2023-5088",
    "CVE-2023-6683",
    "CVE-2023-6693",
    "CVE-2023-40360",
    "CVE-2023-42467",
    "CVE-2024-1441",
    "CVE-2024-3446",
    "CVE-2024-3447",
    "CVE-2024-3567",
    "CVE-2024-4418",
    "CVE-2024-24474",
    "CVE-2024-26327",
    "CVE-2024-26328"
  );
  script_xref(name:"IAVA", value:"2024-A-0184");

  script_name(english:"Oracle Linux 8 : virt:kvm_utils2 (ELSA-2024-12605)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12605 advisory.

    - Fixes: CVE-2021-33285, CVE-2021-33286, CVE-2021-33287, CVE-2021-33289,
      CVE-2021-35266, CVE-2021-35267, CVE-2021-35268, CVE-2021-35269,
      CVE-2021-39251, CVE-2021-39252, CVE-2021-39253, CVE-2021-39254
      resolves: rhbz#2004490
    - Fix for CVE-2019-9755
      (heap-based buffer overflow leads to local root privilege escalation)
      resolves: rhbz#1698503
    - Fix CVE-2022-0485: Fail nbdcopy if NBD read or write fails
      resolves: rhbz#2045718
    - Contains fix for NBD Protocol Downgrade Attack (CVE-2019-14842).
    - Fix CVE-2021-3746 libtpms: out-of-bounds access via specially crafted TPM 2 command packets
      Resolves: rhbz#1999307
    - Fix CVE-2021-3623: out-of-bounds access when trying to resume the state of the vTPM
      Fixes: rhbz#1976816
    - rpc: ensure temporary GSource is removed from client event loop (Daniel P. Berrange) [Orabug: 36821476]
    {CVE-2024-4418}
    - Fix off-by-one error in udevListInterfacesByStatus (Martin Kletzander) [Orabug: 36364471]
    {CVE-2024-1441}
    - virpci: Resolve leak in virPCIVirtualFunctionList cleanup (Tim Shearer) [Orabug: 35395469]
    {CVE-2023-2700}
    - qemu: remove use of qemuDomainObjBeginJobWithAgent() (Jonathon Jongsma)  [Orabug: 31990187]
    {CVE-2019-20485}
    - qemu: agent: set ifname to NULL after freeing (Jan Tomko)  [Orabug: 31964426]  {CVE-2020-25637}
    - rpc: require write acl for guest agent in virDomainInterfaceAddresses  (Jan Tomko)  [Orabug: 31964426]
    {CVE-2020-25637}
    - rpc: add support for filtering @acls by uint params  (Jan Tomko)  [Orabug: 31964426]  {CVE-2020-25637}
    - rpc: gendispatch: handle empty flags (Jan Tomko)  [Orabug: 31964426]  {CVE-2020-25637}
    - storage: Fix daemon crash on lookup storagepool by targetpath (Yi Li)  [Orabug: 31439483]
    {CVE-2020-10703}
    - qemuDomainGetStatsIOThread: Don't leak array with 0 iothreads (Peter Krempa)  [Orabug: 31251756]
    {CVE-2020-12430}
    - qemu: don't hold both jobs for suspend (Jonathon Jongsma)  [Orabug: 31073098]  {CVE-2019-20485}
    - Fix CVE-2021-3716 NBD_OPT_STRUCTURED_REPLY injection on STARTTLS
      resolves: rhbz#1994915
    - Document CVEs (Mark Kanda) {CVE-2023-4135} {CVE-2023-40360} {CVE-2024-26328} {CVE-2023-42467}
    {CVE-2024-26327} {CVE-2024-3567}
    - hw/sd/sdhci: Do not update TRNMOD when Command Inhibit (DAT) is set (Philippe Mathieu-Daude) [Orabug:
    36858718] {CVE-2024-3447}
    - hw/virtio/virtio-crypto: Protect from DMA re-entrancy bugs (Philippe Mathieu-Daude) [Orabug: 36878301]
    {CVE-2024-3446}
    - hw/char/virtio-serial-bus: Protect from DMA re-entrancy bugs (Philippe Mathieu-Daude) [Orabug: 36878301]
    {CVE-2024-3446}
    - hw/display/virtio-gpu: Protect from DMA re-entrancy bugs (Philippe Mathieu-Daude) [Orabug: 36878301]
    {CVE-2024-3446}
    - hw/virtio: Introduce virtio_bh_new_guarded() helper (Philippe Mathieu-Daude) [Orabug: 36878301]
    {CVE-2024-3446}
    - ui/clipboard: add asserts for update and request (Fiona Ebner) [Orabug: 36858698] {CVE-2023-6683}
    - ui/clipboard: mark type as not available when there is no data (Fiona Ebner) [Orabug: 36858698]
    {CVE-2023-6683}
    - virtio-net: correctly copy vnet header when flushing TX (Jason Wang) [Orabug: 36858734] {CVE-2023-6693}
    - esp: restrict non-DMA transfer length to that of available data (Mark Cave-Ayland) [Orabug: 36858704]
    {CVE-2024-24474}
    - tests/qtest: ahci-test: add test exposing reset issue with pending callback (Fiona Ebner) [Orabug:
    36858692] {CVE-2023-5088}
    - hw/ide: reset: cancel async DMA operation before resetting state (Fiona Ebner) [Orabug: 36858692]
    {CVE-2023-5088}
    - net: Update MemReentrancyGuard for NIC (Akihiko Odaki) [Orabug: 36858836] {CVE-2023-3019}
    - net: Provide MemReentrancyGuard * to qemu_new_nic() (Akihiko Odaki) [Orabug: 36858836] {CVE-2023-3019}
    - lsi53c895a: disable reentrancy detection for MMIO region, too (Thomas Huth) [Orabug: 36858811]
    {CVE-2021-3750}
    - memory: stricter checks prior to unsetting engaged_in_io (Alexander Bulekov) [Orabug: 36858811]
    {CVE-2021-3750}
    - async: avoid use-after-free on re-entrancy guard (Alexander Bulekov) [Orabug: 36858811] {CVE-2021-3750}
    - apic: disable reentrancy detection for apic-msi (Alexander Bulekov) [Orabug: 36858811] {CVE-2021-3750}
    - raven: disable reentrancy detection for iomem (Alexander Bulekov) [Orabug: 36858811] {CVE-2021-3750}
    - bcm2835_property: disable reentrancy detection for iomem (Alexander Bulekov) [Orabug: 36858811]
    {CVE-2021-3750}
    - lsi53c895a: disable reentrancy detection for script RAM (Alexander Bulekov) [Orabug: 36858811]
    {CVE-2021-3750}
    - hw: replace most qemu_bh_new calls with qemu_bh_new_guarded (Alexander Bulekov) [Orabug: 36858811]
    {CVE-2021-3750}
    - checkpatch: add qemu_bh_new/aio_bh_new checks (Alexander Bulekov) [Orabug: 36858811] {CVE-2021-3750}
    - async: Add an optional reentrancy guard to the BH API (Alexander Bulekov) [Orabug: 36858811]
    {CVE-2021-3750}
    - memory: prevent dma-reentracy issues (Alexander Bulekov) [Orabug: 36858811] {CVE-2021-3750}
    - qga/win32: Use rundll for VSS installation (Konstantin Kostiuk) [Orabug: 36858681] {CVE-2023-0664}
    - qga/win32: Remove change action from MSI installer (Konstantin Kostiuk) [Orabug: 36858681]
    {CVE-2023-0664}
    - hw/display/ati_2d: Fix buffer overflow in ati_2d_blt (CVE-2021-3638) (Philippe Mathieu-Daude) [Orabug:
    36858674] {CVE-2021-3638}
    - CVE-2023-4135 is not applicable to Oracle QEMU 6.1.1 (Karl Heubaum) [Orabug: 35752193] {CVE-2023-4135}
    - virtio-crypto: verify src&dst buffer length for sym request (zhenwei pi) [Orabug: 35752194]
    {CVE-2023-3180}
    - ui/vnc-clipboard: fix infinite loop in inflate_buffer (CVE-2023-3255) (Mauro Matteo Cascella) [Orabug:
    35752186] {CVE-2023-3255}
    - io: remove io watch if TLS channel is closed during handshake (Daniel P. Berrange) [Orabug: 35752182]
    {CVE-2023-3354}
    - 9pfs: prevent opening special files (CVE-2023-2861) (Christian Schoenebeck) [Orabug: 35752178]
    {CVE-2023-2861}
    - hw/scsi/lsi53c895a: Fix reentrancy issues in the LSI controller (CVE-2023-0330) (Thomas Huth) [Orabug:
    35752171] {CVE-2023-0330}
    - vhost-vdpa: do not cleanup the vdpa/vhost-net structures if peer nic is present (Ani Sinha) [Orabug:
    35662843] {CVE-2023-3301}
    - CVE-2023-1544 is not applicable to Oracle QEMU 6.1.1 (Karl Heubaum) [Orabug: 35305727] {CVE-2023-1544}
    - hw/pvrdma: Protect against buggy or malicious guest driver (Yuval Shaia) [Orabug: 35064352]
    {CVE-2022-1050}
    - hw/display/qxl: Avoid buffer overrun in qxl_phys2virt (CVE-2022-4144) (Philippe Mathieu-Daude) [Orabug:
    35060182] {CVE-2022-4144}
    - ui/vnc-clipboard: fix integer underflow in vnc_client_cut_text_ext (Mauro Matteo Cascella) [Orabug:
    35060115] {CVE-2022-3165}
    - hw/acpi/erst.c: Fix memory handling issues (Christian A. Ehrhardt) [Orabug: 34779541] {CVE-2022-4172}
    - display/qxl-render: fix race condition in qxl_cursor (CVE-2021-4207) (Mauro Matteo Cascella) [Orabug:
    34591445] {CVE-2021-4207}
    - ui/cursor: fix integer overflow in cursor_alloc (CVE-2021-4206) (Mauro Matteo Cascella) [Orabug:
    34591281] {CVE-2021-4206}
    - scsi/lsi53c895a: really fix use-after-free in lsi_do_msgout (CVE-2022-0216) (Mauro Matteo Cascella)
    [Orabug: 34590706] {CVE-2022-0216}
    - scsi/lsi53c895a: fix use-after-free in lsi_do_msgout (CVE-2022-0216) (Mauro Matteo Cascella) [Orabug:
    34590706] {CVE-2022-0216}
    - tests/qtest: Add fuzz-lsi53c895a-test (Philippe Mathieu-Daude) [Orabug: 34590706] {CVE-2022-0216}
    - hw/scsi/lsi53c895a: Do not abort when DMA requested and no data queued (Philippe Mathieu-Daude) [Orabug:
    34590706] {CVE-2022-0216}
    - virtio-net: fix map leaking on error during receive (Jason Wang) [Orabug: 34538375] {CVE-2022-26353}
    - vhost-vsock: detach the virqueue element in case of error (Stefano Garzarella) [Orabug: 33941752]
    {CVE-2022-26354}
    - block/mirror: fix NULL pointer dereference in mirror_wait_on_conflicts() (Stefano Garzarella) [Orabug:
    33916572] {CVE-2021-4145}
    - hw/nvme: fix CVE-2021-3929 (Klaus Jensen) [Orabug: 33866395] {CVE-2021-3929}
    - virtiofsd: Drop membership of all supplementary groups (CVE-2022-0358) (Vivek Goyal) [Orabug: 33816690]
    {CVE-2022-0358}
    - acpi: validate hotplug selector on access (Michael S. Tsirkin) [Orabug: 33816625] {CVE-2021-4158}
    - Document CVE-2021-4158 and CVE-2021-3947 as fixed (Mark Kanda) [Orabug: 33719302] [Orabug: 33754145]
    {CVE-2021-4158} {CVE-2021-3947}
    - hw/block/fdc: Kludge missing floppy drive to fix CVE-2021-20196 (Philippe Mathieu-Daude) [Orabug:
    32439466] {CVE-2021-20196}
    - hw/block/fdc: Extract blk_create_empty_drive() (Philippe Mathieu-Daude) [Orabug: 32439466]
    {CVE-2021-20196}
    - net: vmxnet3: validate configuration values during activate (CVE-2021-20203) (Prasad J Pandit) [Orabug:
    32559476] {CVE-2021-20203}
    - lan9118: switch to use qemu_receive_packet() for loopback (Alexander Bulekov) [Orabug: 32560540]
    {CVE-2021-3416}
    - pcnet: switch to use qemu_receive_packet() for loopback (Alexander Bulekov) [Orabug: 32560540]
    {CVE-2021-3416}
    - rtl8139: switch to use qemu_receive_packet() for loopback (Alexander Bulekov) [Orabug: 32560540]
    {CVE-2021-3416}
    - tx_pkt: switch to use qemu_receive_packet_iov() for loopback (Jason Wang) [Orabug: 32560540]
    {CVE-2021-3416}
    - sungem: switch to use qemu_receive_packet() for loopback (Jason Wang) [Orabug: 32560540] {CVE-2021-3416}
    - dp8393x: switch to use qemu_receive_packet() for loopback packet (Jason Wang) [Orabug: 32560540]
    {CVE-2021-3416}
    - e1000: switch to use qemu_receive_packet() for loopback (Jason Wang) [Orabug: 32560540] {CVE-2021-3416}
    - net: introduce qemu_receive_packet() (Jason Wang) [Orabug: 32560540] {CVE-2021-3416}
    - Update slirp to address various CVEs (Mark Kanda) [Orabug: 32208456] [Orabug: 33014409] [Orabug:
    33014414] [Orabug: 33014417] [Orabug: 33014420] {CVE-2020-29129} {CVE-2020-29130} {CVE-2021-3592}
    {CVE-2021-3593} {CVE-2021-3594} {CVE-2021-3595}
    - uas: add stream number sanity checks (Gerd Hoffmann) [Orabug: 33280793] {CVE-2021-3713}
    - usbredir: fix free call (Gerd Hoffmann) [Orabug: 33198441] {CVE-2021-3682}
    - hw/scsi/scsi-disk: MODE_PAGE_ALLS not allowed in MODE SELECT commands (Mauro Matteo Cascella) [Orabug:
    33548490] {CVE-2021-3930}
    - e1000: fix tx re-entrancy problem (Jon Maloy) [Orabug: 32560552] {CVE-2021-20257}
    - pvrdma: Fix the ring init error flow (Marcel Apfelbaum) [Orabug: 33120142] {CVE-2021-3608}
    - pvrdma: Ensure correct input on ring init (Marcel Apfelbaum) [Orabug: 33120146] {CVE-2021-3607}
    - hw/rdma: Fix possible mremap overflow in the pvrdma device (Marcel Apfelbaum) [Orabug: 33120084]
    {CVE-2021-3582}
    - vhost-user-gpu: reorder free calls (Gerd Hoffmann) [Orabug: 32950701] {CVE-2021-3544}
    - vhost-user-gpu: abstract vg_cleanup_mapping_iov (Li Qiang) [Orabug: 32950716] {CVE-2021-3546}
    - vhost-user-gpu: fix OOB write in 'virgl_cmd_get_capset' (Li Qiang) [Orabug: 32950716] {CVE-2021-3546}
    - vhost-user-gpu: fix memory leak in 'virgl_resource_attach_backing' (Li Qiang) [Orabug: 32950701]
    {CVE-2021-3544}
    - vhost-user-gpu: fix memory leak in 'virgl_cmd_resource_unref' (Li Qiang) [Orabug: 32950701]
    {CVE-2021-3544}
    - vhost-user-gpu: fix memory leak while calling 'vg_resource_unref' (Li Qiang) [Orabug: 32950701]
    {CVE-2021-3544}
    - vhost-user-gpu: fix memory leak in vg_resource_attach_backing (Li Qiang) [Orabug: 32950701]
    {CVE-2021-3544}
    - vhost-user-gpu: fix resource leak in 'vg_resource_create_2d' (Li Qiang) [Orabug: 32950701]
    {CVE-2021-3544}
    - vhost-user-gpu: fix memory disclosure in virgl_cmd_get_capset_info (Li Qiang) [Orabug: 32950708]
    {CVE-2021-3545}
    - usb: limit combined packets to 1 MiB (Gerd Hoffmann) [Orabug: 32842778] {CVE-2021-3527}
    - usb/redir: avoid dynamic stack allocation (Gerd Hoffmann) [Orabug: 32842778] {CVE-2021-3527}
    - mptsas: Remove unused MPTSASState 'pending' field (Michael Tokarev) [Orabug: 32470463] {CVE-2021-3392}
    - e1000: fail early for evil descriptor (Jason Wang) [Orabug: 32560552] {CVE-2021-20257}
    - Document CVE-2020-27661 as fixed (Mark Kanda) [Orabug: 32960200] {CVE-2020-27661}
    - imx7-ccm: add digprog mmio write method (Prasad J Pandit) [Orabug: 31576552] {CVE-2020-15469}
    - tz-ppc: add dummy read/write methods (Prasad J Pandit) [Orabug: 31576552] {CVE-2020-15469}
    - spapr_pci: add spapr msi read method (Prasad J Pandit) [Orabug: 31576552] {CVE-2020-15469}
    - nvram: add nrf51_soc flash read method (Prasad J Pandit) [Orabug: 31576552] {CVE-2020-15469}
    - prep: add ppc-parity write method (Prasad J Pandit) [Orabug: 31576552] {CVE-2020-15469}
    - vfio: add quirk device write method (Prasad J Pandit) [Orabug: 31576552] {CVE-2020-15469}
    - pci-host: designware: add pcie-msi read method (Prasad J Pandit) [Orabug: 31576552] {CVE-2020-15469}
    - hw/pci-host: add pci-intack write method (Prasad J Pandit) [Orabug: 31576552] {CVE-2020-15469}
    - hw/intc/arm_gic: Fix interrupt ID in GICD_SGIR register (Philippe Mathieu-Daude) [Orabug: 32470471]
    {CVE-2021-20221}
    - memory: clamp cached translation in case it points to an MMIO region (Paolo Bonzini) [Orabug: 32252673]
    {CVE-2020-27821}
    - hw/sd/sdhci: Fix DMA Transfer Block Size field (Philippe Mathieu-Daude) [Orabug: 32613470]
    {CVE-2021-3409}
    - 9pfs: Fully restart unreclaim loop (CVE-2021-20181) (Greg Kurz) [Orabug: 32441198] {CVE-2021-20181}
    - ide: atapi: check logical block address and read size (CVE-2020-29443) (Prasad J Pandit) [Orabug:
    32393835] {CVE-2020-29443}
    - Document CVE-2019-20808 as fixed (Mark Kanda) [Orabug: 32339196] {CVE-2019-20808}
    - block/iscsi:fix heap-buffer-overflow in iscsi_aio_ioctl_cb (Chen Qun) [Orabug: 32339207]
    {CVE-2020-11947}
    - net: remove an assert call in eth_get_gso_type (Prasad J Pandit) [Orabug: 32102583] {CVE-2020-27617}
    - Document CVE-2020-25723 as fixed (Mark Kanda) [Orabug: 32222397] {CVE-2020-25723}
    - hw/net/e1000e: advance desc_offset in case of null descriptor (Prasad J Pandit) [Orabug: 32217517]
    {CVE-2020-28916}
    - libslirp: Update version to include CVE fixes (Mark Kanda) [Orabug: 32208456] [Orabug: 32208462]
    {CVE-2020-29129} {CVE-2020-29130}
    - Document CVE-2020-25624 as fixed (Mark Kanda) [Orabug: 32212527] {CVE-2020-25624}
    - ati: check x y display parameter values (Prasad J Pandit) [Orabug: 32108251] {CVE-2020-27616}
    - hw: usb: hcd-ohci: check for processed TD before retire (Prasad J Pandit) [Orabug: 31901690]
    {CVE-2020-25625}
    - hw: usb: hcd-ohci: check len and frame_number variables (Prasad J Pandit) [Orabug: 31901690]
    {CVE-2020-25625}
    - hw: ehci: check return value of 'usb_packet_map' (Li Qiang) [Orabug: 31901649] {CVE-2020-25084}
    - hw: xhci: check return value of 'usb_packet_map' (Li Qiang) [Orabug: 31901649] {CVE-2020-25084}
    - usb: fix setup_len init (CVE-2020-14364) (Gerd Hoffmann) [Orabug: 31848849] {CVE-2020-14364}
    - Document CVE-2020-12829 and CVE-2020-14415 as fixed (Mark Kanda) [Orabug: 31855502] [Orabug: 31855427]
    {CVE-2020-12829} {CVE-2020-14415}
    - hw/net/xgmac: Fix buffer overflow in xgmac_enet_send() (Mauro Matteo Cascella) [Orabug: 31667649]
    {CVE-2020-15863}
    - hw/net/net_tx_pkt: fix assertion failure in net_tx_pkt_add_raw_fragment() (Mauro Matteo Cascella)
    [Orabug: 31737809] {CVE-2020-16092}
    - hw/sd/sdcard: Do not switch to ReceivingData if address is invalid (Philippe Mathieu-Daude)  [Orabug:
    31414336]  {CVE-2020-13253}
    - hw/sd/sdcard: Do not allow invalid SD card sizes (Philippe Mathieu-Daude)  [Orabug: 31414336]
    {CVE-2020-13253}
    - libslirp: Update to v4.3.1 to fix CVE-2020-10756 (Karl Heubaum)  [Orabug: 31604999]  {CVE-2020-10756}
    - Document CVEs as fixed 2/2 (Karl Heubaum)  [Orabug: 30618035]  {CVE-2017-18043} {CVE-2018-10839}
    {CVE-2018-11806} {CVE-2018-12617} {CVE-2018-15746} {CVE-2018-16847} {CVE-2018-16867} {CVE-2018-17958}
    {CVE-2018-17962} {CVE-2018-17963} {CVE-2018-18849} {CVE-2018-19364} {CVE-2018-19489} {CVE-2018-3639}
    {CVE-2018-5683} {CVE-2018-7550} {CVE-2018-7858} {CVE-2019-12068} {CVE-2019-15034} {CVE-2019-15890}
    {CVE-2019-20382} {CVE-2020-10702} {CVE-2020-10761} {CVE-2020-11102} {CVE-2020-11869} {CVE-2020-13361}
    {CVE-2020-13765} {CVE-2020-13800} {CVE-2020-1711} {CVE-2020-1983} {CVE-2020-8608}
    - Document CVEs as fixed 1/2 (Karl Heubaum)  [Orabug: 30618035]  {CVE-2017-10806} {CVE-2017-11334}
    {CVE-2017-12809} {CVE-2017-13672} {CVE-2017-13673} {CVE-2017-13711} {CVE-2017-14167} {CVE-2017-15038}
    {CVE-2017-15119} {CVE-2017-15124} {CVE-2017-15268} {CVE-2017-15289} {CVE-2017-16845} {CVE-2017-17381}
    {CVE-2017-18030} {CVE-2017-2630} {CVE-2017-2633} {CVE-2017-5715} {CVE-2017-5753} {CVE-2017-5754}
    {CVE-2017-5931} {CVE-2017-6058} {CVE-2017-7471} {CVE-2017-7493} {CVE-2017-8112} {CVE-2017-8309}
    {CVE-2017-8379} {CVE-2017-8380} {CVE-2017-9503} {CVE-2017-9524} {CVE-2018-12126} {CVE-2018-12127}
    {CVE-2018-12130} {CVE-2018-16872} {CVE-2018-20123} {CVE-2018-20124} {CVE-2018-20125} {CVE-2018-20126}
    {CVE-2018-20191} {CVE-2018-20216} {CVE-2018-20815} {CVE-2019-11091} {CVE-2019-12155} {CVE-2019-14378}
    {CVE-2019-3812} {CVE-2019-5008} {CVE-2019-6501} {CVE-2019-6778} {CVE-2019-8934} {CVE-2019-9824}
    - exec: set map length to zero when returning NULL (Prasad J Pandit)  [Orabug: 31439733]  {CVE-2020-13659}
    - megasas: use unsigned type for reply_queue_head and check index (Prasad J Pandit)  [Orabug: 31414338]
    {CVE-2020-13362}
    - memory: Revert 'memory: accept mismatching sizes in memory_region_access_valid' (Michael S. Tsirkin)
    [Orabug: 31439736] [Orabug: 31452202]  {CVE-2020-13754} {CVE-2020-13791}
    - Document CVE-2020-13765 as fixed (Karl Heubaum)  [Orabug: 31463250]  {CVE-2020-13765}
    - ati-vga: check mm_index before recursive call (CVE-2020-13800) (Prasad J Pandit)  [Orabug: 31452206]
    {CVE-2020-13800}
    - es1370: check total frame count against current frame (Prasad J Pandit)  [Orabug: 31463235]
    {CVE-2020-13361}
    - ati-vga: Fix checks in ati_2d_blt() to avoid crash (BALATON Zoltan)  [Orabug: 31238432]
    {CVE-2020-11869}
    - libslirp: Update to stable-4.2 to fix CVE-2020-1983 (Karl Heubaum)  [Orabug: 31241227]  {CVE-2020-1983}
    - Document CVEs as fixed (Karl Heubaum)   {CVE-2019-12068} {CVE-2019-15034}
    - libslirp: Update to version 4.2.0 to fix CVEs (Karl Heubaum)  [Orabug: 30274592] [Orabug: 30869830]
    {CVE-2019-15890} {CVE-2020-8608}
    - vnc: fix memory leak when vnc disconnect (Li Qiang)  [Orabug: 30996427]  {CVE-2019-20382}
    - iscsi: Cap block count from GET LBA STATUS (CVE-2020-1711) (Felipe Franciosi)  [Orabug: 31124035]
    {CVE-2020-1711}
    - Update to 0.4.2, to address potential symlink vulnerabilities (CVE-2020-28407).
      Resolves: rhbz#1906043

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12605.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3750");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::kvm_appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-inspect-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-man-pages-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-rescue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-rsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libguestfs-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnbd-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtpms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtpms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lua-guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-basic-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-basic-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-curl-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-example-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-gzip-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-gzip-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-linuxdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-nbd-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-ssh-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-tar-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-tar-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-tmpdisk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-vddk-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nbdkit-xz-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-virtiofsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:seavgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sgabios-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:supermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:supermin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:swtpm-tools-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-dib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v-man-pages-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virt-v2v-man-pages-uk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/virt');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:kvm_utils2');
if ('kvm_utils2' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module virt:' + module_ver);

var appstreams = {
    'virt:kvm_utils2': [
      {'reference':'hivex-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-bash-completion-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-inspect-icons-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-javadoc-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-ja-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-uk-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-winsupport-8.6-1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libiscsi-1.18.0-8.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-bash-completion-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-0.9.1-0.20211126git1ff6fe1f43.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-devel-0.9.1-0.20211126git1ff6fe1f43.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-wireshark-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nbdfuse-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-filter-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-nbd-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-filter-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Virt-6.0.0-1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libnbd-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qemu-guest-agent-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-virtiofsd-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'ruby-hivex-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'supermin-5.2.1-1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'hivex-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-appliance-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-bash-completion-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-devel-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gfs2-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-gobject-devel-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-inspect-icons-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-java-devel-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-javadoc-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-ja-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-man-pages-uk-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rescue-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-rsync-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-tools-c-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libguestfs-winsupport-8.6-1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-xfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'libiscsi-1.18.0-8.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-bash-completion-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-0.9.1-0.20211126git1ff6fe1f43.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtpms-devel-0.9.1-0.20211126git1ff6fe1f43.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-network-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-config-nwfilter-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-interface-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-network-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nodedev-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-nwfilter-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-qemu-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-secret-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-core-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-disk-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-gluster-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-iscsi-direct-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-logical-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-mpath-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-rbd-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-driver-storage-scsi-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-daemon-kvm-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-docs-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-libs-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-lock-sanlock-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-nss-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-wireshark-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'lua-guestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'nbdfuse-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-bash-completion-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-filters-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-basic-plugins-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-curl-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-devel-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-example-plugins-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-filter-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-gzip-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-linuxdisk-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-nbd-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-python-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-server-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-ssh-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-filter-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tar-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-tmpdisk-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-vddk-plugin-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdkit-xz-filter-1.24.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Guestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sys-Virt-6.0.0-1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libguestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-libnbd-1.6.0-5.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-7.10.0-4.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qemu-guest-agent-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-img-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-curl-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-gluster-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-iscsi-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-rbd-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-block-ssh-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-common-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-kvm-core-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'qemu-virtiofsd-6.1.1-9.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'15'},
      {'reference':'ruby-hivex-1.3.18-23.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libguestfs-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'seabios-1.15.0-2.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seabios-bin-1.15.0-2.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'seavgabios-bin-1.15.0-2.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-0.20170427git-3.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'sgabios-bin-0.20170427git-3.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'supermin-5.2.1-1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'supermin-devel-5.2.1-1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-devel-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-libs-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'swtpm-tools-pkcs11-0.7.0-3.20211109gitb79fd91.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'virt-dib-1.44.0-5.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-1.42.0-19.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-bash-completion-1.42.0-19.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-ja-1.42.0-19.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'virt-v2v-man-pages-uk-1.42.0-19.0.1.module+el8.10.0+90374+95a91213', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt:kvm_utils2');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hivex / hivex-devel / libguestfs / etc');
}
