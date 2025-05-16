#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-7000.
##

include('compat.inc');

if (description)
{
  script_id(207773);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2021-46984",
    "CVE-2021-47097",
    "CVE-2021-47101",
    "CVE-2021-47287",
    "CVE-2021-47289",
    "CVE-2021-47321",
    "CVE-2021-47338",
    "CVE-2021-47352",
    "CVE-2021-47383",
    "CVE-2021-47384",
    "CVE-2021-47385",
    "CVE-2021-47386",
    "CVE-2021-47393",
    "CVE-2021-47412",
    "CVE-2021-47432",
    "CVE-2021-47441",
    "CVE-2021-47455",
    "CVE-2021-47466",
    "CVE-2021-47497",
    "CVE-2021-47527",
    "CVE-2021-47560",
    "CVE-2021-47582",
    "CVE-2021-47609",
    "CVE-2022-48619",
    "CVE-2022-48754",
    "CVE-2022-48760",
    "CVE-2022-48804",
    "CVE-2022-48836",
    "CVE-2022-48866",
    "CVE-2023-6040",
    "CVE-2023-52470",
    "CVE-2023-52476",
    "CVE-2023-52478",
    "CVE-2023-52522",
    "CVE-2023-52605",
    "CVE-2023-52683",
    "CVE-2023-52798",
    "CVE-2023-52800",
    "CVE-2023-52809",
    "CVE-2023-52817",
    "CVE-2023-52840",
    "CVE-2024-23848",
    "CVE-2024-26595",
    "CVE-2024-26600",
    "CVE-2024-26638",
    "CVE-2024-26645",
    "CVE-2024-26649",
    "CVE-2024-26665",
    "CVE-2024-26717",
    "CVE-2024-26720",
    "CVE-2024-26769",
    "CVE-2024-26846",
    "CVE-2024-26855",
    "CVE-2024-26880",
    "CVE-2024-26894",
    "CVE-2024-26923",
    "CVE-2024-26939",
    "CVE-2024-27013",
    "CVE-2024-27042",
    "CVE-2024-35809",
    "CVE-2024-35877",
    "CVE-2024-35884",
    "CVE-2024-35944",
    "CVE-2024-35989",
    "CVE-2024-36883",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36919",
    "CVE-2024-36920",
    "CVE-2024-36922",
    "CVE-2024-36939",
    "CVE-2024-36953",
    "CVE-2024-37356",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38570",
    "CVE-2024-38579",
    "CVE-2024-38581",
    "CVE-2024-38619",
    "CVE-2024-39471",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-39506",
    "CVE-2024-40901",
    "CVE-2024-40904",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40929",
    "CVE-2024-40931",
    "CVE-2024-40941",
    "CVE-2024-40954",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40972",
    "CVE-2024-40977",
    "CVE-2024-40978",
    "CVE-2024-40988",
    "CVE-2024-40989",
    "CVE-2024-40995",
    "CVE-2024-40997",
    "CVE-2024-40998",
    "CVE-2024-41005",
    "CVE-2024-41007",
    "CVE-2024-41008",
    "CVE-2024-41012",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-41023",
    "CVE-2024-41035",
    "CVE-2024-41038",
    "CVE-2024-41039",
    "CVE-2024-41040",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41055",
    "CVE-2024-41056",
    "CVE-2024-41060",
    "CVE-2024-41064",
    "CVE-2024-41065",
    "CVE-2024-41071",
    "CVE-2024-41076",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-41097",
    "CVE-2024-42084",
    "CVE-2024-42090",
    "CVE-2024-42094",
    "CVE-2024-42096",
    "CVE-2024-42114",
    "CVE-2024-42124",
    "CVE-2024-42131",
    "CVE-2024-42152",
    "CVE-2024-42154",
    "CVE-2024-42225",
    "CVE-2024-42226",
    "CVE-2024-42228",
    "CVE-2024-42237",
    "CVE-2024-42238",
    "CVE-2024-42240",
    "CVE-2024-42246",
    "CVE-2024-42265",
    "CVE-2024-42322",
    "CVE-2024-43830",
    "CVE-2024-43871"
  );
  script_xref(name:"IAVA", value:"2024-A-0487");

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2024-7000)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-7000 advisory.

    - wifi: mac80211: Avoid address calculations via out of bounds array indexing (Michal Schmidt)
    [RHEL-51278] {CVE-2024-41071}
    - protect the fetch of ->fd[fd] in do_dup2() from mispredictions (CKI Backport Bot) [RHEL-55123]
    {CVE-2024-42265}
    - net: openvswitch: fix overwriting ct original tuple for ICMPv6 (cki-backport-bot) [RHEL-44207]
    {CVE-2024-38558}
    - mlxsw: thermal: Fix out-of-bounds memory accesses (CKI Backport Bot) [RHEL-38375] {CVE-2021-47441}
    - USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages (CKI Backport Bot) [RHEL-47552]
    {CVE-2024-40904}
    - ipvs: properly dereference pe in ip_vs_add_service (Phil Sutter) [RHEL-54903] {CVE-2024-42322}
    - net, sunrpc: Remap EPERM in case of connection failure in xs_tcp_setup_socket (CKI Backport Bot)
    [RHEL-53702] {CVE-2024-42246}
    - drm/amdgpu: change vm->task_info handling (Michel Danzer) [RHEL-49379] {CVE-2024-41008}
    - drm/amdgpu: Fix signedness bug in sdma_v4_0_process_trap_irq() (Michel Danzer) [RHEL-45036]
    {CVE-2024-39471}
    - drm/amdgpu: add error handle to avoid out-of-bounds (Michel Danzer) [RHEL-45036] {CVE-2024-39471}
    - drm/amdgpu: Using uninitialized value *size when calling amdgpu_vce_cs_reloc (Michel Danzer)
    [RHEL-52845] {CVE-2024-42228}
    - KVM: arm64: Disassociate vcpus from redistributor region on teardown (Shaoqin Huang) [RHEL-48417]
    {CVE-2024-40989}
    - devres: Fix memory leakage caused by driver API devm_free_percpu() (CKI Backport Bot) [RHEL-55597]
    {CVE-2024-43871}
    - phy: ti: phy-omap-usb2: Fix NULL pointer dereference for SRP (Izabela Bakollari) [RHEL-26680]
    {CVE-2024-26600}
    - nvmet-fc: avoid deadlock on delete association path (Maurizio Lombardi) [RHEL-31618] {CVE-2024-26769}
    - nvmet-fc: release reference on target port (Maurizio Lombardi) [RHEL-31618] {CVE-2024-26769}
    - ACPI: LPIT: Avoid u32 multiplication overflow (Mark Langsdorf) [RHEL-37062] {CVE-2023-52683}
    - sched/deadline: Fix task_struct reference leak (Phil Auld) [RHEL-50904] {CVE-2024-41023}
    - mlxsw: spectrum_acl_tcam: Fix NULL pointer dereference in error path (CKI Backport Bot) [RHEL-26570]
    {CVE-2024-26595}
    - mlxsw: spectrum_acl_tcam: Move devlink param to TCAM code (Ivan Vecera) [RHEL-26570] {CVE-2024-26595}
    - ACPI: extlog: fix NULL pointer dereference check (Mark Langsdorf) [RHEL-29110] {CVE-2023-52605}
    - ACPI: processor_idle: Fix memory leak in acpi_processor_power_exit() (Mark Langsdorf) [RHEL-33198]
    {CVE-2024-26894}
    - mm: prevent derefencing NULL ptr in pfn_section_valid() (Audra Mitchell) [RHEL-51132] {CVE-2024-41055}
    - mm, kmsan: fix infinite recursion due to RCU critical section (Audra Mitchell) [RHEL-51132]
    {CVE-2024-41055}
    - ext4: do not create EA inode under buffer lock (Carlos Maiolino) [RHEL-48271] {CVE-2024-40972}
    - ext4: fold quota accounting into ext4_xattr_inode_lookup_create() (Carlos Maiolino) [RHEL-48271]
    {CVE-2024-40972}
    - ext4: check the return value of ext4_xattr_inode_dec_ref() (Carlos Maiolino) [RHEL-48271]
    {CVE-2024-40972}
    - ext4: fix uninitialized ratelimit_state->lock access in __ext4_fill_super() (Carlos Maiolino)
    [RHEL-48507] {CVE-2024-40998}
    - ext4: remove duplicate definition of ext4_xattr_ibody_inline_set() (Carlos Maiolino) [RHEL-48271]
    {CVE-2024-40972}
    - drm/i915/vma: Fix UAF on destroy against retire race (Mika Penttila) [RHEL-35222] {CVE-2024-26939}
    - net: ice: Fix potential NULL pointer dereference in ice_bridge_setlink() (CKI Backport Bot) [RHEL-42721]
    {CVE-2024-26855}
    - net: usb: asix: do not force pause frames support (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: asix: fix 'can't send until first packet is send' issue (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: asix: fix modprobe 'sysfs: cannot create duplicate filename' (Ken Cox) [RHEL-28108]
    {CVE-2021-47101}
    - net: asix: add proper error handling of usb read errors (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - asix: fix wrong return value in asix_check_host_enable() (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - asix: fix uninit-value in asix_mdio_read() (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: ax88772: fix boolconv.cocci warnings (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: do not call phy_disconnect() for ax88178 (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: ax88772: move embedded PHY detection as early as possible (Ken Cox) [RHEL-28108]
    {CVE-2021-47101}
    - net: asix: fix uninit value bugs (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: ax88772: add missing stop (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: ax88772: suspend PHY on driver probe (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: ax88772: manage PHY PM from MAC (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: ax88772: Fix less than zero comparison of a u16 (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: Fix less than zero comparison of a u16 (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: add error handling for asix_mdio_* functions (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: ax88772: add phylib support (Ken Cox) [RHEL-28108] {CVE-2021-47101}
    - net: usb: asix: refactor asix_read_phy_addr() and handle errors on return (Ken Cox) [RHEL-28108]
    {CVE-2021-47101}
    - wifi: iwlwifi: read txq->read_ptr under lock (Jose Ignacio Tornos Martinez) [RHEL-39797]
    {CVE-2024-36922}
    - scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload (John Meneghini) [RHEL-39908]
    {CVE-2024-36919}
    - nbd: always initialize struct msghdr completely (Ming Lei) [RHEL-29498] {CVE-2024-26638}
    - block: don't call rq_qos_ops->done_bio if the bio isn't tracked (Ming Lei) [RHEL-42151] {CVE-2021-47412}
    - nvmet: fix a possible leak when destroy a ctrl during qp establishment (Maurizio Lombardi) [RHEL-52013]
    {CVE-2024-42152}
    - ipv6: prevent NULL dereference in ip6_output() (Sabrina Dubroca) [RHEL-39912] {CVE-2024-36901}
    - ppp: reject claimed-as-LCP but actually malformed packets (Guillaume Nault) [RHEL-51052]
    {CVE-2024-41044}
    - leds: trigger: Unregister sysfs attributes before calling deactivate() (CKI Backport Bot) [RHEL-54834]
    {CVE-2024-43830}
    - crypto: bcm - Fix pointer arithmetic (cki-backport-bot) [RHEL-44108] {CVE-2024-38579}
    - scsi: qedf: Ensure the copied buf is NUL terminated (John Meneghini) [RHEL-44195] {CVE-2024-38559}
    - x86/bhi: Avoid warning in #DB handler due to BHI mitigation (Waiman Long) [RHEL-53657] {CVE-2024-42240}
    - scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (CKI Backport Bot) [RHEL-47529]
    {CVE-2024-40901}
    - ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action() (CKI Backport Bot) [RHEL-39843]
    {CVE-2024-36902}
    - KVM: arm64: vgic-v2: Check for non-NULL vCPU in vgic_v2_parse_attr() (Shaoqin Huang) [RHEL-40837]
    {CVE-2024-36953}
    - KVM: arm64: vgic-v2: Use cpuid from userspace as vcpu_id (Shaoqin Huang) [RHEL-40837] {CVE-2024-36953}
    - media: cec: cec-api: add locking in cec_release() (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: core: avoid confusing 'transmit timed out' message (Kate Hsuan) [RHEL-22559]
    {CVE-2024-23848}
    - media: cec: core: avoid recursive cec_claim_log_addrs (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: cec-adap: always cancel work in cec_transmit_msg_fh (Kate Hsuan) [RHEL-22559]
    {CVE-2024-23848}
    - media: cec: core: remove length check of Timer Status (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: core: count low-drive, error and arb-lost conditions (Kate Hsuan) [RHEL-22559]
    {CVE-2024-23848}
    - media: cec: core: add note about *_from_edid() function usage in drm (Kate Hsuan) [RHEL-22559]
    {CVE-2024-23848}
    - media: cec: core: add adap_unconfigured() callback (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: core: add adap_nb_transmit_canceled() callback (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: core: don't set last_initiator if tx in progress (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: core: disable adapter in cec_devnode_unregister (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: core: not all messages were passed on when monitoring (Kate Hsuan) [RHEL-22559]
    {CVE-2024-23848}
    - media: cec: add support for Absolute Volume Control (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-adap.c: log when claiming LA fails unexpectedly (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-adap.c: drop activate_cnt, use state info instead (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-adap.c: reconfigure if the PA changes during configuration (Kate Hsuan) [RHEL-22559]
    {CVE-2024-23848}
    - media: cec-adap.c: fix is_configuring state (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-adap.c: stop trying LAs on CEC_TX_STATUS_TIMEOUT (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-adap.c: don't unconfigure if already unconfigured (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: add optional adap_configured callback (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: add xfer_timeout_ms field (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: use call_op and check for !unregistered (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-pin: fix interrupt en/disable handling (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-pin: drop unused 'enabled' field from struct cec_pin (Kate Hsuan) [RHEL-22559]
    {CVE-2024-23848}
    - media: cec-pin: fix off-by-one SFT check (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-pin: rename timer overrun variables (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: correctly pass on reply results (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: abort if the current transmit was canceled (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: call enable_adap on s_log_addrs (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: media/cec.h: document cec_adapter fields (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: fix a deadlock situation (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: safely unhook lists in cec_data (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: copy sequence field for the reply (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: fix trivial style warnings (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-adap.c: add 'unregistered' checks (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec-adap.c: don't use flush_scheduled_work() (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: Use fallthrough pseudo-keyword (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: remove unused waitq and phys_addrs fields (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - media: cec: silence shift wrapping warning in __cec_s_log_addrs() (Kate Hsuan) [RHEL-22559]
    {CVE-2024-23848}
    - media: cec: move the core to a separate directory (Kate Hsuan) [RHEL-22559] {CVE-2024-23848}
    - net/iucv: Avoid explicit cpumask var allocation on stack (CKI Backport Bot) [RHEL-51631]
    {CVE-2024-42094}
    - firmware: cs_dsp: Return error if block header overflows file (CKI Backport Bot) [RHEL-53646]
    {CVE-2024-42238}
    - firmware: cs_dsp: Validate payload length before processing block (CKI Backport Bot) [RHEL-53638]
    {CVE-2024-42237}
    - mm, slub: fix potential memoryleak in kmem_cache_open() (Waiman Long) [RHEL-38404] {CVE-2021-47466}
    - slub: don't panic for memcg kmem cache creation failure (Waiman Long) [RHEL-38404] {CVE-2021-47466}
    - wifi: ath11k: fix htt pktlog locking (Jose Ignacio Tornos Martinez) [RHEL-38317] {CVE-2023-52800}
    - wifi: ath11k: fix dfs radar event locking (Jose Ignacio Tornos Martinez) [RHEL-38165] {CVE-2023-52798}
    - lib/generic-radix-tree.c: Don't overflow in peek() (Waiman Long) [RHEL-37737] {CVE-2021-47432}
    - include/linux/generic-radix-tree.h: replace kernel.h with the necessary inclusions (Waiman Long)
    [RHEL-37737] {CVE-2021-47432}
    - scsi: libfc: Fix potential NULL pointer dereference in fc_lport_ptp_setup() (John Meneghini)
    [RHEL-38197] {CVE-2023-52809}
    - gfs2: Fix potential glock use-after-free on unmount (Andreas Gruenbacher) [RHEL-44149] {CVE-2024-38570}
    - gfs2: simplify gdlm_put_lock with out_free label (Andreas Gruenbacher) [RHEL-44149] {CVE-2024-38570}
    - gfs2: Remove ill-placed consistency check (Andreas Gruenbacher) [RHEL-44149] {CVE-2024-38570}
    - nvme-fc: do not wait in vain when unloading module (Ewan D. Milne) [RHEL-33083] {CVE-2024-26846}
    - HID: hid-thrustmaster: fix OOB read in thrustmaster_interrupts (CKI Backport Bot) [RHEL-49698]
    {CVE-2022-48866}
    - Revert 'mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again' (Audra Mitchell)
    [RHEL-42625] {CVE-2024-26720}
    - mm: avoid overflows in dirty throttling logic (Audra Mitchell) [RHEL-51840] {CVE-2024-42131}
    - mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again (Audra Mitchell) [RHEL-42625]
    {CVE-2024-26720}
    - ACPI: fix NULL pointer dereference (Mark Langsdorf) [RHEL-37897] {CVE-2021-47289}
    - scsi: mpi3mr: Avoid memcpy field-spanning write WARNING (Ewan D. Milne) [RHEL-39805] {CVE-2024-36920}
    - tun: limit printing rate when illegal packet received by tun dev (Jon Maloy) [RHEL-35046]
    {CVE-2024-27013}
    - drm/amdgpu/debugfs: fix error code when smc register accessors are NULL (Michel Danzer) [RHEL-38210]
    {CVE-2023-52817}
    - drm/amdgpu: Fix a null pointer access when the smc_rreg pointer is NULL (Michel Danzer) [RHEL-38210]
    {CVE-2023-52817}
    - drm/amdgpu/mes: fix use-after-free issue (Michel Danzer) [RHEL-44043] {CVE-2024-38581}
    - drm/amdgpu: Fix the null pointer when load rlc firmware (Michel Danzer) [RHEL-30603] {CVE-2024-26649}
    - drm/amdgpu: Fix potential out-of-bounds access in 'amdgpu_discovery_reg_base_init()' (Michel Danzer)
    [RHEL-35160] {CVE-2024-27042}
    - net/sched: Fix UAF when resolving a clash (Xin Long) [RHEL-51014] {CVE-2024-41040}
    - tcp_metrics: validate source addr length (Guillaume Nault) [RHEL-52025] {CVE-2024-42154}
    - scsi: qedf: Make qedf_execute_tmf() non-preemptible (John Meneghini) [RHEL-51799] {CVE-2024-42124}
    - Input: elantech - fix stack out of bound access in elantech_change_report_id() (CKI Backport Bot)
    [RHEL-41938] {CVE-2021-47097}
    - HID: logitech-hidpp: Fix kernel crash on receiver USB disconnect (CKI Backport Bot) [RHEL-28982]
    {CVE-2023-52478}
    - drm/radeon: fix UBSAN warning in kv_dpm.c (CKI Backport Bot) [RHEL-48399] {CVE-2024-40988}
    - usb: core: Don't hold the device lock while sleeping in do_proc_control() (Desnes Nunes) [RHEL-43646]
    {CVE-2021-47582}
    - USB: core: Make do_proc_control() and do_proc_bulk() killable (Desnes Nunes) [RHEL-43646]
    {CVE-2021-47582}
    - scsi: qedi: Fix crash while reading debugfs attribute (CKI Backport Bot) [RHEL-48327] {CVE-2024-40978}
    - wifi: mt76: mt7921s: fix potential hung tasks during chip recovery (CKI Backport Bot) [RHEL-48309]
    {CVE-2024-40977}
    - wifi: iwlwifi: mvm: don't read past the mfuart notifcation (CKI Backport Bot) [RHEL-48016]
    {CVE-2024-40941}
    - wifi: iwlwifi: mvm: check n_ssids before accessing the ssids (CKI Backport Bot) [RHEL-47908]
    {CVE-2024-40929}
    - Input: aiptek - properly check endpoint type (Benjamin Tissoires) [RHEL-48963] {CVE-2022-48836}
    - Input: aiptek - use descriptors of current altsetting (Benjamin Tissoires) [RHEL-48963] {CVE-2022-48836}
    - Input: aiptek - fix endpoint sanity check (Benjamin Tissoires) [RHEL-48963] {CVE-2022-48836}
    - usb: xhci: prevent potential failure in handle_tx_event() for Transfer events without TRB (CKI Backport
    Bot) [RHEL-52373] {CVE-2024-42226}
    - wifi: mt76: replace skb_put with skb_put_zero (CKI Backport Bot) [RHEL-52366] {CVE-2024-42225}
    - wifi: mac80211: Fix deadlock in ieee80211_sta_ps_deliver_wakeup() (CKI Backport Bot) [RHEL-47776]
    {CVE-2024-40912}
    - wifi: cfg80211: Lock wiphy in cfg80211_get_station (CKI Backport Bot) [RHEL-47758] {CVE-2024-40911}
    - VMCI: Use struct_size() in kmalloc() (Steve Best) [RHEL-37325] {CVE-2024-35944}
    - VMCI: Fix possible memcpy() run-time warning in vmci_datagram_invoke_guest_handler() (Steve Best)
    [RHEL-37325] {CVE-2024-35944}
    - VMCI: Fix memcpy() run-time warning in dg_dispatch_as_host() (Steve Best) [RHEL-37325] {CVE-2024-35944}
    - wifi: cfg80211: restrict NL80211_ATTR_TXQ_QUANTUM values (Jose Ignacio Tornos Martinez) [RHEL-51761]
    {CVE-2024-42114}
    - usb: atm: cxacru: fix endpoint checking in cxacru_bind() (CKI Backport Bot) [RHEL-51442]
    {CVE-2024-41097}
    - nfs: handle error of rpc_proc_register() in init_nfs_fs() (Scott Mayhew) [RHEL-39904] {CVE-2024-36939}
    - drm/radeon: check bo_va->bo is non-NULL before using it (CKI Backport Bot) [RHEL-51184] {CVE-2024-41060}
    - udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port(). (CKI Backport Bot) [RHEL-51027] {CVE-2024-41041}
    - USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor (CKI Backport Bot)
    [RHEL-50961] {CVE-2024-41035}
    - tcp: Fix shift-out-of-bounds in dctcp_update_alpha(). (CKI Backport Bot) [RHEL-44408] {CVE-2024-37356}
    - tcp: avoid too many retransmit packets (Florian Westphal) [RHEL-48627] {CVE-2024-41007}
    - netfilter: nf_tables: Reject tables of unsupported family (Florian Westphal) [RHEL-21418]
    {CVE-2023-6040}
    - kyber: fix out of bounds access when preempted (Ming Lei) [RHEL-27258] {CVE-2021-46984}
    - fbmem: Do not delete the mode that is still in use (CKI Backport Bot) [RHEL-37796] {CVE-2021-47338}
    - netpoll: Fix race condition in netpoll_owner_active (CKI Backport Bot) [RHEL-49361] {CVE-2024-41005}
    - firmware: arm_scpi: Fix string overflow in SCPI genpd driver (Mark Salter) [RHEL-43702] {CVE-2021-47609}
    - ipv6: prevent possible NULL dereference in rt6_probe() (Guillaume Nault) [RHEL-48149] {CVE-2024-40960}
    - HID: i2c-hid-of: fix NULL-deref on failed power up (CKI Backport Bot) [RHEL-31598] {CVE-2024-26717}
    - cpufreq: amd-pstate: fix memory leak on CPU EPP exit (CKI Backport Bot) [RHEL-48489] {CVE-2024-40997}
    - x86/mm/pat: fix VM_PAT handling in COW mappings (Chris von Recklinghausen) [RHEL-37258] {CVE-2024-35877}
    - PCI/PM: Drain runtime-idle callbacks before driver removal (Myron Stowe) [RHEL-42937] {CVE-2024-35809}
    - PCI: Drop pci_device_remove() test of pci_dev->driver (Myron Stowe) [RHEL-42937] {CVE-2024-35809}
    - drm/radeon: check the alloc_workqueue return value in radeon_crtc_init() (Mika Penttila) [RHEL-26909]
    {CVE-2023-52470}
    - USB: core: Fix hang in usb_kill_urb by adding memory barriers (Desnes Nunes) [RHEL-43979]
    {CVE-2022-48760}
    - selftests: forwarding: devlink_lib: Wait for udev events after reloading (Mark Langsdorf) [RHEL-47642]
    {CVE-2024-39501}
    - drivers: core: synchronize really_probe() and dev_uevent() (Mark Langsdorf) [RHEL-47642]
    {CVE-2024-39501}
    - udp: do not accept non-tunnel GSO skbs landing in a tunnel (Xin Long) [RHEL-42997] {CVE-2024-35884}
    - filelock: Remove locks reliably when fcntl/close race is detected (Bill O'Donnell) [RHEL-50170]
    {CVE-2024-41012}
    - Input: add bounds checking to input_set_capability() (Benjamin Tissoires) [RHEL-21413] {CVE-2022-48619}
    - xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr() (CKI Backport Bot) [RHEL-48130]
    {CVE-2024-40959}
    - net: do not leave a dangling sk pointer, when socket creation fails (CKI Backport Bot) [RHEL-48060]
    {CVE-2024-40954}
    - perf/x86/lbr: Filter vsyscall addresses (Michael Petlan) [RHEL-28991] {CVE-2023-52476}
    - vmci: prevent speculation leaks by sanitizing event in event_deliver() (CKI Backport Bot) [RHEL-47678]
    {CVE-2024-39499}
    - serial: core: fix transmit-buffer reset and memleak (Steve Best) [RHEL-38731] {CVE-2021-47527}
    - powerpc/pseries: Whitelist dtl slub object for copying to userspace (Mamatha Inamdar) [RHEL-51236]
    {CVE-2024-41065}
    - powerpc/eeh: avoid possible crash when edev->pdev changes (Mamatha Inamdar) [RHEL-51220]
    {CVE-2024-41064}
    - x86: stop playing stack games in profile_pc() (Steve Best) [RHEL-51643] {CVE-2024-42096}
    - mptcp: ensure snd_una is properly initialized on connect (Florian Westphal) [RHEL-47933 RHEL-47934]
    {CVE-2024-40931}
    - liquidio: Adjust a NULL pointer handling path in lio_vf_rep_copy_packet (CKI Backport Bot) [RHEL-47492]
    {CVE-2024-39506}
    - tun: add missing verification for short frame (Patrick Talbert) [RHEL-50194] {CVE-2024-41091}
    - tap: add missing verification for short frame (Patrick Talbert) [RHEL-50279] {CVE-2024-41090}
    - usb-storage: alauda: Check whether the media is initialized (Desnes Nunes) [RHEL-43708] {CVE-2024-38619}
    - usb-storage: alauda: Fix uninit-value in alauda_check_media() (Desnes Nunes) [RHEL-43708]
    {CVE-2024-38619}
    - hwmon: (w83793) Fix NULL pointer dereference by removing unnecessary structure field (Steve Best)
    [RHEL-37723] {CVE-2021-47384}
    - watchdog: Fix possible use-after-free by calling del_timer_sync() (Steve Best) [RHEL-38795]
    {CVE-2021-47321}
    - hwmon: (w83792d) Fix NULL pointer dereference by removing unnecessary structure field (Steve Best)
    [RHEL-37719] {CVE-2021-47385}
    - mlxsw: spectrum: Protect driver from buggy firmware (CKI Backport Bot) [RHEL-42245] {CVE-2021-47560}
    - mlxsw: Verify the accessed index doesn't exceed the array length (CKI Backport Bot) [RHEL-42245]
    {CVE-2021-47560}
    - dm: call the resume method on internal suspend (Benjamin Marzinski) [RHEL-41835] {CVE-2024-26880}
    - tty: Fix out-of-bound vmalloc access in imageblit (Steve Best) [RHEL-37727] {CVE-2021-47383}
    - hwmon: (w83791d) Fix NULL pointer dereference by removing unnecessary structure field (Steve Best)
    [RHEL-37715] {CVE-2021-47386}
    - hwmon: (mlxreg-fan) Return non-zero value when fan current state is enforced from sysfs (Steve Best)
    [RHEL-37710] {CVE-2021-47393}
    - nvmem: Fix shift-out-of-bound (UBSAN) with byte size cells (Steve Best) [RHEL-38436] {CVE-2021-47497}
    - driver core: auxiliary bus: Fix memory leak when driver_register() fail (Steve Best) [RHEL-37901]
    {CVE-2021-47287}
    - phylib: fix potential use-after-free (cki-backport-bot) [RHEL-43764] {CVE-2022-48754}
    - ptp: Fix possible memory leak in ptp_clock_register() (Hangbin Liu) [RHEL-38424] {CVE-2021-47455}
    - NFSv4: Fix memory leak in nfs4_set_security_label (CKI Backport Bot) [RHEL-51315] {CVE-2024-41076}
    - pinctrl: fix deadlock in create_pinctrl() when handling -EPROBE_DEFER (CKI Backport Bot) [RHEL-51618]
    {CVE-2024-42090}
    - ftruncate: pass a signed offset (CKI Backport Bot) [RHEL-51598] {CVE-2024-42084}
    - af_unix: Fix garbage collector racing against connect() (Felix Maurer) [RHEL-34225] {CVE-2024-26923}
    - virtio-net: Add validation for used length (Laurent Vivier) [RHEL-42080] {CVE-2021-47352}
    - net: fix possible store tearing in neigh_periodic_work() (Antoine Tenart) [RHEL-42359] {CVE-2023-52522}
    - tunnels: fix out of bounds access when building IPv6 PMTU error (Antoine Tenart) [RHEL-41823]
    {CVE-2024-26665}
    - vt_ioctl: fix array_index_nospec in vt_setactivate (John W. Linville) [RHEL-49141] {CVE-2022-48804}
    - Input: synaptics-rmi4 - fix use after free in rmi_unregister_function() (CKI Backport Bot) [RHEL-38302]
    {CVE-2023-52840}
    - netns: Make get_net_ns() handle zero refcount net (Antoine Tenart) [RHEL-48105] {CVE-2024-40958}
    - tracing: Ensure visibility when inserting an element into tracing_map (Michael Petlan) [RHEL-30457]
    {CVE-2024-26645}
    - firmware: cs_dsp: Use strnlen() on name fields in V1 wmfw files (CKI Backport Bot) [RHEL-51144]
    {CVE-2024-41056}
    - firmware: cs_dsp: Fix overflow checking of wmfw header (CKI Backport Bot) [RHEL-50999] {CVE-2024-41039}
    - firmware: cs_dsp: Prevent buffer overrun when processing V2 alg headers (CKI Backport Bot) [RHEL-50987]
    {CVE-2024-41038}
    - net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc() (Xin Long) [RHEL-48471]
    {CVE-2024-40995}
    - net: fix out-of-bounds access in ops_init (Xin Long) [RHEL-43185] {CVE-2024-36883}
    - dmaengine: idxd: Fix oops during rmmod on single-CPU platforms (Eder Zulian) [RHEL-37361]
    {CVE-2024-35989}
    - xfs: don't walk off the end of a directory data block (CKI Backport Bot) [RHEL-50879] {CVE-2024-41013}
    - xfs: add bounds checking to xlog_recover_process_data (CKI Backport Bot) [RHEL-50856] {CVE-2024-41014}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-7000.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42225");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-41039");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
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

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.18.0-553.22.1.el8_10'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-7000');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.18';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.22.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-4.18.0'},
    {'reference':'kernel-abi-stablelists-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-4.18.0'},
    {'reference':'kernel-core-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-4.18.0'},
    {'reference':'kernel-cross-headers-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-debug-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-4.18.0'},
    {'reference':'kernel-debug-core-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-4.18.0'},
    {'reference':'kernel-debug-devel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-4.18.0'},
    {'reference':'kernel-debug-modules-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-4.18.0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-4.18.0'},
    {'reference':'kernel-devel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-modules-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-4.18.0'},
    {'reference':'kernel-modules-extra-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.22.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
