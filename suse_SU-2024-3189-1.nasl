#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3189-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(206954);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/11");

  script_cve_id(
    "CVE-2021-4440",
    "CVE-2021-47257",
    "CVE-2021-47289",
    "CVE-2021-47341",
    "CVE-2021-47373",
    "CVE-2021-47425",
    "CVE-2021-47549",
    "CVE-2022-48751",
    "CVE-2022-48769",
    "CVE-2022-48786",
    "CVE-2022-48822",
    "CVE-2022-48865",
    "CVE-2022-48875",
    "CVE-2022-48896",
    "CVE-2022-48899",
    "CVE-2022-48905",
    "CVE-2022-48910",
    "CVE-2022-48919",
    "CVE-2022-48920",
    "CVE-2022-48925",
    "CVE-2022-48930",
    "CVE-2022-48931",
    "CVE-2022-48938",
    "CVE-2023-52708",
    "CVE-2023-52893",
    "CVE-2023-52901",
    "CVE-2023-52907",
    "CVE-2024-26668",
    "CVE-2024-26677",
    "CVE-2024-26812",
    "CVE-2024-26851",
    "CVE-2024-27011",
    "CVE-2024-35915",
    "CVE-2024-35933",
    "CVE-2024-35965",
    "CVE-2024-36013",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-38618",
    "CVE-2024-38662",
    "CVE-2024-39489",
    "CVE-2024-40984",
    "CVE-2024-41012",
    "CVE-2024-41016",
    "CVE-2024-41020",
    "CVE-2024-41035",
    "CVE-2024-41062",
    "CVE-2024-41068",
    "CVE-2024-41087",
    "CVE-2024-41097",
    "CVE-2024-41098",
    "CVE-2024-42077",
    "CVE-2024-42082",
    "CVE-2024-42090",
    "CVE-2024-42101",
    "CVE-2024-42106",
    "CVE-2024-42110",
    "CVE-2024-42148",
    "CVE-2024-42155",
    "CVE-2024-42157",
    "CVE-2024-42158",
    "CVE-2024-42162",
    "CVE-2024-42226",
    "CVE-2024-42228",
    "CVE-2024-42232",
    "CVE-2024-42236",
    "CVE-2024-42240",
    "CVE-2024-42244",
    "CVE-2024-42246",
    "CVE-2024-42259",
    "CVE-2024-42271",
    "CVE-2024-42280",
    "CVE-2024-42281",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42287",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42301",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42312",
    "CVE-2024-42322",
    "CVE-2024-43819",
    "CVE-2024-43831",
    "CVE-2024-43839",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43856",
    "CVE-2024-43861",
    "CVE-2024-43863",
    "CVE-2024-43866",
    "CVE-2024-43871",
    "CVE-2024-43872",
    "CVE-2024-43879",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43900",
    "CVE-2024-43902",
    "CVE-2024-43905",
    "CVE-2024-43907"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3189-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:3189-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:3189-1 advisory.

    The SUSE Linux Enterprise 12 SP5 RT kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-43907: drm/amdgpu/pm: fix the null pointer dereference in apply_state_adjust_rules
    (bsc#1229787).
    - CVE-2024-43905: drm/amd/pm: fix the null pointer dereference for vega10_hwmgr (bsc#1229784).
    - CVE-2024-43902: Add null checker before passing variables (bsc#1229767).
    - CVE-2024-43900: Avoid use-after-free in load_firmware_cb() (bsc#1229756).
    - CVE-2024-43893: Check uartclk for zero to avoid divide by zero (bsc#1229759).
    - CVE-2024-43883: Do not drop references before new references are gained (bsc#1229707).
    - CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
    - CVE-2024-43879: wifi: cfg80211: handle 2x996 RU allocation in cfg80211_calculate_bitrate_he()
    (bsc#1229482).
    - CVE-2024-43872: RDMA/hns: Fix soft lockup under heavy CEQE load (bsc#1229489).
    - CVE-2024-43871: devres: Fix memory leakage caused by driver API devm_free_percpu() (bsc#1229490).
    - CVE-2024-43866: net/mlx5: Always drain health in shutdown callback (bsc#1229495).
    - CVE-2024-43863: drm/vmwgfx: Fix a deadlock in dma buf fence polling (bsc#1229497).
    - CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).
    - CVE-2024-43856: dma: fix call order in dmam_free_coherent (bsc#1229346).
    - CVE-2024-43854: block: initialize integrity buffer to zero before writing it to media (bsc#1229345)
    - CVE-2024-43839: bna: adjust 'name' buf size of bna_tcb and bna_ccb structures (bsc#1229301).
    - CVE-2024-43831: media: mediatek: vcodec: Handle invalid decoder vsi (bsc#1229309).
    - CVE-2024-43819: Reject memory region operations for ucontrol VMs (bsc#1229290 git-fixes).
    - CVE-2024-42322: ipvs: properly dereference pe in ip_vs_add_service (bsc#1229347)
    - CVE-2024-42312: sysctl: always initialize i_uid/i_gid (bsc#1229357)
    - CVE-2024-42310: drm/gma500: fix null pointer dereference in cdv_intel_lvds_get_modes (bsc#1229358).
    - CVE-2024-42309: drm/gma500: fix null pointer dereference in psb_intel_lvds_get_modes (bsc#1229359).
    - CVE-2024-42301: dev/parport: fix the array out-of-bounds risk (bsc#1229407).
    - CVE-2024-42285: RDMA/iwcm: Fix a use-after-free related to destroying CM IDs (bsc#1229381).
    - CVE-2024-42284: tipc: Return non-zero value from tipc_udp_addr2str() on error (bsc#1229382)
    - CVE-2024-42281: bpf: Fix a segment issue when downgrading gso_size (bsc#1229386).
    - CVE-2024-42280: Fix a use after free in hfcmulti_tx() (bsc#1229388)
    - CVE-2024-42271: Fixed a use after free in iucv_sock_close(). (bsc#1229400)
    - CVE-2024-42259: drm/i915/gem: fix Virtual Memory mapping boundaries calculation (bsc#1229156).
    - CVE-2024-42246: net, sunrpc: Remap EPERM in case of connection failure in xs_tcp_setup_socket
    (bsc#1228989).
    - CVE-2024-42244: usb: serial: mos7840: fix crash on resume (bsc#1228967).
    - CVE-2024-42236: usb: gadget: configfs: prevent OOB read/write in usb_string_copy() (bsc#1228964).
    - CVE-2024-42232: Fixed a race between delayed_work() and ceph_monc_stop(). (bsc#1228959)
    - CVE-2024-42228: Using uninitialized value *size when calling amdgpu_vce_cs_reloc (bsc#1228667).
    - CVE-2024-42226: usb: xhci: prevent potential failure in handle_tx_event() for Transfer events without
    TRB (bsc#1228709).
    - CVE-2024-42162: gve: Account for stopped queues when reading NIC stats (bsc#1228706).
    - CVE-2024-42158: s390/pkey: Use kfree_sensitive() to fix Coccinelle warnings (bsc#1228720).
    - CVE-2024-42157: s390/pkey: Wipe sensitive data on failure (bsc#1228727).
    - CVE-2024-42155: s390/pkey: Wipe copies of protected- and secure-keys (bsc#1228733).
    - CVE-2024-42148: bnx2x: Fix multiple UBSAN array-index-out-of-bounds (bsc#1228487).
    - CVE-2024-42110: net: ntb_netdev: Move ntb_netdev_rx_handler() to call netif_rx() from __netif_rx()
    (bsc#1228501).
    - CVE-2024-42106: inet_diag: Initialize pad field in struct inet_diag_req_v2 (bsc#1228493).
    - CVE-2024-42101: drm/nouveau: fix null pointer dereference in nouveau_connector_get_modes (bsc#1228495).
    - CVE-2024-42090: pinctrl: fix deadlock in create_pinctrl() when handling -EPROBE_DEFER (bsc#1228449).
    - CVE-2024-42082: xdp: Remove WARN() from __xdp_reg_mem_model() (bsc#1228482).
    - CVE-2024-41098: ata: libata-core: Fix null pointer dereference on error (bsc#1228467).
    - CVE-2024-41087: Fix double free on error (CVE-2024-41087,bsc#1228466).
    - CVE-2024-41068: s390/sclp: Fix sclp_init() cleanup on failure (bsc#1228579).
    - CVE-2024-41062: bluetooth/l2cap: sync sock recv cb and release (bsc#1228576).
    - CVE-2024-41035: usb: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor
    (bsc#1228485).
    - CVE-2024-41020: filelock: Fix fcntl/close race recovery compat path (bsc#1228427).
    - CVE-2024-41012: filelock: Remove locks reliably when fcntl/close race is detected (bsc#1228247).
    - CVE-2024-40984: ACPICA: Revert 'ACPICA: avoid Info: mapping multiple BARs. Your kernel is fine.'
    (bsc#1227820).
    - CVE-2024-39489: ipv6: sr: fix memleak in seg6_hmac_init_algo (bsc#1227623)
    - CVE-2024-38662: selftests/bpf: Cover verifier checks for mutating sockmap/sockhash (bsc#1226885).
    - CVE-2024-38618: ALSA: timer: Set lower bound of start tick time (bsc#1226754).
    - CVE-2024-36286: netfilter: nfnetlink_queue: acquire rcu_read_lock() in instance_destroy_rcu()
    (bsc#1226801)
    - CVE-2024-36270: Fix reference in patches.suse/netfilter-tproxy-bail-out-if-IP-has-been-disabled-on.patch
    (bsc#1226798)
    - CVE-2024-36013: Fix slab-use-after-free in l2cap_connect() (bsc#1225578).
    - CVE-2024-35965: Bluetooth: L2CAP: Fix not validating setsockopt user input (bsc#1224579).
    - CVE-2024-35933: Bluetooth: btintel: Fix null ptr deref in btintel_read_version (bsc#1224640).
    - CVE-2024-35915: nfc: nci: Fix uninit-value in nci_dev_up and nci_ntf_packet (bsc#1224479).
    - CVE-2024-27011: netfilter: nf_tables: fix memleak in map from abort path (bsc#1223803).
    - CVE-2024-26851: netfilter: nf_conntrack_h323: Add protection for bmp length out of range (bsc#1223074)
    - CVE-2024-26812: kABI: vfio: struct virqfd kABI workaround (bsc#1222808).
    - CVE-2024-26677: Blacklist e7870cf13d20 (' Fix delayed ACKs to not set the reference serial number')
    (bsc#1222387)
    - CVE-2024-26668: netfilter: nft_limit: reject configurations that cause integer overflow (bsc#1222335).
    - CVE-2023-52907: nfc: pn533: Wait for out_urb's completion in pn533_usb_send_frame() (bsc#1229526).
    - CVE-2023-52893: gsmi: fix null-deref in gsmi_get_variable (bsc#1229535).
    - CVE-2023-52708: mmc: mmc_spi: fix error handling in mmc_spi_probe() (bsc#1225483).
    - CVE-2022-48920: Get rid of warning on transaction commit when using flushoncommit (bsc#1229658).
    - CVE-2022-48910: net: ipv6: ensure we call ipv6_mc_down() at most once (bsc#1229632).
    - CVE-2022-48875: wifi: mac80211: sdata can be NULL during AMPDU start (bsc#1229516).
    - CVE-2022-48865: Fix kernel panic when enabling bearer (bsc#1228065).
    - CVE-2022-48822: usb: f_fs: fix use-after-free for epfile (bsc#1228040).
    - CVE-2022-48786: vsock: remove vsock from connected table when connect is interrupted by a signal
    (bsc#1227996).
    - CVE-2022-48769: efi: runtime: avoid EFIv2 runtime services on Apple x86 machines (bsc#1226629).
    - CVE-2022-48751: net/smc: transitional solution for clcsock race issue (bsc#1226653).
    - CVE-2021-47549: sata_fsl: fix UAF in sata_fsl_port_stop when rmmod sata_fsl (bsc#1225508).
    - CVE-2021-47425: i2c: acpi: fix resource leak in reconfiguration device addition (bsc#1225223).
    - CVE-2021-47373: irqchip/gic-v3-its: Fix potential VPE leak on error (bsc#1225190).
    - CVE-2021-47341: KVM: mmio: Fix use-after-free Read in kvm_vm_ioctl_unregister_coalesced_mmio
    (bsc#1224923).
    - CVE-2021-47289: ACPI: fix NULL pointer dereference (bsc#1224984).
    - CVE-2021-47257: net: ieee802154: fix null deref in parse dev addr (bsc#1224896).
    - CVE-2021-4440: x86/xen: drop USERGS_SYSRET64 paravirt call (bsc#1227069).



Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229851");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-September/019404.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?599fdc8b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4440");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47257");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42246");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43907");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43900");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'dlm-kmp-rt-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'gfs2-kmp-rt-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-devel-rt-4.12.14-10.200.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-base-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-devel-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-source-rt-4.12.14-10.200.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-syms-rt-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.200.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
