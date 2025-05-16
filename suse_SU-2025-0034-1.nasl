#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0034-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213597);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/09");

  script_cve_id(
    "CVE-2021-46936",
    "CVE-2021-47163",
    "CVE-2021-47416",
    "CVE-2021-47612",
    "CVE-2022-48788",
    "CVE-2022-48789",
    "CVE-2022-48790",
    "CVE-2022-48809",
    "CVE-2022-48946",
    "CVE-2022-48949",
    "CVE-2022-48951",
    "CVE-2022-48956",
    "CVE-2022-48958",
    "CVE-2022-48960",
    "CVE-2022-48962",
    "CVE-2022-48966",
    "CVE-2022-48967",
    "CVE-2022-48969",
    "CVE-2022-48971",
    "CVE-2022-48972",
    "CVE-2022-48973",
    "CVE-2022-48978",
    "CVE-2022-48985",
    "CVE-2022-48988",
    "CVE-2022-48991",
    "CVE-2022-48992",
    "CVE-2022-48997",
    "CVE-2022-49000",
    "CVE-2022-49002",
    "CVE-2022-49010",
    "CVE-2022-49011",
    "CVE-2022-49014",
    "CVE-2022-49015",
    "CVE-2022-49020",
    "CVE-2022-49021",
    "CVE-2022-49026",
    "CVE-2022-49027",
    "CVE-2022-49028",
    "CVE-2022-49029",
    "CVE-2023-6270",
    "CVE-2023-46343",
    "CVE-2023-52881",
    "CVE-2023-52898",
    "CVE-2023-52918",
    "CVE-2023-52919",
    "CVE-2024-26804",
    "CVE-2024-27043",
    "CVE-2024-38538",
    "CVE-2024-39476",
    "CVE-2024-40965",
    "CVE-2024-41016",
    "CVE-2024-41082",
    "CVE-2024-42114",
    "CVE-2024-42145",
    "CVE-2024-42253",
    "CVE-2024-44931",
    "CVE-2024-44958",
    "CVE-2024-46724",
    "CVE-2024-46755",
    "CVE-2024-46802",
    "CVE-2024-46809",
    "CVE-2024-46813",
    "CVE-2024-46816",
    "CVE-2024-46818",
    "CVE-2024-46826",
    "CVE-2024-46834",
    "CVE-2024-46840",
    "CVE-2024-46841",
    "CVE-2024-46848",
    "CVE-2024-47670",
    "CVE-2024-47672",
    "CVE-2024-47673",
    "CVE-2024-47674",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47706",
    "CVE-2024-47707",
    "CVE-2024-47713",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47742",
    "CVE-2024-47745",
    "CVE-2024-47749",
    "CVE-2024-49851",
    "CVE-2024-49860",
    "CVE-2024-49877",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49890",
    "CVE-2024-49891",
    "CVE-2024-49894",
    "CVE-2024-49896",
    "CVE-2024-49901",
    "CVE-2024-49920",
    "CVE-2024-49929",
    "CVE-2024-49936",
    "CVE-2024-49949",
    "CVE-2024-49957",
    "CVE-2024-49958",
    "CVE-2024-49959",
    "CVE-2024-49962",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49967",
    "CVE-2024-49982",
    "CVE-2024-49991",
    "CVE-2024-49995",
    "CVE-2024-49996",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50024",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50045",
    "CVE-2024-50047",
    "CVE-2024-50058"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0034-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2025:0034-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:0034-1 advisory.

    The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

    The Linux Enterprise 12 SP5 kernel turned LTSS (Extended Security)

    The following security bugs were fixed:

    - CVE-2021-46936: Fixed use-after-free in tw_timer_handler() (bsc#1220439).
    - CVE-2021-47163: kABI fix for tipc: wait and exit until all work queues are done (bsc#1221980).
    - CVE-2021-47612: nfc: fix segfault in nfc_genl_dump_devices_done (bsc#1226585).
    - CVE-2022-48809: net: fix a memleak when uncloning an skb dst and its metadata (bsc#1227947).
    - CVE-2022-48951: ASoC: ops: Correct bounds check for second channel on SX controls (bsc#1231929).
    - CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).
    - CVE-2022-48958: ethernet: aeroflex: fix potential skb leak in greth_init_rings() (bsc#1231889).
    - CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx() (bsc#1231979).
    - CVE-2022-48962: net: hisilicon: Fix potential use-after-free in hisi_femac_rx() (bsc#1232286).
    - CVE-2022-48966: net: mvneta: Fix an out of bounds check (bsc#1232191).
    - CVE-2022-48967: NFC: nci: Bounds check struct nfc_target arrays (bsc#1232304).
    - CVE-2022-48971: Bluetooth: Fix not cleanup led when bt_init fails (bsc#1232037).
    - CVE-2022-48972: mac802154: fix missing INIT_LIST_HEAD in ieee802154_if_add() (bsc#1232025).
    - CVE-2022-48973: gpio: amd8111: Fix PCI device reference count leak (bsc#1232039).
    - CVE-2022-48978: HID: core: fix shift-out-of-bounds in hid_report_raw_event (bsc#1232038).
    - CVE-2022-48991: mm/khugepaged: invoke MMU notifiers in shmem/file collapse paths (bsc#1232070).
    - CVE-2022-48992: ASoC: soc-pcm: Add NULL check in BE reparenting (bsc#1232071).
    - CVE-2022-49000: iommu/vt-d: Fix PCI device refcount leak in has_external_pci() (bsc#1232123).
    - CVE-2022-49002: iommu/vt-d: Fix PCI device refcount leak in dmar_dev_scope_init() (bsc#1232133).
    - CVE-2022-49010: hwmon: (coretemp) Check for null before removing sysfs attrs (bsc#1232172).
    - CVE-2022-49011: hwmon: (coretemp) fix pci device refcount leak in nv1a_ram_new() (bsc#1232006).
    - CVE-2022-49014: net: tun: Fix use-after-free in tun_detach() (bsc#1231890).
    - CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).
    - CVE-2022-49020: net/9p: Fix a potential socket leak in p9_socket_open (bsc#1232175).
    - CVE-2022-49021: net: phy: fix null-ptr-deref while probe() failed (bsc#1231939).
    - CVE-2022-49026: e100: Fix possible use after free in e100_xmit_prepare (bsc#1231997).
    - CVE-2022-49027: iavf: Fix error handling in iavf_init_module() (bsc#1232007).
    - CVE-2022-49028: ixgbevf: Fix resource leak in ixgbevf_init_module() (bsc#1231996).
    - CVE-2022-49029: hwmon: (ibmpex) Fix possible UAF when ibmpex_register_bmc() fails (bsc#1231995).
    - CVE-2023-52898: xhci: Fix null pointer dereference when host dies (bsc#1229568).
    - CVE-2023-52918: media: pci: cx23885: check cx23885_vdev_init() return (bsc#1232047).
    - CVE-2024-26804: net: ip_tunnel: prevent perpetual headroom growth (bsc#1222629).
    - CVE-2024-38538: net: bridge: xmit: make sure we have at least eth header len bytes (bsc#1226606).
    - CVE-2024-39476: md/raid5: fix deadlock that raid5d() wait for itself to clear MD_SB_CHANGE_PENDING
    (bsc#1227437).
    - CVE-2024-40965: i2c: lpi2c: Avoid calling clk_get_rate during transfer (bsc#1227885).
    - CVE-2024-41082: nvme-fabrics: use reserved tag for reg read/write command  (bsc#1228620).
    - CVE-2024-42114: netlink: extend policy range validation (bsc#1228564 prerequisite).
    - CVE-2024-42253: gpio: pca953x: fix pca953x_irq_bus_sync_unlock race (bsc#1229005 stable-fixes).
    - CVE-2024-44931: gpio: prevent potential speculation leaks in gpio_device_get_desc() (bsc#1229837 stable-
    fixes).
    - CVE-2024-44958: sched/smt: Fix unbalance sched_smt_present dec/inc (bsc#1230179).
    - CVE-2024-46724: drm/amdgpu: Fix out-of-bounds read of df_v1_7_channel_number (bsc#1230725).
    - CVE-2024-46755: wifi: mwifiex: Do not return unused priv in mwifiex_get_priv_by_id() (bsc#1230802).
    - CVE-2024-46802: drm/amd/display: added NULL check at start of dc_validate_stream (bsc#1231111).
    - CVE-2024-46809: drm/amd/display: Check BIOS images before it is used (bsc#1231148).
    - CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links (bsc#1231191).
    - CVE-2024-46816: drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links
    (bsc#1231197).
    - CVE-2024-46818: drm/amd/display: Check gpio_id before used as array index (bsc#1231203).
    - CVE-2024-46826: ELF: fix kernel.randomize_va_space double read (bsc#1231115).
    - CVE-2024-46834: ethtool: fail closed if we can't get max channel used in indirection tables
    (bsc#1231096).
    - CVE-2024-46840: btrfs: clean up our handling of refs == 0 in snapshot delete (bsc#1231105).
    - CVE-2024-46841: btrfs: do not BUG_ON on ENOMEM from btrfs_lookup_extent_info() in walk_down_proc()
    (bsc#1231094).
    - CVE-2024-46848: perf/x86/intel: Limit the period on Haswell (bsc#1231072).
    - CVE-2024-47672: wifi: iwlwifi: mvm: do not wait for tx queues if firmware is dead (bsc#1231540).
    - CVE-2024-47673: wifi: iwlwifi: mvm: pause TCM when the firmware is stopped (bsc#1231539).
    - CVE-2024-47674: mm: avoid leaving partial pfn mappings around in error case (bsc#1231673).
    - CVE-2024-47684: tcp: check skb is non-NULL in tcp_rto_delta_us() (bsc#1231987).
    - CVE-2024-47685: netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put() (bsc#1231998).
    - CVE-2024-47697: drivers: media: dvb-frontends/rtl2830: fix an out-of-bounds write error (bsc#1231858).
    - CVE-2024-47698: drivers: media: dvb-frontends/rtl2832: fix an out-of-bounds write error (bsc#1231859).
    - CVE-2024-47706: block, bfq: fix possible UAF for bfqq->bic with merge chain (bsc#1231942).
    - CVE-2024-47707: ipv6: avoid possible NULL deref in rt6_uncached_list_flush_dev() (bsc#1231935).
    - CVE-2024-47713: wifi: mac80211: use two-phase skb reclamation in ieee80211_do_stop() (bsc#1232016).
    - CVE-2024-47735: RDMA/hns: Fix spin_unlock_irqrestore() called with IRQs enabled (bsc#1232111).
    - CVE-2024-47737: nfsd: call cache_put if xdr_reserve_space returns NULL (bsc#1232056).
    - CVE-2024-47742: firmware_loader: Block path traversal (bsc#1232126).
    - CVE-2024-47745: mm: split critical region in remap_file_pages() and invoke LSMs in between
    (bsc#1232135).
    - CVE-2024-49851: tpm: Clean up TPM space after command failure (bsc#1232134).
    - CVE-2024-49860: ACPI: sysfs: validate return type of _STR method (bsc#1231861).
    - CVE-2024-49881: ext4: update orig_path in ext4_find_extent() (bsc#1232201).
    - CVE-2024-49882: ext4: fix double brelse() the buffer of the extents path (bsc#1232200).
    - CVE-2024-49883: ext4: aovid use-after-free in ext4_ext_insert_extent() (bsc#1232199).
    - CVE-2024-49890: drm/amd/pm: ensure the fw_info is not null before using it (bsc#1232217).
    - CVE-2024-49891: scsi: lpfc: Validate hdwq pointers before dereferencing in reset/errata paths
    (bsc#1232218).
    - CVE-2024-49894: drm/amd/display: Fix index out of bounds in degamma hardware format translation
    (bsc#1232354).
    - CVE-2024-49896: drm/amd/display: Check stream before comparing them (bsc#1232221).
    - CVE-2024-49901: drm/msm/adreno: Assign msm_gpu->pdev earlier to avoid nullptrs (bsc#1232305).
    - CVE-2024-49920: drm/amd/display: Check null pointers before multiple uses (bsc#1232313).
    - CVE-2024-49929: wifi: iwlwifi: mvm: avoid NULL pointer dereference (bsc#1232253).
    - CVE-2024-49936: net/xen-netback: prevent UAF in xenvif_flush_hash() (bsc#1232424).
    - CVE-2024-49949: net: avoid potential underflow in qdisc_pkt_len_init() with UFO (bsc#1232160).
    - CVE-2024-49958: ocfs2: reserve space for inline xattr before attaching reflink tree (bsc#1232151).
    - CVE-2024-49959: jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error
    (bsc#1232149).
    - CVE-2024-49962: ACPICA: check null return of ACPI_ALLOCATE_ZEROED() in acpi_db_convert_to_package()
    (bsc#1232314).
    - CVE-2024-49966: ocfs2: cancel dqi_sync_work before freeing oinfo (bsc#1232141).
    - CVE-2024-49967: ext4: no need to continue when the number of entries is 1 (bsc#1232140).
    - CVE-2024-49991: drm/amdkfd: amdkfd_free_gtt_mem clear the correct pointer (bsc#1232282).
    - CVE-2024-49995: tipc: guard against string buffer overrun (bsc#1232432).
    - CVE-2024-49996: cifs: Fix buffer overflow when parsing NFS reparse points (bsc#1232089).
    - CVE-2024-50006: ext4: fix i_data_sem unlock order in ext4_ind_migrate() (bsc#1232442).
    - CVE-2024-50007: ALSA: asihpi: Fix potential OOB array access (bsc#1232394).
    - CVE-2024-50024: net: Fix an unsafe loop on the list (bsc#1231954).
    - CVE-2024-50033: slip: make slhc_remember() more robust against malicious packets (bsc#1231914).
    - CVE-2024-50035: ppp: fix ppp_async_encode() illegal access (bsc#1232392).
    - CVE-2024-50045: netfilter: br_netfilter: fix panic with metadata_dst skb (bsc#1231903).
    - CVE-2024-50047: smb: client: fix UAF in async decryption (bsc#1232418).
    - CVE-2024-50058: serial: protect uart_port_dtr_rts() in uart_shutdown() too (bsc#1232285).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232442");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020071.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10862ddc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47163");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49027");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42253");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50058");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cluster-md-kmp-default-4.12.14-122.234.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.234.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.234.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.234.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.234.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.234.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.234.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.234.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.234.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.234.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
