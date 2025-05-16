#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4367-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213130);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2021-47162",
    "CVE-2022-48853",
    "CVE-2024-26801",
    "CVE-2024-26852",
    "CVE-2024-26886",
    "CVE-2024-27051",
    "CVE-2024-35937",
    "CVE-2024-36886",
    "CVE-2024-36905",
    "CVE-2024-36954",
    "CVE-2024-42098",
    "CVE-2024-42131",
    "CVE-2024-42229",
    "CVE-2024-44995",
    "CVE-2024-45016",
    "CVE-2024-46771",
    "CVE-2024-46777",
    "CVE-2024-46800",
    "CVE-2024-47660",
    "CVE-2024-47679",
    "CVE-2024-47701",
    "CVE-2024-49858",
    "CVE-2024-49868",
    "CVE-2024-49884",
    "CVE-2024-49921",
    "CVE-2024-49925",
    "CVE-2024-49938",
    "CVE-2024-49945",
    "CVE-2024-49950",
    "CVE-2024-49952",
    "CVE-2024-50044",
    "CVE-2024-50055",
    "CVE-2024-50073",
    "CVE-2024-50074",
    "CVE-2024-50095",
    "CVE-2024-50099",
    "CVE-2024-50115",
    "CVE-2024-50117",
    "CVE-2024-50125",
    "CVE-2024-50135",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50154",
    "CVE-2024-50167",
    "CVE-2024-50171",
    "CVE-2024-50179",
    "CVE-2024-50183",
    "CVE-2024-50187",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50210",
    "CVE-2024-50218",
    "CVE-2024-50234",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50264",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50273",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50289",
    "CVE-2024-50290",
    "CVE-2024-50296",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-53058",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53085",
    "CVE-2024-53088",
    "CVE-2024-53104",
    "CVE-2024-53114",
    "CVE-2024-53142"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4367-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:4367-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:4367-1 advisory.

    The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2022-48853: swiotlb: fix info leak with DMA_FROM_DEVICE (bsc#1228015).
    - CVE-2024-26801: Bluetooth: Avoid potential use-after-free in hci_error_reset (bsc#1222413).
    - CVE-2024-26852: Fixed use-after-free in ip6_route_mpath_notify() (bsc#1223057).
    - CVE-2024-26886: Bluetooth: af_bluetooth: Fix deadlock (bsc#1223044).
    - CVE-2024-27051: cpufreq: brcmstb-avs-cpufreq: add check for cpufreq_cpu_get's return value
    (bsc#1223769).
    - CVE-2024-35937: wifi: cfg80211: check A-MSDU format more carefully (bsc#1224526).
    - CVE-2024-36905: tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets (bsc#1225742).
    - CVE-2024-42098: crypto: ecdh - explicitly zeroize private_key (bsc#1228779).
    - CVE-2024-42229: crypto: aead,cipher - zeroize key buffer after use (bsc#1228708).
    - CVE-2024-44995: net: hns3: fix a deadlock problem when config TC during resetting (bsc#1230231).
    - CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
    - CVE-2024-46771: can: bcm: Remove proc entry when dev is unregistered (bsc#1230766).
    - CVE-2024-46777: udf: Avoid excessive partition lengths (bsc#1230773).
    - CVE-2024-46800: sch/netem: fix use after free in netem_dequeue (bsc#1230827).
    - CVE-2024-47660: fsnotify: clear PARENT_WATCHED flags lazily (bsc#1231439).
    - CVE-2024-47679: vfs: fix race between evice_inodes() and find_inode()&iput() (bsc#1231930).
    - CVE-2024-47701: ext4: avoid OOB when system.data xattr changes underneath the filesystem (bsc#1231920).
    - CVE-2024-49858: efistub/tpm: Use ACPI reclaim memory for event log to avoid corruption (bsc#1232251).
    - CVE-2024-49868: btrfs: fix a NULL pointer dereference when failed to start a new trasacntion
    (bsc#1232272).
    - CVE-2024-49921: drm/amd/display: Check null pointers before used (bsc#1232371).
    - CVE-2024-49925: fbdev: efifb: Register sysfs groups through driver core (bsc#1232224)
    - CVE-2024-49938: wifi: ath9k_htc: Use __skb_set_length() for resetting urb before resubmit (bsc#1232552).
    - CVE-2024-49945: net/ncsi: Disable the ncsi work before freeing the associated structure (bsc#1232165).
    - CVE-2024-49950: Bluetooth: L2CAP: Fix uaf in l2cap_connect (bsc#1232159).
    - CVE-2024-49952: netfilter: nf_tables: prevent nf_skb_duplicated corruption (bsc#1232157).
    - CVE-2024-50044: Bluetooth: RFCOMM: FIX possible deadlock in rfcomm_sk_state_change (bsc#1231904).
    - CVE-2024-50055: driver core: bus: Fix double free in driver API bus_register() (bsc#1232329).
    - CVE-2024-50073: tty: n_gsm: Fix use-after-free in gsm_cleanup_mux (bsc#1232520).
    - CVE-2024-50074: parport: Proper fix for array out-of-bounds access (bsc#1232507).
    - CVE-2024-50095: RDMA/mad: Improve handling of timed out WRs of mad agent (bsc#1232873).
    - CVE-2024-50115: KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (bsc#1232919).
    - CVE-2024-50117: drm/amd: Guard against bad data for ATIF ACPI method (bsc#1232897).
    - CVE-2024-50125: Bluetooth: SCO: Fix UAF on sco_sock_timeout (bsc#1232928).
    - CVE-2024-50135: nvme-pci: fix race condition between reset and nvme_dev_disable() (bsc#1232888).
    - CVE-2024-50148: Bluetooth: bnep: fix wild-memory-access in proto_unregister (bsc#1233063).
    - CVE-2024-50150: usb: typec: altmode should keep reference to parent (bsc#1233051).
    - CVE-2024-50154: tcp/dccp: Do not use timer_pending() in reqsk_queue_unlink() (bsc#1233070).
    - CVE-2024-50167: be2net: fix potential memory leak in be_xmit() (bsc#1233049).
    - CVE-2024-50171: net: systemport: fix potential memory leak in bcm_sysport_xmit() (bsc#1233057).
    - CVE-2024-50183: scsi: lpfc: Ensure DA_ID handling completion before deleting an NPIV instance
    (bsc#1233130).
    - CVE-2024-50187: drm/vc4: Stop the active perfmon before being destroyed (bsc#1233108).
    - CVE-2024-50195: posix-clock: Fix missing timespec64 check in pc_clock_settime() (bsc#1233103).
    - CVE-2024-50218: ocfs2: pass u64 to ocfs2_truncate_inline maybe overflow (bsc#1233191).
    - CVE-2024-50234: wifi: iwlegacy: Clear stale interrupts before resuming device (bsc#1233211).
    - CVE-2024-50236: wifi: ath10k: Fix memory leak in management tx (bsc#1233212).
    - CVE-2024-50237: wifi: mac80211: do not pass a stopped vif to the driver in .get_txpower (bsc#1233216).
    - CVE-2024-50264: vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans
    (bsc#1233453).
    - CVE-2024-50265: ocfs2: remove entry once instead of null-ptr-dereference in ocfs2_xa_remove()
    (bsc#1233454).
    - CVE-2024-50267: usb: serial: io_edgeport: fix use after free in debug printk (bsc#1233456).
    - CVE-2024-50273: btrfs: reinitialize delayed ref list after deleting it from the list (bsc#1233462).
    - CVE-2024-50278: dm cache: fix potential out-of-bounds access on the first resume (bsc#1233467).
    - CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when resizing (bsc#1233468).
    - CVE-2024-50289: media: av7110: fix a spectre vulnerability (bsc#1233478).
    - CVE-2024-50290: media: cx24116: prevent overflows on SNR calculus (bsc#1233479).
    - CVE-2024-50296: net: hns3: fix kernel crash when uninstalling driver (bsc#1233485).
    - CVE-2024-50301: security/keys: fix slab-out-of-bounds in key_task_permission (bsc#1233490).
    - CVE-2024-50302: HID: core: zero-initialize the report buffer (bsc#1233491).
    - CVE-2024-53058: net: stmmac: TSO: Fix unbalanced DMA map/unmap for non-paged SKB data (bsc#1233552).
    - CVE-2024-53061: media: s5p-jpeg: prevent buffer overflows (bsc#1233555).
    - CVE-2024-53063: media: dvbdev: prevent the risk of out of memory access (bsc#1233557).
    - CVE-2024-53066: nfs: Fix KMSAN warning in decode_getfattr_attrs() (bsc#1233560).
    - CVE-2024-53085: tpm: Lock TPM chip in tpm_pm_suspend() first (bsc#1082555 bsc#1233577).
    - CVE-2024-53088: i40e: fix race condition by adding filter's intermediate sync state (bsc#1233580).
    - CVE-2024-53104: media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format
    (bsc#1234025).
    - CVE-2024-53114: x86/CPU/AMD: Clear virtualized VMLOAD/VMSAVE on Zen4 client (bsc#1234072).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234087");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/020025.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85555865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50167");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50195");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50273");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50278");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53142");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53142");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_237-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cluster-md-kmp-default-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'kernel-default-kgraft-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_237-default-1-8.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.237.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.237.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.237.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.237.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.237.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.237.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
      severity   : SECURITY_WARNING,
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
