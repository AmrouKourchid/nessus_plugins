##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.4-2022-004.
##

include('compat.inc');

if (description)
{
  script_id(160440);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/01");

  script_cve_id(
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26141",
    "CVE-2020-26145",
    "CVE-2020-26147",
    "CVE-2020-26541",
    "CVE-2020-26558",
    "CVE-2021-0129",
    "CVE-2021-3506",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-22543",
    "CVE-2021-32399",
    "CVE-2021-33034",
    "CVE-2021-34693",
    "CVE-2021-38208",
    "CVE-2021-46906",
    "CVE-2021-46938",
    "CVE-2021-46939",
    "CVE-2021-46950",
    "CVE-2021-46951",
    "CVE-2021-46953",
    "CVE-2021-46955",
    "CVE-2021-46956",
    "CVE-2021-46959",
    "CVE-2021-46960",
    "CVE-2021-46961",
    "CVE-2021-46963",
    "CVE-2021-46981",
    "CVE-2021-46984",
    "CVE-2021-46985",
    "CVE-2021-46991",
    "CVE-2021-46992",
    "CVE-2021-46993",
    "CVE-2021-46999",
    "CVE-2021-47000",
    "CVE-2021-47006",
    "CVE-2021-47010",
    "CVE-2021-47013",
    "CVE-2021-47015",
    "CVE-2021-47054",
    "CVE-2021-47055",
    "CVE-2021-47058",
    "CVE-2021-47060",
    "CVE-2021-47071",
    "CVE-2021-47078",
    "CVE-2021-47109",
    "CVE-2021-47110",
    "CVE-2021-47112",
    "CVE-2021-47117",
    "CVE-2021-47118",
    "CVE-2021-47120",
    "CVE-2021-47126",
    "CVE-2021-47129",
    "CVE-2021-47138",
    "CVE-2021-47142",
    "CVE-2021-47144",
    "CVE-2021-47145",
    "CVE-2021-47146",
    "CVE-2021-47159",
    "CVE-2021-47162",
    "CVE-2021-47163",
    "CVE-2021-47166",
    "CVE-2021-47167",
    "CVE-2021-47168",
    "CVE-2021-47170",
    "CVE-2021-47171",
    "CVE-2021-47177",
    "CVE-2021-47245",
    "CVE-2021-47254",
    "CVE-2021-47256",
    "CVE-2021-47259",
    "CVE-2021-47261",
    "CVE-2021-47262",
    "CVE-2021-47266",
    "CVE-2021-47274",
    "CVE-2021-47280"
  );
  script_xref(name:"IAVA", value:"2021-A-0223-S");
  script_xref(name:"IAVA", value:"2021-A-0222-S");

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.4-2022-004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.4.129-62.227. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.4-2022-004 advisory.

    A flaw was found in the Linux kernels implementation of wifi fragmentation handling. An attacker with the
    ability to transmit within the wireless transmission range of an access point can abuse a flaw where
    previous contents of wifi fragments can be unintentionally transmitted to another device. (CVE-2020-24586)

    A flaw was found in the Linux kernel's WiFi implementation. An attacker within the wireless range can
    abuse a logic flaw in the WiFi implementation by reassembling packets from multiple fragments under
    different keys, treating them as valid. This flaw allows an attacker to send a fragment under an incorrect
    key, treating them as a valid fragment under the new key. The highest threat from this vulnerability is to
    confidentiality. (CVE-2020-24587)

    A flaw was found in the Linux kernels wifi implementation. An attacker within wireless broadcast range can
    inject custom data into the wireless communication circumventing checks on the data.  This can cause the
    frame to pass checks and be considered a valid frame of a different type. (CVE-2020-24588)

    Frames used for authentication and key management between the AP and connected clients.  Some clients may
    take these redirected frames masquerading as control mechanisms from the AP. (CVE-2020-26139)

    A vulnerability was found in Linux kernel's WiFi implementation.  An attacker within wireless range can
    inject a control packet fragment where the kernel does not verify the Message Integrity Check
    (authenticity) of fragmented TKIP frames. (CVE-2020-26141)

    A flaw was found in ath10k_htt_rx_proc_rx_frag_ind_hl in drivers/net/wireless/ath/ath10k/htt_rx.c in the
    Linux kernel WiFi implementations, where it accepts a second (or subsequent) broadcast fragments even when
    sent in plaintext and then process them as full unfragmented frames. The highest threat from this
    vulnerability is to integrity. (CVE-2020-26145)

    A flaw was found in ieee80211_rx_h_defragment in net/mac80211/rx.c in the Linux Kernel's WiFi
    implementation. This vulnerability can be abused to inject packets or exfiltrate selected fragments when
    another device sends fragmented frames, and the WEP, CCMP, or GCMP data-confidentiality protocol is used.
    The highest threat from this vulnerability is to integrity. (CVE-2020-26147)

    A flaw was found in the Linux kernel in certs/blacklist.c, When signature entries for EFI_CERT_X509_GUID
    are contained in the Secure Boot Forbidden Signature Database, the entries are skipped. This can cause a
    security threat and breach system integrity, confidentiality and even lead to a denial of service problem.
    (CVE-2020-26541)

    A vulnerability was found in the bluez, where Passkey Entry protocol used in Secure Simple Pairing (SSP),
    Secure Connections (SC) and LE Secure Connections (LESC) of the Bluetooth Core Specification is vulnerable
    to an impersonation attack where an active attacker can impersonate the initiating device without any
    previous knowledge. (CVE-2020-26558)

    A flaw was found in the Linux kernel. Improper access control in BlueZ may allow an authenticated user to
    potentially enable information disclosure via adjacent access. The highest threat from this vulnerability
    is to data confidentiality and integrity. (CVE-2021-0129)

    A flaw was found in the Linux kernel's KVM implementation, where improper handing of the VM_IO|VM_PFNMAP
    VMAs in KVM bypasses RO checks and leads to pages being freed while still accessible by the VMM and guest.
    This flaw allows users who can start and control a VM to read/write random pages of memory, resulting in
    local privilege escalation. The highest threat from this vulnerability is to confidentiality, integrity,
    and system availability. (CVE-2021-22543)

    A flaw was found in the Linux kernel's handling of the removal of Bluetooth HCI controllers. This flaw
    allows an attacker with a local account to exploit a race condition, leading to corrupted memory and
    possible privilege escalation. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-32399)

    A use-after-free flaw was found in hci_send_acl in the bluetooth host controller interface (HCI) in Linux
    kernel, where a local attacker with an access rights could cause a denial of service problem on the system
    The issue results from the object hchan, freed in hci_disconn_loglink_complete_evt, yet still used in
    other places. The highest threat from this vulnerability is to data integrity, confidentiality and system
    availability. (CVE-2021-33034)

    The canbus filesystem in the Linux kernel contains an information leak of kernel memory to devices on the
    CAN bus network link layer.  An attacker with the ability to dump messages on the CAN bus is able to learn
    of uninitialized stack values by dumbing messages on the can bus. (CVE-2021-34693)

    An out-of-bounds (OOB) memory access flaw was found in fs/f2fs/node.c in the f2fs module in the Linux
    kernel. A bounds check failure allows a local attacker to gain access to out-of-bounds memory leading to a
    system crash or a leak of internal kernel information. The highest threat from this vulnerability is to
    system availability. (CVE-2021-3506)

    A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. (CVE-2021-3564)

    A flaw use-after-free in function hci_sock_bound_ioctl() of the Linux kernel HCI subsystem was found in
    the way user calls ioct HCIUNBLOCKADDR or other way triggers race condition of the call
    hci_unregister_dev() together with one of the calls hci_sock_blacklist_add(), hci_sock_blacklist_del(),
    hci_get_conn_info(), hci_get_auth_info(). A privileged local user could use this flaw to crash the system
    or escalate their privileges on the system. (CVE-2021-3573)

    A flaw was found in the Linux kernels NFC implementation, A NULL pointer dereference and BUG leading to a
    denial of service can be triggered by a local unprivileged user causing a kernel panic. (CVE-2021-38208)

    In the Linux kernel, the following vulnerability has been resolved:

    HID: usbhid: fix info leak in hid_submit_ctrl

    In hid_submit_ctrl(), the way of calculating the report length doesn'ttake into account that report->size
    can be zero. When running thesyzkaller reproducer, a report of size 0 causes hid_submit_ctrl) tocalculate
    transfer_buffer_length as 16384. When this urb is passed tothe usb core layer, KMSAN reports an info leak
    of 16384 bytes.

    To fix this, first modify hid_report_len() to account for the zeroreport size case by using DIV_ROUND_UP
    for the division. Then, call itfrom hid_submit_ctrl(). (CVE-2021-46906)

    In the Linux kernel, the following vulnerability has been resolved:

    dm rq: fix double free of blk_mq_tag_set in dev remove after table load fails (CVE-2021-46938)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Restructure trace_clock_global() to never block (CVE-2021-46939)

    In the Linux kernel, the following vulnerability has been resolved:

    md/raid1: properly indicate failure when ending a failed write request

    This patch addresses a data corruption bug in raid1 arrays using bitmaps.Without this fix, the bitmap bits
    for the failed I/O end up being cleared.

    Since we are in the failure leg of raid1_end_write_request, the requesteither needs to be retried
    (R1BIO_WriteError) or failed (R1BIO_Degraded). (CVE-2021-46950)

    In the Linux kernel, the following vulnerability has been resolved:

    tpm: efi: Use local variable for calculating final log size (CVE-2021-46951)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: GTDT: Don't corrupt interrupt mappings on watchdow probe failure (CVE-2021-46953)

    In the Linux kernel, the following vulnerability has been resolved:

    openvswitch: fix stack OOB read while fragmenting IPv4 packets (CVE-2021-46955)

    In the Linux kernel, the following vulnerability has been resolved:

    virtiofs: fix memory leak in virtio_fs_probe() (CVE-2021-46956)

    In the Linux kernel, the following vulnerability has been resolved:

    spi: Fix use-after-free with devm_spi_alloc_* (CVE-2021-46959)

    In the Linux kernel, the following vulnerability has been resolved:

    cifs: Return correct error code from smb2_get_enc_key (CVE-2021-46960)

    In the Linux kernel, the following vulnerability has been resolved:

    irqchip/gic-v3: Do not enable irqs when handling spurious interrups (CVE-2021-46961)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: qla2xxx: Fix crash in qla2xxx_mqueuecommand() (CVE-2021-46963)

    In the Linux kernel, the following vulnerability has been resolved:

    nbd: Fix NULL pointer in flush_workqueue (CVE-2021-46981)

    In the Linux kernel, the following vulnerability has been resolved:

    kyber: fix out of bounds access when preempted (CVE-2021-46984)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: scan: Fix a memory leak in an error handling path (CVE-2021-46985)

    In the Linux kernel, the following vulnerability has been resolved:

    i40e: Fix use-after-free in i40e_client_subtask() (CVE-2021-46991)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nftables: avoid overflows in nft_hash_buckets() (CVE-2021-46992)

    In the Linux kernel, the following vulnerability has been resolved:

    sched: Fix out-of-bound access in uclamp (CVE-2021-46993)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: do asoc update earlier in sctp_sf_do_dupcook_a (CVE-2021-46999)

    In the Linux kernel, the following vulnerability has been resolved:

    ceph: fix inode leak on getattr error in __fh_to_dentry (CVE-2021-47000)

    In the Linux kernel, the following vulnerability has been resolved:

    ARM: 9064/1: hw_breakpoint: Do not directly check the event's overflow_handler hook (CVE-2021-47006)

    In the Linux kernel, the following vulnerability has been resolved:

    net: Only allow init netns to set default tcp cong to a restricted algo (CVE-2021-47010)

    In the Linux kernel, the following vulnerability has been resolved:

    net:emac/emac-mac: Fix a use after free in emac_mac_tx_buf_send (CVE-2021-47013)

    In the Linux kernel, the following vulnerability has been resolved:

    bnxt_en: Fix RX consumer index logic in the error path. (CVE-2021-47015)

    In the Linux kernel, the following vulnerability has been resolved:

    bus: qcom: Put child node before return (CVE-2021-47054)

    In the Linux kernel, the following vulnerability has been resolved:

    mtd: require write permissions for locking and badblock ioctls (CVE-2021-47055)

    In the Linux kernel, the following vulnerability has been resolved:

    regmap: set debugfs_name to NULL after it is freed (CVE-2021-47058)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: Stop looking for coalesced MMIO zones if the bus is destroyed (CVE-2021-47060)

    In the Linux kernel, the following vulnerability has been resolved:

    uio_hv_generic: Fix a memory leak in error handling paths (CVE-2021-47071)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/rxe: Clear all QP fields if creation failed (CVE-2021-47078)

    In the Linux kernel, the following vulnerability has been resolved:

    neighbour: allow NUD_NOARP entries to be forced GCed (CVE-2021-47109)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/kvm: Disable kvmclock on all CPUs on shutdown (CVE-2021-47110)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/kvm: Teardown PV features on boot CPU as well (CVE-2021-47112)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed (CVE-2021-47117)

    In the Linux kernel, the following vulnerability has been resolved:

    pid: take a reference when initializing `cad_pid` (CVE-2021-47118)

    In the Linux kernel, the following vulnerability has been resolved:

    HID: magicmouse: fix NULL-deref on disconnect (CVE-2021-47120)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: Fix KASAN: slab-out-of-bounds Read in fib6_nh_flush_exceptions (CVE-2021-47126)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_ct: skip expectations for confirmed conntrack (CVE-2021-47129)

    In the Linux kernel, the following vulnerability has been resolved:

    cxgb4: avoid accessing registers when clearing filters (CVE-2021-47138)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/amdgpu: Fix a use-after-free (CVE-2021-47142)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/amd/amdgpu: fix refcount leak (CVE-2021-47144)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: do not BUG_ON in link_to_fixup_dir (CVE-2021-47145)

    In the Linux kernel, the following vulnerability has been resolved:

    mld: fix panic in mld_newpack() (CVE-2021-47146)

    In the Linux kernel, the following vulnerability has been resolved:

    net: dsa: fix a crash if ->get_sset_count() fails (CVE-2021-47159)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: skb_linearize the head skb when reassembling msgs (CVE-2021-47162)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: wait and exit until all work queues are done (CVE-2021-47163)

    In the Linux kernel, the following vulnerability has been resolved:

    NFS: Don't corrupt the value of pg_bytes_written in nfs_do_recoalesce() (CVE-2021-47166)

    In the Linux kernel, the following vulnerability has been resolved:

    NFS: Fix an Oopsable condition in __nfs_pageio_add_request() (CVE-2021-47167)

    In the Linux kernel, the following vulnerability has been resolved:

    NFS: fix an incorrect limit in filelayout_decode_layout() (CVE-2021-47168)

    In the Linux kernel, the following vulnerability has been resolved:

    USB: usbfs: Don't WARN about excessively large memory allocations (CVE-2021-47170)

    In the Linux kernel, the following vulnerability has been resolved:

    net: usb: fix memory leak in smsc75xx_bind (CVE-2021-47171)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Fix sysfs leak in alloc_iommu() (CVE-2021-47177)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: synproxy: Fix out of bounds when parsing TCP options (CVE-2021-47245)

    In the Linux kernel, the following vulnerability has been resolved:

    gfs2: Fix use-after-free in gfs2_glock_shrink_scan (CVE-2021-47254)

    In the Linux kernel, the following vulnerability has been resolved:

    mm/memory-failure: make sure wait for page writeback in memory_failure (CVE-2021-47256)

    In the Linux kernel, the following vulnerability has been resolved:

    NFS: Fix use-after-free in nfs4_init_client() (CVE-2021-47259)

    In the Linux kernel, the following vulnerability has been resolved:

    IB/mlx5: Fix initializing CQ fragments buffer (CVE-2021-47261)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: x86: Ensure liveliness of nested VM-Enter fail tracepoint message (CVE-2021-47262)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/ipoib: Fix warning caused by destroying non-initial netns (CVE-2021-47266)

    In the Linux kernel, the following vulnerability has been resolved:

    tracing: Correct the length check which causes memory corruption (CVE-2021-47274)

    In the Linux kernel, the following vulnerability has been resolved:

    drm: Fix use-after-free read in drm_getunique() (CVE-2021-47280)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.4-2022-004.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-24586.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-24587.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-24588.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-26139.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-26141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-26145.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-26147.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-26541.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-26558.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-0129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3506.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3564.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3573.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-22543.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32399.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33034.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-34693.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38208.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46906.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46939.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46950.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46951.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46953.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46955.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46956.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46961.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46963.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46981.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46984.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46985.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46991.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46992.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46993.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46999.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47000.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47006.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47010.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47015.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47054.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47055.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47058.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47060.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47071.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47078.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47109.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47110.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47112.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47117.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47118.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47120.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47126.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47138.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47144.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47145.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47146.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47159.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47162.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47163.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47166.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47167.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47168.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47170.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47171.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47177.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47245.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47254.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47256.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47259.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47261.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47262.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47266.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47274.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47280.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3573");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-47261");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2021-22543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kpatch.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2020-26541", "CVE-2020-26558", "CVE-2021-0129", "CVE-2021-3506", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-22543", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-34693", "CVE-2021-38208", "CVE-2021-46906", "CVE-2021-46938", "CVE-2021-46939", "CVE-2021-46950", "CVE-2021-46951", "CVE-2021-46953", "CVE-2021-46955", "CVE-2021-46956", "CVE-2021-46959", "CVE-2021-46960", "CVE-2021-46961", "CVE-2021-46963", "CVE-2021-46981", "CVE-2021-46984", "CVE-2021-46985", "CVE-2021-46991", "CVE-2021-46992", "CVE-2021-46993", "CVE-2021-46999", "CVE-2021-47000", "CVE-2021-47006", "CVE-2021-47010", "CVE-2021-47013", "CVE-2021-47015", "CVE-2021-47054", "CVE-2021-47055", "CVE-2021-47058", "CVE-2021-47060", "CVE-2021-47071", "CVE-2021-47078", "CVE-2021-47109", "CVE-2021-47110", "CVE-2021-47112", "CVE-2021-47117", "CVE-2021-47118", "CVE-2021-47120", "CVE-2021-47126", "CVE-2021-47129", "CVE-2021-47138", "CVE-2021-47142", "CVE-2021-47144", "CVE-2021-47145", "CVE-2021-47146", "CVE-2021-47159", "CVE-2021-47162", "CVE-2021-47163", "CVE-2021-47166", "CVE-2021-47167", "CVE-2021-47168", "CVE-2021-47170", "CVE-2021-47171", "CVE-2021-47177", "CVE-2021-47245", "CVE-2021-47254", "CVE-2021-47256", "CVE-2021-47259", "CVE-2021-47261", "CVE-2021-47262", "CVE-2021-47266", "CVE-2021-47274", "CVE-2021-47280");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.4-2022-004");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.4"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'bpftool-debuginfo-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-aarch64-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-debuginfo-common-x86_64-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-devel-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.129-62.227.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-headers-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-debuginfo-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'kernel-tools-devel-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'perf-debuginfo-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.129-62.227.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'},
    {'reference':'python-perf-debuginfo-5.4.129-62.227.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.4'}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}
