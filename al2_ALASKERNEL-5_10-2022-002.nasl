##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.10-2022-002.
##

include('compat.inc');

if (description)
{
  script_id(160459);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/17");

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
    "CVE-2020-36776",
    "CVE-2021-0129",
    "CVE-2021-3489",
    "CVE-2021-3490",
    "CVE-2021-3491",
    "CVE-2021-3506",
    "CVE-2021-3543",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-22543",
    "CVE-2021-28691",
    "CVE-2021-31440",
    "CVE-2021-32399",
    "CVE-2021-33034",
    "CVE-2021-33200",
    "CVE-2021-33624",
    "CVE-2021-34693",
    "CVE-2021-38208",
    "CVE-2021-46906",
    "CVE-2021-46938",
    "CVE-2021-46939",
    "CVE-2021-46950",
    "CVE-2021-46951",
    "CVE-2021-46952",
    "CVE-2021-46953",
    "CVE-2021-46955",
    "CVE-2021-46956",
    "CVE-2021-46958",
    "CVE-2021-46959",
    "CVE-2021-46960",
    "CVE-2021-46961",
    "CVE-2021-46963",
    "CVE-2021-46976",
    "CVE-2021-46977",
    "CVE-2021-46978",
    "CVE-2021-46981",
    "CVE-2021-46984",
    "CVE-2021-46985",
    "CVE-2021-46991",
    "CVE-2021-46992",
    "CVE-2021-46993",
    "CVE-2021-46996",
    "CVE-2021-46997",
    "CVE-2021-46999",
    "CVE-2021-47000",
    "CVE-2021-47001",
    "CVE-2021-47006",
    "CVE-2021-47009",
    "CVE-2021-47010",
    "CVE-2021-47011",
    "CVE-2021-47013",
    "CVE-2021-47015",
    "CVE-2021-47024",
    "CVE-2021-47035",
    "CVE-2021-47040",
    "CVE-2021-47044",
    "CVE-2021-47049",
    "CVE-2021-47054",
    "CVE-2021-47055",
    "CVE-2021-47058",
    "CVE-2021-47060",
    "CVE-2021-47061",
    "CVE-2021-47063",
    "CVE-2021-47066",
    "CVE-2021-47069",
    "CVE-2021-47071",
    "CVE-2021-47074",
    "CVE-2021-47075",
    "CVE-2021-47078",
    "CVE-2021-47080",
    "CVE-2021-47109",
    "CVE-2021-47110",
    "CVE-2021-47111",
    "CVE-2021-47112",
    "CVE-2021-47113",
    "CVE-2021-47116",
    "CVE-2021-47117",
    "CVE-2021-47118",
    "CVE-2021-47119",
    "CVE-2021-47120",
    "CVE-2021-47124",
    "CVE-2021-47126",
    "CVE-2021-47128",
    "CVE-2021-47129",
    "CVE-2021-47130",
    "CVE-2021-47131",
    "CVE-2021-47134",
    "CVE-2021-47136",
    "CVE-2021-47138",
    "CVE-2021-47142",
    "CVE-2021-47144",
    "CVE-2021-47145",
    "CVE-2021-47146",
    "CVE-2021-47152",
    "CVE-2021-47159",
    "CVE-2021-47162",
    "CVE-2021-47163",
    "CVE-2021-47164",
    "CVE-2021-47166",
    "CVE-2021-47167",
    "CVE-2021-47168",
    "CVE-2021-47170",
    "CVE-2021-47171",
    "CVE-2021-47174",
    "CVE-2021-47175",
    "CVE-2021-47177",
    "CVE-2021-47227",
    "CVE-2021-47241",
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

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.10-2022-002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.10.47-39.130. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.10-2022-002 advisory.

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

    In the Linux kernel, the following vulnerability has been resolved:

    thermal/drivers/cpufreq_cooling: Fix slab OOB issue (CVE-2020-36776)

    A flaw was found in the Linux kernel. Improper access control in BlueZ may allow an authenticated user to
    potentially enable information disclosure via adjacent access. The highest threat from this vulnerability
    is to data confidentiality and integrity. (CVE-2021-0129)

    A flaw was found in the Linux kernel's KVM implementation, where improper handing of the VM_IO|VM_PFNMAP
    VMAs in KVM bypasses RO checks and leads to pages being freed while still accessible by the VMM and guest.
    This flaw allows users who can start and control a VM to read/write random pages of memory, resulting in
    local privilege escalation. The highest threat from this vulnerability is to confidentiality, integrity,
    and system availability. (CVE-2021-22543)

    Guest triggered use-after-free in Linux xen-netback A malicious or buggy network PV frontend can force
    Linux netback to disable the interface and terminate the receive kernel thread associated with queue 0 in
    response to the frontend sending a malformed packet. Such kernel thread termination will lead to a use-
    after-free in Linux netback when the backend is destroyed, as the kernel thread associated with queue 0
    will have already exited and thus the call to kthread_stop will be performed against a stale pointer.
    (CVE-2021-28691)

    An out-of-bounds access flaw was found in the Linux kernel's implementation of the eBPF code verifier,
    where an incorrect register bounds calculation while checking unsigned 32-bit instructions in an eBPF
    program occurs.. By default accessing the eBPF verifier is only accessible to privileged users with
    CAP_SYS_ADMIN. The issue results from the lack of proper validation of user-supplied eBPF programs prior
    to executing them. A local user could use this flaw to crash the system or possibly escalate their
    privileges on the system. (CVE-2021-31440)

    A flaw was found in the Linux kernel's handling of the removal of Bluetooth HCI controllers. This flaw
    allows an attacker with a local account to exploit a race condition, leading to corrupted memory and
    possible privilege escalation. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-32399)

    A use-after-free flaw was found in hci_send_acl in the bluetooth host controller interface (HCI) in Linux
    kernel, where a local attacker with an access rights could cause a denial of service problem on the system
    The issue results from the object hchan, freed in hci_disconn_loglink_complete_evt, yet still used in
    other places. The highest threat from this vulnerability is to data integrity, confidentiality and system
    availability. (CVE-2021-33034)

    A flaw was found in kernel/bpf/verifier.c in BPF in the Linux kernel. An incorrect limit is enforced for
    pointer arithmetic operations which can be abused to perform out-of-bounds reads and writes in kernel
    memory, leading to local privilege escalation. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2021-33200)

    In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because
    of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a
    side-channel attack, aka CID-9183671af6db. (CVE-2021-33624)

    The canbus filesystem in the Linux kernel contains an information leak of kernel memory to devices on the
    CAN bus network link layer.  An attacker with the ability to dump messages on the CAN bus is able to learn
    of uninitialized stack values by dumbing messages on the can bus. (CVE-2021-34693)

    The eBPF RINGBUF bpf_ringbuf_reserve() function in the Linux kernel did not check that the allocated size
    was smaller than the ringbuf size, allowing an attacker to perform out-of-bounds writes within the kernel
    and therefore, arbitrary code execution. This issue was fixed via commit 4b81ccebaeee (bpf, ringbuf: Deny
    reserve of buffers larger than ringbuf) (v5.13-rc4) and backported to the stable kernels in v5.12.4,
    v5.11.21, and v5.10.37. It was introduced via 457f44363a88 (bpf: Implement BPF ring buffer and verifier
    support for it) (v5.8-rc1). (CVE-2021-3489)

    The eBPF ALU32 bounds tracking for bitwise ops (AND, OR and XOR) in the Linux kernel did not properly
    update 32-bit bounds, which could be turned into out of bounds reads and writes in the Linux kernel and
    therefore, arbitrary code execution. This issue was fixed via commit 049c4e13714e (bpf: Fix alu32 const
    subreg bound tracking on bitwise operations) (v5.13-rc4) and backported to the stable kernels in v5.12.4,
    v5.11.21, and v5.10.37. The AND/OR issues were introduced by commit 3f50f132d840 (bpf: Verifier, do
    explicit ALU32 bounds tracking) (5.7-rc1) and the XOR variant was introduced by 2921c90d4718 (bpf:Fix a
    verifier failure with xor) ( 5.10-rc1). (CVE-2021-3490)

    A flaw was found in the Linux kernel.  The io_uring PROVIDE_BUFFERS operation allowed the MAX_RW_COUNT
    limit to be bypassed, which led to negative values being used in mem_rw when reading /proc/<PID>/mem. The
    highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2021-3491)

    An out-of-bounds (OOB) memory access flaw was found in fs/f2fs/node.c in the f2fs module in the Linux
    kernel. A bounds check failure allows a local attacker to gain access to out-of-bounds memory leading to a
    system crash or a leak of internal kernel information. The highest threat from this vulnerability is to
    system availability. (CVE-2021-3506)

    A flaw null pointer dereference in the Nitro Enclaves kernel driver was found in the way that Enclaves VMs
    forces closures on the enclave file descriptor. A local user of a host machine could use this flaw to
    crash the system or escalate their privileges on the system. (CVE-2021-3543)

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

    NFS: fs_context: validate UDP retrans to prevent shift out-of-bounds (CVE-2021-46952)

    In the Linux kernel, the following vulnerability has been resolved:

    ACPI: GTDT: Don't corrupt interrupt mappings on watchdow probe failure (CVE-2021-46953)

    In the Linux kernel, the following vulnerability has been resolved:

    openvswitch: fix stack OOB read while fragmenting IPv4 packets (CVE-2021-46955)

    In the Linux kernel, the following vulnerability has been resolved:

    virtiofs: fix memory leak in virtio_fs_probe() (CVE-2021-46956)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix race between transaction aborts and fsyncs leading to use-after-free (CVE-2021-46958)

    In the Linux kernel, the following vulnerability has been resolved:

    spi: Fix use-after-free with devm_spi_alloc_* (CVE-2021-46959)

    In the Linux kernel, the following vulnerability has been resolved:

    cifs: Return correct error code from smb2_get_enc_key (CVE-2021-46960)

    In the Linux kernel, the following vulnerability has been resolved:

    irqchip/gic-v3: Do not enable irqs when handling spurious interrups (CVE-2021-46961)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: qla2xxx: Fix crash in qla2xxx_mqueuecommand() (CVE-2021-46963)

    In the Linux kernel, the following vulnerability has been resolved:

    drm/i915: Fix crash in auto_retire (CVE-2021-46976)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: VMX: Disable preemption when probing user return MSRs (CVE-2021-46977)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: nVMX: Always make an attempt to map eVMCS after migration (CVE-2021-46978)

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

    netfilter: nftables: Fix a memleak from userdata error path in new objects (CVE-2021-46996)

    In the Linux kernel, the following vulnerability has been resolved:

    arm64: entry: always set GIC_PRIO_PSR_I_SET during entry (CVE-2021-46997)

    In the Linux kernel, the following vulnerability has been resolved:

    sctp: do asoc update earlier in sctp_sf_do_dupcook_a (CVE-2021-46999)

    In the Linux kernel, the following vulnerability has been resolved:

    ceph: fix inode leak on getattr error in __fh_to_dentry (CVE-2021-47000)

    In the Linux kernel, the following vulnerability has been resolved:

    xprtrdma: Fix cwnd update ordering (CVE-2021-47001)

    In the Linux kernel, the following vulnerability has been resolved:

    ARM: 9064/1: hw_breakpoint: Do not directly check the event's overflow_handler hook (CVE-2021-47006)

    In the Linux kernel, the following vulnerability has been resolved:

    KEYS: trusted: Fix memory leak on object td (CVE-2021-47009)

    In the Linux kernel, the following vulnerability has been resolved:

    net: Only allow init netns to set default tcp cong to a restricted algo (CVE-2021-47010)

    In the Linux kernel, the following vulnerability has been resolved:

    mm: memcontrol: slab: fix obtain a reference to a freeing memcg (CVE-2021-47011)

    In the Linux kernel, the following vulnerability has been resolved:

    net:emac/emac-mac: Fix a use after free in emac_mac_tx_buf_send (CVE-2021-47013)

    In the Linux kernel, the following vulnerability has been resolved:

    bnxt_en: Fix RX consumer index logic in the error path. (CVE-2021-47015)

    In the Linux kernel, the following vulnerability has been resolved:

    vsock/virtio: free queued packets when closing socket (CVE-2021-47024)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Remove WO permissions on second-level paging entries (CVE-2021-47035)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: fix overflows checks in provide buffers (CVE-2021-47040)

    In the Linux kernel, the following vulnerability has been resolved:

    sched/fair: Fix shift-out-of-bounds in load_balance() (CVE-2021-47044)

    In the Linux kernel, the following vulnerability has been resolved:

    Drivers: hv: vmbus: Use after free in __vmbus_open() (CVE-2021-47049)

    In the Linux kernel, the following vulnerability has been resolved:

    bus: qcom: Put child node before return (CVE-2021-47054)

    In the Linux kernel, the following vulnerability has been resolved:

    mtd: require write permissions for locking and badblock ioctls (CVE-2021-47055)

    In the Linux kernel, the following vulnerability has been resolved:

    regmap: set debugfs_name to NULL after it is freed (CVE-2021-47058)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: Stop looking for coalesced MMIO zones if the bus is destroyed (CVE-2021-47060)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: Destroy I/O bus devices on unregister failure _after_ sync'ing SRCU (CVE-2021-47061)

    In the Linux kernel, the following vulnerability has been resolved:

    drm: bridge/panel: Cleanup connector on bridge detach (CVE-2021-47063)

    In the Linux kernel, the following vulnerability has been resolved:

    async_xor: increase src_offs when dropping destination page (CVE-2021-47066)

    In the Linux kernel, the following vulnerability has been resolved:

    ipc/mqueue, msg, sem: avoid relying on a stack reference past its expiry (CVE-2021-47069)

    In the Linux kernel, the following vulnerability has been resolved:

    uio_hv_generic: Fix a memory leak in error handling paths (CVE-2021-47071)

    In the Linux kernel, the following vulnerability has been resolved:

    nvme-loop: fix memory leak in nvme_loop_create_ctrl() (CVE-2021-47074)

    In the Linux kernel, the following vulnerability has been resolved:

    nvmet: fix memory leak in nvmet_alloc_ctrl() (CVE-2021-47075)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/rxe: Clear all QP fields if creation failed (CVE-2021-47078)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/core: Prevent divide-by-zero error triggered by the user (CVE-2021-47080)

    In the Linux kernel, the following vulnerability has been resolved:

    neighbour: allow NUD_NOARP entries to be forced GCed (CVE-2021-47109)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/kvm: Disable kvmclock on all CPUs on shutdown (CVE-2021-47110)

    In the Linux kernel, the following vulnerability has been resolved:

    xen-netback: take a reference to the RX task thread (CVE-2021-47111)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/kvm: Teardown PV features on boot CPU as well (CVE-2021-47112)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: abort in rename_exchange if we fail to insert the second ref (CVE-2021-47113)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix memory leak in ext4_mb_init_backend on error path. (CVE-2021-47116)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed (CVE-2021-47117)

    In the Linux kernel, the following vulnerability has been resolved:

    pid: take a reference when initializing `cad_pid` (CVE-2021-47118)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix memory leak in ext4_fill_super (CVE-2021-47119)

    In the Linux kernel, the following vulnerability has been resolved:

    HID: magicmouse: fix NULL-deref on disconnect (CVE-2021-47120)

    In the Linux kernel, the following vulnerability has been resolved:

    io_uring: fix link timeout refs (CVE-2021-47124)

    In the Linux kernel, the following vulnerability has been resolved:

    ipv6: Fix KASAN: slab-out-of-bounds Read in fib6_nh_flush_exceptions (CVE-2021-47126)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf, lockdown, audit: Fix buggy SELinux lockdown permission checks (CVE-2021-47128)

    In the Linux kernel, the following vulnerability has been resolved:

    netfilter: nft_ct: skip expectations for confirmed conntrack (CVE-2021-47129)

    In the Linux kernel, the following vulnerability has been resolved:

    nvmet: fix freeing unallocated p2pmem (CVE-2021-47130)

    In the Linux kernel, the following vulnerability has been resolved: net/tls: Fix use-after-free after the
    TLS device goes down and up When a netdev with active TLS offload goes down, tls_device_down is called to
    stop the offload and tear down the TLS context. However, the socket stays alive, and it still points to
    the TLS context, which is now deallocated. If a netdev goes up, while the connection is still active, and
    the data flow resumes after a number of TCP retransmissions, it will lead to a use-after-free of the TLS
    context. This commit addresses this bug by keeping the context alive until its normal destruction, and
    implements the necessary fallbacks, so that the connection can resume in software (non-offloaded) kTLS
    mode. (CVE-2021-47131)

    In the Linux kernel, the following vulnerability has been resolved:

    efi/fdt: fix panic when no valid fdt found (CVE-2021-47134)

    In the Linux kernel, the following vulnerability has been resolved:

    net: zero-initialize tc skb extension on allocation (CVE-2021-47136)

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

    mptcp: fix data stream corruption (CVE-2021-47152)

    In the Linux kernel, the following vulnerability has been resolved:

    net: dsa: fix a crash if ->get_sset_count() fails (CVE-2021-47159)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: skb_linearize the head skb when reassembling msgs (CVE-2021-47162)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: wait and exit until all work queues are done (CVE-2021-47163)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: Fix null deref accessing lag dev (CVE-2021-47164)

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

    netfilter: nft_set_pipapo_avx2: Add irq_fpu_usable() check, fallback to non-AVX2 version (CVE-2021-47174)

    In the Linux kernel, the following vulnerability has been resolved:

    net/sched: fq_pie: fix OOB access in the traffic path (CVE-2021-47175)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Fix sysfs leak in alloc_iommu() (CVE-2021-47177)

    In the Linux kernel, the following vulnerability has been resolved:

    x86/fpu: Prevent state corruption in __fpu__restore_sig() (CVE-2021-47227)

    In the Linux kernel, the following vulnerability has been resolved:

    ethtool: strset: fix message length calculation (CVE-2021-47241)

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
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2022-002.html");
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
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-36776.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-0129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3489.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3490.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3491.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3506.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3543.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3564.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3573.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-22543.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28691.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-31440.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32399.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33034.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33200.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-33624.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-34693.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38208.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46906.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46939.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46950.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46951.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46952.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46953.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46955.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46956.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46958.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46961.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46963.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46976.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46977.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46978.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46981.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46984.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46985.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46991.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46992.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46993.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46996.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46997.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-46999.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47000.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47001.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47006.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47009.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47010.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47011.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47015.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47024.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47035.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47040.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47044.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47049.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47054.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47055.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47058.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47060.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47061.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47063.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47066.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47069.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47071.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47074.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47075.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47078.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47080.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47109.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47110.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47111.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47112.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47113.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47116.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47117.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47118.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47119.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47120.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47124.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47126.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47128.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47130.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47134.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47136.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47138.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47142.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47144.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47145.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47146.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47152.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47159.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47162.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47163.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47164.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47166.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47167.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47168.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47170.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47171.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47174.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47175.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47177.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47227.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47241.html");
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
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3543");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3491");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2021-22543");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux eBPF ALU32 32-bit Invalid Bounds Tracking LPE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/20");
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
  var cve_list = make_list("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2020-26541", "CVE-2020-26558", "CVE-2020-36776", "CVE-2021-0129", "CVE-2021-3489", "CVE-2021-3490", "CVE-2021-3491", "CVE-2021-3506", "CVE-2021-3543", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-22543", "CVE-2021-28691", "CVE-2021-31440", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33200", "CVE-2021-33624", "CVE-2021-34693", "CVE-2021-38208", "CVE-2021-46906", "CVE-2021-46938", "CVE-2021-46939", "CVE-2021-46950", "CVE-2021-46951", "CVE-2021-46952", "CVE-2021-46953", "CVE-2021-46955", "CVE-2021-46956", "CVE-2021-46958", "CVE-2021-46959", "CVE-2021-46960", "CVE-2021-46961", "CVE-2021-46963", "CVE-2021-46976", "CVE-2021-46977", "CVE-2021-46978", "CVE-2021-46981", "CVE-2021-46984", "CVE-2021-46985", "CVE-2021-46991", "CVE-2021-46992", "CVE-2021-46993", "CVE-2021-46996", "CVE-2021-46997", "CVE-2021-46999", "CVE-2021-47000", "CVE-2021-47001", "CVE-2021-47006", "CVE-2021-47009", "CVE-2021-47010", "CVE-2021-47011", "CVE-2021-47013", "CVE-2021-47015", "CVE-2021-47024", "CVE-2021-47035", "CVE-2021-47040", "CVE-2021-47044", "CVE-2021-47049", "CVE-2021-47054", "CVE-2021-47055", "CVE-2021-47058", "CVE-2021-47060", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47066", "CVE-2021-47069", "CVE-2021-47071", "CVE-2021-47074", "CVE-2021-47075", "CVE-2021-47078", "CVE-2021-47080", "CVE-2021-47109", "CVE-2021-47110", "CVE-2021-47111", "CVE-2021-47112", "CVE-2021-47113", "CVE-2021-47116", "CVE-2021-47117", "CVE-2021-47118", "CVE-2021-47119", "CVE-2021-47120", "CVE-2021-47124", "CVE-2021-47126", "CVE-2021-47128", "CVE-2021-47129", "CVE-2021-47130", "CVE-2021-47131", "CVE-2021-47134", "CVE-2021-47136", "CVE-2021-47138", "CVE-2021-47142", "CVE-2021-47144", "CVE-2021-47145", "CVE-2021-47146", "CVE-2021-47152", "CVE-2021-47159", "CVE-2021-47162", "CVE-2021-47163", "CVE-2021-47164", "CVE-2021-47166", "CVE-2021-47167", "CVE-2021-47168", "CVE-2021-47170", "CVE-2021-47171", "CVE-2021-47174", "CVE-2021-47175", "CVE-2021-47177", "CVE-2021-47227", "CVE-2021-47241", "CVE-2021-47245", "CVE-2021-47254", "CVE-2021-47256", "CVE-2021-47259", "CVE-2021-47261", "CVE-2021-47262", "CVE-2021-47266", "CVE-2021-47274", "CVE-2021-47280");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.10-2022-002");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-kernel-5.10"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'bpftool-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-aarch64-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-x86_64-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.47-39.130.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.47-39.130.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.47-39.130.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'}
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
      severity   : SECURITY_HOLE,
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
