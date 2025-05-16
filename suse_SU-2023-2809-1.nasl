#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2809-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(178179);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id(
    "CVE-2020-24588",
    "CVE-2022-2196",
    "CVE-2022-3523",
    "CVE-2022-4269",
    "CVE-2022-4744",
    "CVE-2022-36280",
    "CVE-2022-38096",
    "CVE-2022-45884",
    "CVE-2022-45885",
    "CVE-2022-45886",
    "CVE-2022-45887",
    "CVE-2022-45919",
    "CVE-2023-0045",
    "CVE-2023-0122",
    "CVE-2023-0179",
    "CVE-2023-0386",
    "CVE-2023-0394",
    "CVE-2023-0461",
    "CVE-2023-0469",
    "CVE-2023-0590",
    "CVE-2023-0597",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1077",
    "CVE-2023-1078",
    "CVE-2023-1079",
    "CVE-2023-1095",
    "CVE-2023-1118",
    "CVE-2023-1249",
    "CVE-2023-1382",
    "CVE-2023-1513",
    "CVE-2023-1582",
    "CVE-2023-1583",
    "CVE-2023-1611",
    "CVE-2023-1637",
    "CVE-2023-1652",
    "CVE-2023-1670",
    "CVE-2023-1838",
    "CVE-2023-1855",
    "CVE-2023-1989",
    "CVE-2023-1998",
    "CVE-2023-2002",
    "CVE-2023-2124",
    "CVE-2023-2156",
    "CVE-2023-2162",
    "CVE-2023-2176",
    "CVE-2023-2235",
    "CVE-2023-2269",
    "CVE-2023-2483",
    "CVE-2023-2513",
    "CVE-2023-3006",
    "CVE-2023-3141",
    "CVE-2023-3161",
    "CVE-2023-3220",
    "CVE-2023-3357",
    "CVE-2023-3358",
    "CVE-2023-21102",
    "CVE-2023-21106",
    "CVE-2023-22998",
    "CVE-2023-23000",
    "CVE-2023-23001",
    "CVE-2023-23004",
    "CVE-2023-23006",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-25012",
    "CVE-2023-26545",
    "CVE-2023-28327",
    "CVE-2023-28410",
    "CVE-2023-28464",
    "CVE-2023-28466",
    "CVE-2023-28866",
    "CVE-2023-30456",
    "CVE-2023-30772",
    "CVE-2023-31084",
    "CVE-2023-31436",
    "CVE-2023-32233",
    "CVE-2023-33288",
    "CVE-2023-33951",
    "CVE-2023-33952",
    "CVE-2023-35788",
    "CVE-2023-35823",
    "CVE-2023-35828",
    "CVE-2023-35829"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2809-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:2809-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:2809-1 advisory.

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated.
    Against devices that support receiving non-SSP A-MSDU frames (which is mandatory as part of 802.11n), an
    adversary can abuse this to inject arbitrary network packets. (CVE-2020-24588)

  - A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks.
    L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after
    running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can
    execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past
    commit 2e7eab81425a (CVE-2022-2196)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is an unknown
    function of the file mm/memory.c of the component Driver Handler. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211020. (CVE-2022-3523)

  - An out-of-bounds(OOB) memory access vulnerability was found in vmwgfx driver in
    drivers/gpu/vmxgfx/vmxgfx_kms.c in GPU component in the Linux kernel with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-36280)

  - A NULL pointer dereference vulnerability was found in vmwgfx driver in drivers/gpu/vmxgfx/vmxgfx_execbuf.c
    in GPU component of Linux kernel with device file '/dev/dri/renderD128 (or Dxxx)'. This flaw allows a
    local attacker with a user account on the system to gain privilege, causing a denial of service(DoS).
    (CVE-2022-38096)

  - A flaw was found in the Linux kernel Traffic Control (TC) subsystem. Using a specific networking
    configuration (redirecting egress packets to ingress using TC action mirred) a local unprivileged user
    could trigger a CPU soft lockup (ABBA deadlock) when the transport protocol in use (TCP or SCTP) does a
    retransmission, resulting in a denial of service condition. (CVE-2022-4269)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvbdev.c has a use-
    after-free, related to dvb_register_device dynamically allocating fops. (CVE-2022-45884)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_frontend.c has a
    race condition that can cause a use-after-free when a device is disconnected. (CVE-2022-45885)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_net.c has a
    .disconnect versus dvb_device_open race condition that leads to a use-after-free. (CVE-2022-45886)

  - An issue was discovered in the Linux kernel through 6.0.9. drivers/media/usb/ttusb-dec/ttusb_dec.c has a
    memory leak because of the lack of a dvb_frontend_detach call. (CVE-2022-45887)

  - An issue was discovered in the Linux kernel through 6.0.10. In drivers/media/dvb-core/dvb_ca_en50221.c, a
    use-after-free can occur is there is a disconnect after an open, because of the lack of a wait_event.
    (CVE-2022-45919)

  - A double-free flaw was found in the Linux kernel's TUN/TAP device driver functionality in how a user
    registers the device when the register_netdevice function fails (NETDEV_REGISTER notifier). This flaw
    allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-4744)

  - The current implementation of the prctl syscall does not issue an IBPB immediately during the syscall. The
    ib_prctl_set function updates the Thread Information Flags (TIFs) for the task and updates the SPEC_CTRL
    MSR on the function __speculation_ctrl_update, but the IBPB is only issued on the next schedule, when the
    TIF bits are checked. This leaves the victim vulnerable to values already injected on the BTB, prior to
    the prctl syscall. The patch that added the support for the conditional mitigation via prctl
    (ib_prctl_set) dates back to the kernel 4.9.176. We recommend upgrading past commit
    a664ec9158eeddd75121d39c9a0758016097fa96 (CVE-2023-0045)

  - A NULL pointer dereference vulnerability in the Linux kernel NVMe functionality, in nvmet_setup_auth(),
    allows an attacker to perform a Pre-Auth Denial of Service (DoS) attack on a remote machine. Affected
    versions v6.0-rc1 to v6.0-rc3, fixed in v6.0-rc4. (CVE-2023-0122)

  - A buffer overflow vulnerability was found in the Netfilter subsystem in the Linux Kernel. This issue could
    allow the leakage of both stack and heap addresses, and potentially allow Local Privilege Escalation to
    the root user via arbitrary code execution. (CVE-2023-0179)

  - A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with
    capabilities was found in the Linux kernel's OverlayFS subsystem in how a user copies a capable file from
    a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges
    on the system. (CVE-2023-0386)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - A use-after-free flaw was found in io_uring/filetable.c in io_install_fixed_file in the io_uring
    subcomponent in the Linux Kernel during call cleanup. This flaw may lead to a denial of service.
    (CVE-2023-0469)

  - A use-after-free flaw was found in qdisc_graft in net/sched/sch_api.c in the Linux Kernel due to a race
    problem. This flaw leads to a denial of service issue. If patch ebda44da44f6 (net: sched: fix race
    condition in qdisc_graft()) not applied yet, then kernel could be affected. (CVE-2023-0590)

  - A flaw possibility of memory leak in the Linux kernel cpu_entry_area mapping of X86 CPU data to memory was
    found in the way user can guess location of exception stack(s) or other important data. A local user could
    use this flaw to get access to some important data with expected location in memory. (CVE-2023-0597)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

  - A flaw was found in the Linux Kernel. The tun/tap sockets have their socket UID hardcoded to 0 due to a
    type confusion in their initialization function. While it will be often correct, as tuntap devices require
    CAP_NET_ADMIN, it may not always be the case, e.g., a non-root user only having that capability. This
    would make tun/tap sockets being incorrectly treated in filtering/routing decisions, possibly bypassing
    network filters. (CVE-2023-1076)

  - In the Linux kernel, pick_next_rt_entity() may return a type confused entry, not detected by the BUG_ON
    condition, as the confused entry will not be NULL, but list_head.The buggy error condition would lead to a
    type confused entry with the list head,which would then be used as a type confused sched_rt_entity,causing
    memory corruption. (CVE-2023-1077)

  - A flaw was found in the Linux Kernel in RDS (Reliable Datagram Sockets) protocol. The
    rds_rm_zerocopy_callback() uses list_entry() on the head of a list causing a type confusion. Local user
    can trigger this with rds_message_put(). Type confusion leads to `struct rds_msg_zcopy_info *info`
    actually points to something else that is potentially controlled by local user. It is known how to trigger
    this, which causes an out of bounds access, and a lock corruption. (CVE-2023-1078)

  - A flaw was found in the Linux kernel. A use-after-free may be triggered in asus_kbd_backlight_set when
    plugging/disconnecting in a malicious USB device, which advertises itself as an Asus device. Similarly to
    the previous known CVE-2023-25012, but in asus devices, the work_struct may be scheduled by the LED
    controller while the device is disconnecting, triggering a use-after-free on the struct asus_kbd_leds *led
    structure. A malicious USB device may exploit the issue to cause memory corruption with controlled data.
    (CVE-2023-1079)

  - In nf_tables_updtable, if nf_tables_table_enable returns an error, nft_trans_destroy is called to free the
    transaction object. nft_trans_destroy() calls list_del(), but the transaction was never placed on a list
    -- the list head is all zeroes, this results in a NULL pointer dereference. (CVE-2023-1095)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - A use-after-free flaw was found in the Linux kernel's core dump subsystem. This flaw allows a local user
    to crash the system. Only if patch 390031c94211 (coredump: Use the vma snapshot in fill_files_note) not
    applied yet, then kernel could be affected. (CVE-2023-1249)

  - A data race flaw was found in the Linux kernel, between where con is allocated and con->sock is set. This
    issue leads to a NULL pointer dereference when accessing con->sock->sk in net/tipc/topsrv.c in the tipc
    protocol in the Linux kernel. (CVE-2023-1382)

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

  - A race problem was found in fs/proc/task_mmu.c in the memory management sub-component in the Linux kernel.
    This issue may allow a local attacker with user privilege to cause a denial of service. (CVE-2023-1582)

  - A NULL pointer dereference was found in io_file_bitmap_get in io_uring/filetable.c in the io_uring sub-
    component in the Linux Kernel. When fixed files are unregistered, some context information
    (file_alloc_{start,end} and alloc_hint) is not cleared. A subsequent request that has auto index selection
    enabled via IORING_FILE_INDEX_ALLOC can cause a NULL pointer dereference. An unprivileged user can use the
    flaw to cause a system crash. (CVE-2023-1583)

  - A use-after-free flaw was found in btrfs_search_slot in fs/btrfs/ctree.c in btrfs in the Linux Kernel.This
    flaw allows an attacker to crash the system and possibly cause a kernel information lea (CVE-2023-1611)

  - A flaw that boot CPU could be vulnerable for the speculative execution behavior kind of attacks in the
    Linux kernel X86 CPU Power management options functionality was found in the way user resuming CPU from
    suspend-to-RAM. A local user could use this flaw to potentially get unauthorized access to some memory of
    the CPU similar to the speculative execution behavior kind of attacks. (CVE-2023-1637)

  - A use-after-free flaw was found in nfsd4_ssc_setup_dul in fs/nfsd/nfs4proc.c in the NFS filesystem in the
    Linux Kernel. This issue could allow a local attacker to crash the system or it may lead to a kernel
    information leak problem. (CVE-2023-1652)

  - A flaw use after free in the Linux kernel Xircom 16-bit PCMCIA (PC-card) Ethernet driver was found.A local
    user could use this flaw to crash the system or potentially escalate their privileges on the system.
    (CVE-2023-1670)

  - A use-after-free flaw was found in vhost_net_set_backend in drivers/vhost/net.c in virtio network
    subcomponent in the Linux kernel due to a double fget. This flaw could allow a local attacker to crash the
    system, and could even lead to a kernel information leak problem. (CVE-2023-1838)

  - A use-after-free flaw was found in xgene_hwmon_remove in drivers/hwmon/xgene-hwmon.c in the Hardware
    Monitoring Linux Kernel Driver (xgene-hwmon). This flaw could allow a local attacker to crash the system
    due to a race problem. This vulnerability could even lead to a kernel information leak problem.
    (CVE-2023-1855)

  - A use-after-free flaw was found in btsdio_remove in drivers\bluetooth\btsdio.c in the Linux Kernel. In
    this flaw, a call to btsdio_remove with an unfinished job, may cause a race problem leading to a UAF on
    hdev devices. (CVE-2023-1989)

  - The Linux kernel allows userspace processes to enable mitigations by calling prctl with
    PR_SET_SPECULATION_CTRL which disables the speculation feature as well as by using seccomp. We had noticed
    that on VMs of at least one major cloud provider, the kernel still left the victim process exposed to
    attacks in some cases even after enabling the spectre-BTI mitigation with prctl. The same behavior can be
    observed on a bare-metal machine when forcing the mitigation to IBRS on boot command line. This happened
    because when plain IBRS was enabled (not enhanced IBRS), the kernel had some logic that determined that
    STIBP was not needed. The IBRS bit implicitly protects against cross-thread branch target injection.
    However, with legacy IBRS, the IBRS bit was cleared on returning to userspace, due to performance reasons,
    which disabled the implicit STIBP and left userspace threads vulnerable to cross-thread branch target
    injection against which STIBP protects. (CVE-2023-1998)

  - A vulnerability was found in the HCI sockets implementation due to a missing capability check in
    net/bluetooth/hci_sock.c in the Linux Kernel. This flaw allows an attacker to unauthorized execution of
    management commands, compromising the confidentiality, integrity, and availability of Bluetooth
    communication. (CVE-2023-2002)

  - In __efi_rt_asm_wrapper of efi-rt-wrapper.S, there is a possible bypass of shadow stack protection due to
    a logic error in the code. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-260821414References: Upstream kernel (CVE-2023-21102)

  - In adreno_set_param of adreno_gpu.c, there is a possible memory corruption due to a double free. This
    could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-265016072References: Upstream kernel (CVE-2023-21106)

  - An out-of-bounds memory access flaw was found in the Linux kernel's XFS file system in how a user restores
    an XFS image after failure (with a dirty log journal). This flaw allows a local user to crash or
    potentially escalate their privileges on the system. (CVE-2023-2124)

  - A flaw was found in the networking subsystem of the Linux kernel within the handling of the RPL protocol.
    This issue results from the lack of proper handling of user-supplied data, which can lead to an assertion
    failure. This may allow an unauthenticated remote attacker to create a denial of service condition on the
    system. (CVE-2023-2156)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - A vulnerability was found in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA in the Linux
    Kernel. The improper cleanup results in out-of-boundary read, where a local user can utilize this problem
    to crash the system or escalation of privilege. (CVE-2023-2176)

  - A use-after-free vulnerability in the Linux Kernel Performance Events system can be exploited to achieve
    local privilege escalation. The perf_group_detach function did not check the event's siblings'
    attach_state before calling add_event_to_groups(), but remove_on_exec made it possible to call
    list_del_event() on before detaching from their group, making it possible to use a dangling pointer
    causing a use-after-free vulnerability. We recommend upgrading past commit
    fd0815f632c24878e325821943edccc7fde947a2. (CVE-2023-2235)

  - A denial of service problem was found, due to a possible recursive locking scenario, resulting in a
    deadlock in table_clear in drivers/md/dm-ioctl.c in the Linux Kernel Device Mapper-Multipathing sub-
    component. (CVE-2023-2269)

  - In the Linux kernel before 6.0.3, drivers/gpu/drm/virtio/virtgpu_object.c misinterprets the
    drm_gem_shmem_get_sg_table return value (expects it to be NULL in the error case, whereas it is actually
    an error pointer). (CVE-2023-22998)

  - In the Linux kernel before 5.17, drivers/phy/tegra/xusb.c mishandles the tegra_xusb_find_port_node return
    value. Callers expect NULL in the error case, but an error pointer is used. (CVE-2023-23000)

  - In the Linux kernel before 5.16.3, drivers/scsi/ufs/ufs-mediatek.c misinterprets the regulator_get return
    value (expects it to be NULL in the error case, whereas it is actually an error pointer). (CVE-2023-23001)

  - In the Linux kernel before 5.19, drivers/gpu/drm/arm/malidp_planes.c misinterprets the get_sg_table return
    value (expects it to be NULL in the error case, whereas it is actually an error pointer). (CVE-2023-23004)

  - In the Linux kernel before 5.15.13, drivers/net/ethernet/mellanox/mlx5/core/steering/dr_domain.c
    misinterprets the mlx5_get_uars_page return value (expects it to be NULL in the error case, whereas it is
    actually an error pointer). (CVE-2023-23006)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

  - The Linux kernel through 6.1.9 has a Use-After-Free in bigben_remove in drivers/hid/hid-bigbenff.c via a
    crafted USB device because the LED controllers remain registered for too long. (CVE-2023-25012)

  - A use-after-free vulnerability was found in the Linux kernel's ext4 filesystem in the way it handled the
    extra inode size for extended attributes. This flaw could allow a privileged local user to cause a system
    crash or other undefined behaviors. (CVE-2023-2513)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - A NULL pointer dereference flaw was found in the UNIX protocol in net/unix/diag.c In unix_diag_get_exact
    in the Linux Kernel. The newly allocated skb does not have sk, leading to a NULL pointer. This flaw allows
    a local user to crash or potentially cause a denial of service. (CVE-2023-28327)

  - Improper restriction of operations within the bounds of a memory buffer in some Intel(R) i915 Graphics
    drivers for linux before kernel version 6.2.10 may allow an authenticated user to potentially enable
    escalation of privilege via local access. (CVE-2023-28410)

  - hci_conn_cleanup in net/bluetooth/hci_conn.c in the Linux kernel through 6.2.9 has a use-after-free
    (observed in hci_conn_hash_flush) because of calls to hci_dev_put and hci_conn_put. There is a double free
    that may lead to privilege escalation. (CVE-2023-28464)

  - do_tls_getsockopt in net/tls/tls_main.c in the Linux kernel through 6.2.6 lacks a lock_sock call, leading
    to a race condition (with a resultant use-after-free or NULL pointer dereference). (CVE-2023-28466)

  - In the Linux kernel through 6.2.8, net/bluetooth/hci_sync.c allows out-of-bounds access because
    amp_init1[] and amp_init2[] are supposed to have an intentionally invalid element, but do not.
    (CVE-2023-28866)

  - A known cache speculation vulnerability, known as Branch History Injection (BHI) or Spectre-BHB, becomes
    actual again for the new hw AmpereOne. Spectre-BHB is similar to Spectre v2, except that malicious code
    uses the shared branch history (stored in the CPU Branch History Buffer, or BHB) to influence mispredicted
    branches within the victim's hardware context. Once that occurs, speculation caused by the mispredicted
    branches can cause cache allocation. This issue leads to obtaining information that should not be
    accessible. (CVE-2023-3006)

  - An issue was discovered in arch/x86/kvm/vmx/nested.c in the Linux kernel before 6.2.8. nVMX on x86_64
    lacks consistency checks for CR0 and CR4. (CVE-2023-30456)

  - The Linux kernel before 6.2.9 has a race condition and resultant use-after-free in
    drivers/power/supply/da9150-charger.c if a physically proximate attacker unplugs a device.
    (CVE-2023-30772)

  - An issue was discovered in drivers/media/dvb-core/dvb_frontend.c in the Linux kernel 6.2. There is a
    blocking operation when a task is in !TASK_RUNNING. In dvb_frontend_get_event, wait_event_interruptible is
    called; the condition is dvb_frontend_test_event(fepriv,events). In dvb_frontend_test_event,
    down(&fepriv->sem) is called. However, wait_event_interruptible would put the process to sleep, and
    down(&fepriv->sem) may block the process. (CVE-2023-31084)

  - A use-after-free flaw was found in r592_remove in drivers/memstick/host/r592.c in media access in the
    Linux Kernel. This flaw allows a local attacker to crash the system at device disconnect, possibly leading
    to a kernel information leak. (CVE-2023-3141)

  - qfq_change_class in net/sched/sch_qfq.c in the Linux kernel before 6.2.13 allows an out-of-bounds write
    because lmax can exceed QFQ_MIN_LMAX. (CVE-2023-31436)

  - A flaw was found in the Framebuffer Console (fbcon) in the Linux Kernel. When providing font->width and
    font->height greater than 32 to fbcon_set_font, since there are no checks in place, a shift-out-of-bounds
    occurs leading to undefined behavior and possible denial of service. (CVE-2023-3161)

  - An issue was discovered in the Linux kernel through 6.1-rc8. dpu_crtc_atomic_check in
    drivers/gpu/drm/msm/disp/dpu1/dpu_crtc.c lacks check of the return value of kzalloc() and will cause the
    NULL Pointer Dereference. (CVE-2023-3220)

  - In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests
    can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users
    can obtain root privileges. This occurs because anonymous sets are mishandled. (CVE-2023-32233)

  - An issue was discovered in the Linux kernel before 6.2.9. A use-after-free was found in bq24190_remove in
    drivers/power/supply/bq24190_charger.c. It could allow a local attacker to crash the system due to a race
    condition. (CVE-2023-33288)

  - A NULL pointer dereference flaw was found in the Linux kernel AMD Sensor Fusion Hub driver. This flaw
    allows a local user to crash the system. (CVE-2023-3357)

  - A null pointer dereference was found in the Linux kernel's Integrated Sensor Hub (ISH) driver. This issue
    could allow a local user to crash the system. (CVE-2023-3358)

  - An issue was discovered in fl_set_geneve_opt in net/sched/cls_flower.c in the Linux kernel before 6.3.7.
    It allows an out-of-bounds write in the flower classifier code via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets.
    This may result in denial of service or privilege escalation. (CVE-2023-35788)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in saa7134_finidev in
    drivers/media/pci/saa7134/saa7134-core.c. (CVE-2023-35823)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in
    renesas_usb3_remove in drivers/usb/gadget/udc/renesas_usb3.c. (CVE-2023-35828)

  - An issue was discovered in the Linux kernel before 6.3.2. A use-after-free was found in rkvdec_remove in
    drivers/staging/media/rkvdec/rkvdec.c. (CVE-2023-35829)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212741");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-July/030270.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0122");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0386");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0461");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21102");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23455");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-26545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28466");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30456");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3220");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-33288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3357");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-33951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-33952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35829");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24588");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation via CVE-2023-0386');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_13_5-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-rt-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-rt-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-rt-5.14.21-150500.13.5.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-devel-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-extra-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-livepatch-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-livepatch-devel-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-optional-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-vdso-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-devel-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-livepatch-devel-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-vdso-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-rt-5.14.21-150500.13.5.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-rt-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-rt-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-rt-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-rt-5.14.21-150500.13.5.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-livepatch-5_14_21-150500_13_5-rt-1-150500.11.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']}
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
      severity   : SECURITY_NOTE,
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
