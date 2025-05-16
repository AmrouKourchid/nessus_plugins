#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-6583.
##

include('compat.inc');

if (description)
{
  script_id(185819);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2022-3523",
    "CVE-2022-3565",
    "CVE-2022-3594",
    "CVE-2022-38457",
    "CVE-2022-40133",
    "CVE-2022-40982",
    "CVE-2022-42895",
    "CVE-2023-0597",
    "CVE-2023-1073",
    "CVE-2023-1074",
    "CVE-2023-1075",
    "CVE-2023-1076",
    "CVE-2023-1079",
    "CVE-2023-1206",
    "CVE-2023-1249",
    "CVE-2023-1252",
    "CVE-2023-1652",
    "CVE-2023-1855",
    "CVE-2023-1989",
    "CVE-2023-3141",
    "CVE-2023-3161",
    "CVE-2023-3212",
    "CVE-2023-3268",
    "CVE-2023-3358",
    "CVE-2023-3609",
    "CVE-2023-3772",
    "CVE-2023-3773",
    "CVE-2023-4128",
    "CVE-2023-4155",
    "CVE-2023-4194",
    "CVE-2023-4206",
    "CVE-2023-4207",
    "CVE-2023-4208",
    "CVE-2023-4273",
    "CVE-2023-26545",
    "CVE-2023-30456",
    "CVE-2023-33203",
    "CVE-2023-33951",
    "CVE-2023-33952",
    "CVE-2023-39191"
  );

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2023-6583)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-6583 advisory.

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - A flaw was found in the Linux kernel's TUN/TAP functionality. This issue could allow a local user to
    bypass network filters and gain unauthorized access to some resources. The original patches fixing
    CVE-2023-1076 are incorrect or incomplete. The problem is that the following upstream commits -
    a096ccca6e50 (tun: tun_chr_open(): correctly initialize socket uid), - 66b2c338adce (tap: tap_open():
    correctly initialize socket uid), pass inode->i_uid to sock_init_data_uid() as the last parameter and
    that turns out to not be accurate. (CVE-2023-4194)

  - A use-after-free flaw was found in r592_remove in drivers/memstick/host/r592.c in media access in the
    Linux Kernel. This flaw allows a local attacker to crash the system at device disconnect, possibly leading
    to a kernel information leak. (CVE-2023-3141)

  - In the Linux kernel before 6.1.13, there is a double free in net/mpls/af_mpls.c upon an allocation failure
    (for registering the sysctl table under a new location) during the renaming of a device. (CVE-2023-26545)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

  - A use-after-free(UAF) vulnerability was found in function 'vmw_cmd_res_check' in
    drivers/gpu/vmxgfx/vmxgfx_execbuf.c in Linux kernel's vmwgfx driver with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-38457)

  - There is an infoleak vulnerability in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_parse_conf_req
    function which can be used to leak kernel pointers remotely. We recommend upgrading past commit
    https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e
    https://www.google.com/url (CVE-2022-42895)

  - A flaw was found in the Framebuffer Console (fbcon) in the Linux Kernel. When providing font->width and
    font->height greater than 32 to fbcon_set_font, since there are no checks in place, a shift-out-of-bounds
    occurs leading to undefined behavior and possible denial of service. (CVE-2023-3161)

  - A null pointer dereference was found in the Linux kernel's Integrated Sensor Hub (ISH) driver. This issue
    could allow a local user to crash the system. (CVE-2023-3358)

  - A use-after-free(UAF) vulnerability was found in function 'vmw_execbuf_tie_context' in
    drivers/gpu/vmxgfx/vmxgfx_execbuf.c in Linux kernel's vmwgfx driver with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-40133)

  - A memory leak flaw was found in the Linux kernel's Stream Control Transmission Protocol. This issue may
    occur when a user starts a malicious networking service and someone connects to this service. This could
    allow a local user to starve resources, causing a denial of service. (CVE-2023-1074)

  - A flaw was found in the Linux Kernel. The tun/tap sockets have their socket UID hardcoded to 0 due to a
    type confusion in their initialization function. While it will be often correct, as tuntap devices require
    CAP_NET_ADMIN, it may not always be the case, e.g., a non-root user only having that capability. This
    would make tun/tap sockets being incorrectly treated in filtering/routing decisions, possibly bypassing
    network filters. (CVE-2023-1076)

  - An issue was discovered in arch/x86/kvm/vmx/nested.c in the Linux kernel before 6.2.8. nVMX on x86_64
    lacks consistency checks for CR0 and CR4. (CVE-2023-30456)

  - A flaw possibility of memory leak in the Linux kernel cpu_entry_area mapping of X86 CPU data to memory was
    found in the way user can guess location of exception stack(s) or other important data. A local user could
    use this flaw to get access to some important data with expected location in memory. (CVE-2023-0597)

  - A memory corruption flaw was found in the Linux kernel's human interface device (HID) subsystem in how a
    user inserts a malicious USB device. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2023-1073)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

  - A use-after-free flaw was found in the Linux kernel's core dump subsystem. This flaw allows a local user
    to crash the system. Only if patch 390031c94211 (coredump: Use the vma snapshot in fill_files_note) not
    applied yet, then kernel could be affected. (CVE-2023-1249)

  - A use-after-free flaw was found in btsdio_remove in drivers\bluetooth\btsdio.c in the Linux Kernel. In
    this flaw, a call to btsdio_remove with an unfinished job, may cause a race problem leading to a UAF on
    hdev devices. (CVE-2023-1989)

  - A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is an unknown
    function of the file mm/memory.c of the component Driver Handler. The manipulation leads to use after
    free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue.
    The identifier of this vulnerability is VDB-211020. (CVE-2022-3523)

  - A hash collision flaw was found in the IPv6 connection lookup table in the Linux kernel's IPv6
    functionality when a user makes a new kind of SYN flood attack. A user located in the local network or
    with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up
    to 95%. (CVE-2023-1206)

  - A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue
    may allow a malicious user with CAP_NET_ADMIN privileges to cause a 4 byte out-of-bounds read of
    XFRMA_MTIMER_THRESH when parsing netlink attributes, leading to potential leakage of sensitive heap data
    to userspace. (CVE-2023-3773)

  - A flaw was found in KVM AMD Secure Encrypted Virtualization (SEV) in the Linux kernel. A KVM guest using
    SEV-ES or SEV-SNP with multiple vCPUs can trigger a double fetch race condition vulnerability and invoke
    the `VMGEXIT` handler recursively. If an attacker manages to call the handler multiple times, they can
    trigger a stack overflow and cause a denial of service or potentially guest-to-host escape in kernel
    configurations without stack guard pages (`CONFIG_VMAP_STACK`). (CVE-2023-4155)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_fw component can be exploited to
    achieve local privilege escalation. When fw_change() is called on an existing filter, the whole tcf_result
    struct is always copied into the new instance of the filter. This causes a problem when updating a filter
    bound to a class, as tcf_unbind_filter() is always called on the old instance in the success path,
    decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading to a use-after-
    free. We recommend upgrading past commit 76e42ae831991c828cffa8c37736ebfb831ad5ec. (CVE-2023-4207)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to
    achieve local privilege escalation. When u32_change() is called on an existing filter, the whole
    tcf_result struct is always copied into the new instance of the filter. This causes a problem when
    updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the
    success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading
    to a use-after-free. We recommend upgrading past commit 3044b16e7c6fe5d24b1cdbcf1bd0a9d92d1ebd81.
    (CVE-2023-4208)

  - A flaw was found in the exFAT driver of the Linux kernel. The vulnerability exists in the implementation
    of the file name reconstruction function, which is responsible for reading file name entries from a
    directory index and merging file name parts belonging to one file into a single long file name. Since the
    file name characters are copied into a stack variable, a local privileged attacker could use this flaw to
    overflow the kernel stack. (CVE-2023-4273)

  - A use-after-free flaw was found in xgene_hwmon_remove in drivers/hwmon/xgene-hwmon.c in the Hardware
    Monitoring Linux Kernel Driver (xgene-hwmon). This flaw could allow a local attacker to crash the system
    due to a race problem. This vulnerability could even lead to a kernel information leak problem.
    (CVE-2023-1855)

  - A NULL pointer dereference issue was found in the gfs2 file system in the Linux kernel. It occurs on
    corrupt gfs2 file systems when the evict code tries to reference the journal descriptor structure after it
    has been freed and set to NULL. A privileged local user could use this flaw to cause a kernel panic.
    (CVE-2023-3212)

  - The Linux kernel before 6.2.9 has a race condition and resultant use-after-free in
    drivers/net/ethernet/qualcomm/emac/emac.c if a physically proximate attacker unplugs an emac based device.
    (CVE-2023-33203)

  - A double-free vulnerability was found in the vmwgfx driver in the Linux kernel. The flaw exists within the
    handling of vmw_buffer_object objects. The issue results from the lack of validating the existence of an
    object prior to performing further free operations on the object. This flaw allows a local privileged user
    to escalate privileges and execute code in the context of the kernel. (CVE-2023-33952)

  - Information exposure through microarchitectural state after transient execution in certain vector
    execution units for some Intel(R) Processors may allow an authenticated user to potentially enable
    information disclosure via local access. (CVE-2022-40982)

  - An out of bounds (OOB) memory access flaw was found in the Linux kernel in relay_file_read_start_pos in
    kernel/relay.c in the relayfs. This flaw could allow a local attacker to crash the system or leak kernel
    internal information. (CVE-2023-3268)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to
    achieve local privilege escalation. If tcf_change_indev() fails, u32_set_parms() will immediately return
    an error after incrementing or decrementing the reference counter in tcf_bind_filter(). If an attacker can
    control the reference counter and set it to zero, they can cause the reference to be freed, leading to a
    use-after-free vulnerability. We recommend upgrading past commit 04c55383fa5689357bcdd2c8036725a55ed632bc.
    (CVE-2023-3609)

  - A use-after-free flaw was found in the Linux kernel's Ext4 File System in how a user triggers several file
    operations simultaneously with the overlay FS usage. This flaw allows a local user to crash or potentially
    escalate their privileges on the system. Only if patch 9a2544037600 (ovl: fix use after free in struct
    ovl_aio_req) not applied yet, the kernel could be affected. (CVE-2023-1252)

  - A use-after-free flaw was found in nfsd4_ssc_setup_dul in fs/nfsd/nfs4proc.c in the NFS filesystem in the
    Linux Kernel. This issue could allow a local attacker to crash the system or it may lead to a kernel
    information leak problem. (CVE-2023-1652)

  - A race condition vulnerability was found in the vmwgfx driver in the Linux kernel. The flaw exists within
    the handling of GEM objects. The issue results from improper locking when performing operations on an
    object. This flaw allows a local privileged user to disclose information in the context of the kernel.
    (CVE-2023-33951)

  - A flaw was found in the Linux kernel. A use-after-free may be triggered in asus_kbd_backlight_set when
    plugging/disconnecting in a malicious USB device, which advertises itself as an Asus device. Similarly to
    the previous known CVE-2023-25012, but in asus devices, the work_struct may be scheduled by the LED
    controller while the device is disconnecting, triggering a use-after-free on the struct asus_kbd_leds *led
    structure. A malicious USB device may exploit the issue to cause memory corruption with controlled data.
    (CVE-2023-1079)

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_route component can be exploited to
    achieve local privilege escalation. When route4_change() is called on an existing filter, the whole
    tcf_result struct is always copied into the new instance of the filter. This causes a problem when
    updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the
    success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading
    to a use-after-free. We recommend upgrading past commit b80b829e9e2c1b3f7aae34855e04d8f6ecaf13c8.
    (CVE-2023-4206)

  - An improper input validation flaw was found in the eBPF subsystem in the Linux kernel. The issue occurs
    due to a lack of proper validation of dynamic pointers within user-supplied eBPF programs prior to
    executing them. This may allow an attacker with CAP_BPF privileges to escalate privileges and execute
    arbitrary code in the context of the kernel. (CVE-2023-39191)

  - A flaw was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem). This issue
    may allow a malicious user with CAP_NET_ADMIN privileges to directly dereference a NULL pointer in
    xfrm_update_ae_params(), leading to a possible kernel crash and denial of service. (CVE-2023-3772)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-6583.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1079");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-39191");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:3:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:3:baseos_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rv");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-362.8.1.el9_3'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2023-6583');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-7.2.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-devel-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'libperf-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-362.8.1.el9_3', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.2.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-devel-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'libperf-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-362.8.1.el9_3', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
