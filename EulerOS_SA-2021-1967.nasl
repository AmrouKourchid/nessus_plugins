#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150271);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/27");

  script_cve_id(
    "CVE-2020-27170",
    "CVE-2020-27171",
    "CVE-2020-35519",
    "CVE-2020-36322",
    "CVE-2021-3483",
    "CVE-2021-20292",
    "CVE-2021-23133",
    "CVE-2021-28660",
    "CVE-2021-28688",
    "CVE-2021-28964",
    "CVE-2021-28972",
    "CVE-2021-29154",
    "CVE-2021-29264",
    "CVE-2021-29265",
    "CVE-2021-29647",
    "CVE-2021-29650",
    "CVE-2021-30002"
  );

  script_name(english:"EulerOS Virtualization 2.9.1 : kernel (EulerOS-SA-2021-1967)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - There is a flaw reported in
    drivers/gpu/drm/nouveau/nouveau_sgdma.c in
    nouveau_sgdma_create_ttm in Nouveau DRM subsystem. The
    issue results from the lack of validating the existence
    of an object prior to performing operations on the
    object. An attacker with a local account with a root
    privilege, can leverage this vulnerability to escalate
    privileges and execute code in the context of the
    kernel.(CVE-2021-20292)

  - A flaw memory leak in the Linux kernel webcam device
    functionality was found in the way user calls ioctl
    that triggers video_usercopy function. The highest
    threat from this vulnerability is to system
    availability.(CVE-2021-30002)

  - A flaw was found in the Linux kernel. The usbip driver
    allows attackers to cause a denial of service (GPF)
    because the stub-up sequence has race conditions during
    an update of the local and shared status. The highest
    threat from this vulnerability is to system
    availability.(CVE-2021-29265)

  - A flaw in the Linux kernels implementation of the RPA
    PCI Hotplug driver for power-pc. A user with
    permissions to write to the sysfs settings for this
    driver can trigger a buffer overflow when writing a new
    device name to the driver from userspace, overwriting
    data in the kernel's stack.(CVE-2021-28972)

  - rtw_wx_set_scan in
    drivers/staging/rtl8188eu/os_dep/ioctl_linux.c in the
    Linux kernel through 5.11.6 allows writing beyond the
    end of the ->ssid[] array. NOTE: from the perspective
    of kernel.org releases, CVE IDs are not normally used
    for drivers/staging/* (unfinished work) however, system
    integrators may have situations in which a
    drivers/staging issue is relevant to their own customer
    base.(CVE-2021-28660)

  - A race condition flaw was found in get_old_root in
    fs/btrfs/ctree.c in the Linux kernel in btrfs
    file-system. This flaw allows a local attacker with a
    special user privilege to cause a denial of service due
    to not locking an extent buffer before a cloning
    operation. The highest threat from this vulnerability
    is to system availability.(CVE-2021-28964)

  - A flaw was found in the Linux kernel. This flaw allows
    attackers to obtain sensitive information from kernel
    memory because of a partially uninitialized data
    structure. The highest threat from this vulnerability
    is to confidentiality.(CVE-2021-29647)

  - A flaw was found in the Linux kernel. The Freescale
    Gianfar Ethernet driver allows attackers to cause a
    system crash due to a negative fragment size calculated
    in situations involving an RX queue overrun when jumbo
    packets are used and NAPI is enabled. The highest
    threat from this vulnerability is to data integrity and
    system availability.(CVE-2021-29264)

  - An out-of-bounds (OOB) memory access flaw was found in
    x25_bind in net/x25/af_x25.c in the Linux kernel. A
    bounds check failure allows a local attacker with a
    user account on the system to gain access to
    out-of-bounds memory, leading to a system crash or a
    leak of internal kernel information. The highest threat
    from this vulnerability is to confidentiality,
    integrity, as well as system
    availability.(CVE-2020-35519)

  - A flaw was found in the Linux kernels eBPF verification
    code. By default accessing the eBPF verifier is only
    accessible to privileged users with CAP_SYS_ADMIN. A
    flaw that triggers Integer underflow when restricting
    speculative pointer arithmetic allows unprivileged
    local users to leak the content of kernel memory. The
    highest threat from this vulnerability is to data
    confidentiality.(CVE-2020-27171)

  - A flaw was found in the Linux kernels eBPF verification
    code. By default accessing the eBPF verifier is only
    accessible to privileged users with CAP_SYS_ADMIN. A
    local user with the ability to insert eBPF instructions
    can use the eBPF verifier to abuse a spectre like flaw
    where they can infer all system memory.(CVE-2020-27170)

  - A flaw was found in the Linux kernels eBPF
    implementation. By default, accessing the eBPF verifier
    is only accessible to privileged users with
    CAP_SYS_ADMIN. A local user with the ability to insert
    eBPF instructions can abuse a flaw in eBPF to corrupt
    memory. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system
    availability.(CVE-2021-29154)

  - The fix for XSA-365 includes initialization of pointers
    such that subsequent cleanup code wouldn't use
    uninitialized or stale values. This initialization went
    too far and may under certain conditions also overwrite
    pointers which are in need of cleaning up. The lack of
    cleanup would result in leaking persistent grants. The
    leak in turn would prevent fully cleaning up after a
    respective guest has died, leaving around zombie
    domains. All Linux versions having the fix for XSA-365
    applied are vulnerable. XSA-365 was classified to
    affect versions back to at least 3.11.(CVE-2021-28688)

  - A denial-of-service (DoS) flaw was identified in the
    Linux kernel due to an incorrect memory barrier in
    xt_replace_table in net/netfilter/x_tables.c in the
    netfilter subsystem.(CVE-2021-29650)

  - A flaw was found in the Nosy driver in the Linux
    kernel. This issue allows a device to be inserted twice
    into a doubly-linked list, leading to a use-after-free
    when one of these devices is removed. The highest
    threat from this vulnerability is to confidentiality,
    integrity, as well as system
    availability.(CVE-2021-3483)

  - A use-after-free flaw was found in the Linux kernel's
    SCTP socket functionality that triggers a race
    condition. This flaw allows a local user to escalate
    their privileges on the system. The highest threat from
    this vulnerability is to confidentiality, integrity, as
    well as system availability.(CVE-2021-23133)

  - A denial of service flaw was found in fuse_do_getattr
    in fs/fuse/dir.c in the kernel side of the FUSE
    filesystem in the Linux kernel. A local user could use
    this flaw to crash the system.(CVE-2020-36322)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1967
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd8d5d51");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28660");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-4.19.90-vhulk2103.1.0.h462.eulerosv2r9",
        "kernel-tools-4.19.90-vhulk2103.1.0.h462.eulerosv2r9",
        "kernel-tools-libs-4.19.90-vhulk2103.1.0.h462.eulerosv2r9",
        "perf-4.19.90-vhulk2103.1.0.h462.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
