#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153080);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/01");

  script_cve_id(
    "CVE-2020-14416",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-28374",
    "CVE-2020-36322",
    "CVE-2021-3573",
    "CVE-2021-23134",
    "CVE-2021-31916",
    "CVE-2021-32399",
    "CVE-2021-33033"
  );

  script_name(english:"EulerOS 2.0 SP5 : kernel (EulerOS-SA-2021-2336)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A vulnerability was found in Linux Kernel where
    refcount leak in llcp_sock_bind() causing
    use-after-free which might lead to privilege
    escalations.(CVE-2020-25670)

  - A vulnerability was found in Linux Kernel, where a
    refcount leak in llcp_sock_connect() causing
    use-after-free which might lead to privilege
    escalations.(CVE-2020-25671)

  - In the Linux kernel before 5.4.16, a race condition in
    tty->disc_data handling in the slip and slcan line
    discipline could lead to a use-after-free, aka
    CID-0ace17d56824. This affects drivers/net/slip/slip.c
    and drivers/net/can/slcan.c.(CVE-2020-14416)

  - An issue was discovered in the FUSE filesystem
    implementation in the Linux kernel before 5.10.6, aka
    CID-5d069dbe8aaf. fuse_do_getattr() calls
    make_bad_inode() in inappropriate situations, causing a
    system crash. NOTE: the original fix for this
    vulnerability was incomplete, and its incompleteness is
    tracked as CVE-2021-28950.(CVE-2020-36322)

  - In drivers/target/target_core_xcopy.c in the Linux
    kernel before 5.10.7, insufficient identifier checking
    in the LIO SCSI target code can be used by remote
    attackers to read or write files via directory
    traversal in an XCOPY request, aka CID-2896c93811e3.
    For example, an attack can occur over a network if the
    attacker has access to one iSCSI LUN. The attacker
    gains control over file access because I/O operations
    are proxied via an attacker-selected
    backstore.(CVE-2020-28374)

  - The Linux kernel before 5.11.14 has a use-after-free in
    cipso_v4_genopt in net/ipv4/cipso_ipv4.c because the
    CIPSO and CALIPSO refcounting for the DOI definitions
    is mishandled, aka CID-ad5d07f4a9cd. This leads to
    writing an arbitrary value.(CVE-2021-33033)

  - Use After Free vulnerability in nfc sockets in the
    Linux Kernel before 5.12.4 allows local attackers to
    elevate their privileges. In typical configurations,
    the issue can only be triggered by a privileged local
    user with the CAP_NET_RAW capability.(CVE-2021-23134)

  - An out-of-bounds (OOB) memory write flaw was found in
    list_devices in drivers/md/dm-ioctl.c in the
    Multi-device driver module in the Linux kernel before
    5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access
    to out-of-bounds memory leading to a system crash or a
    leak of internal kernel information. The highest threat
    from this vulnerability is to system
    availability.(CVE-2021-31916)

  - net/bluetooth/hci_request.c in the Linux kernel through
    5.12.2 has a race condition for removal of the HCI
    controller.(CVE-2021-32399)

  - A flaw use-after-free in the Linux kernel HCI subsystem
    was found in the way user detaches bluetooth dongle or
    other way triggers unregister bluetooth device event. A
    local user could use this flaw to crash the system or
    escalate their privileges on the system.(CVE-2021-3573)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2336
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a15ab415");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25671");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-28374");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.5.h591.eulerosv2r7",
        "kernel-devel-3.10.0-862.14.1.5.h591.eulerosv2r7",
        "kernel-headers-3.10.0-862.14.1.5.h591.eulerosv2r7",
        "kernel-tools-3.10.0-862.14.1.5.h591.eulerosv2r7",
        "kernel-tools-libs-3.10.0-862.14.1.5.h591.eulerosv2r7",
        "perf-3.10.0-862.14.1.5.h591.eulerosv2r7",
        "python-perf-3.10.0-862.14.1.5.h591.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
