#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109619);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2018-1087", "CVE-2018-8897");

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2018-1119)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A statement in the System Programming Guide of the
    Intel 64 and IA-32 Architectures Software Developer's
    Manual (SDM) was mishandled in the development of some
    or all operating-system kernels, resulting in
    unexpected behavior for #DB exceptions that are
    deferred by MOV SS or POP SS, as demonstrated by (for
    example) privilege escalation in Windows, macOS, some
    Xen configurations, or FreeBSD, or a Linux kernel
    crash. The MOV to SS and POP SS instructions inhibit
    interrupts (including NMIs), data breakpoints, and
    single step trap exceptions until the instruction
    boundary following the next instruction (SDM Vol. 3A
    section 6.8.3). (The inhibited data breakpoints are
    those on memory accessed by the MOV to SS or POP to SS
    instruction itself.) Note that debug exceptions are not
    inhibited by the interrupt enable (EFLAGS.IF) system
    flag (SDM Vol. 3A section 2.3). If the instruction
    following the MOV to SS or POP to SS instruction is an
    instruction like SYSCALL, SYSENTER, INT 3, etc. that
    transfers control to the operating system at CPL i1/4oe 3,
    the debug exception is delivered after the transfer to
    CPL i1/4oe 3 is complete. OS kernels may not expect this
    order of events and may therefore experience unexpected
    behavior when it occurs.i1/4^CVE-2018-8897)

  - On x86, MOV SS and POP SS behave strangely if they
    encounter a data breakpoint. If this occurs in a KVM
    guest, KVM incorrectly thinks that a #DB instruction
    was caused by the undocumented ICEBP instruction. This
    results in #DB being delivered to the guest kernel with
    an incorrect RIP on the stack. On most guest kernels,
    this will allow a guest user to DoS the guest kernel or
    even to escalate privilege to that of the guest kernel.
    (CVE-2018-1087)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1119
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?719c09bd");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
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

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.49.1.180",
        "kernel-debuginfo-3.10.0-229.49.1.180",
        "kernel-debuginfo-common-x86_64-3.10.0-229.49.1.180",
        "kernel-devel-3.10.0-229.49.1.180",
        "kernel-headers-3.10.0-229.49.1.180",
        "kernel-tools-3.10.0-229.49.1.180",
        "kernel-tools-libs-3.10.0-229.49.1.180",
        "perf-3.10.0-229.49.1.180",
        "python-perf-3.10.0-229.49.1.180"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
