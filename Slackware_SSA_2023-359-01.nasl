#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-359-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187293);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id("CVE-2023-6121", "CVE-2023-46862");

  script_name(english:"Slackware Linux 15.0 kernel-generic  Multiple Vulnerabilities (SSA:2023-359-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to kernel-generic.");
  script_set_attribute(attribute:"description", value:
"The version of kernel-generic installed on the remote host is prior to 5.15.145 / 5.15.145_smp. It is, therefore,
affected by multiple vulnerabilities as referenced in the SSA:2023-359-01 advisory.

  - An issue was discovered in the Linux kernel through 6.5.9. During a race with SQ thread exit, an
    io_uring/fdinfo.c io_uring_show_fdinfo NULL pointer dereference can occur. (CVE-2023-46862)

  - An out-of-bounds read vulnerability was found in the NVMe-oF/TCP subsystem in the Linux kernel. This issue
    may allow a remote attacker to send a crafted TCP packet, triggering a heap-based buffer overflow that
    results in kmalloc data being printed and potentially leaked to the kernel ring buffer (dmesg).
    (CVE-2023-6121)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.649908
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c00f99ef");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected kernel-generic package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6121");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '5.15.145', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.145', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.145', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '5.15.145_smp', 'product' : 'kernel-generic-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.145_smp', 'product' : 'kernel-huge-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.145_smp', 'product' : 'kernel-modules-smp', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '5.15.145', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.145_smp', 'product' : 'kernel-source', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'noarch' },
    { 'fixed_version' : '5.15.145', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.145_smp', 'product' : 'kernel-headers', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86' },
    { 'fixed_version' : '5.15.145', 'product' : 'kernel-generic', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.145', 'product' : 'kernel-huge', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '5.15.145', 'product' : 'kernel-modules', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach var constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
