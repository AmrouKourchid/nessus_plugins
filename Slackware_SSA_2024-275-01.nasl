#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-275-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208004);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id("CVE-2024-47176");

  script_name(english:"Slackware Linux 15.0 / current cups-filters  Vulnerability (SSA:2024-275-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to cups-filters.");
  script_set_attribute(attribute:"description", value:
"The version of cups-filters installed on the remote host is prior to 1.28.17 / 2.0.1. It is, therefore, affected by a
vulnerability as referenced in the SSA:2024-275-01 advisory.

  - CUPS is a standards-based, open-source printing system, and `cups-browsed` contains network printing
    functionality including, but not limited to, auto-discovering print services and shared printers. `cups-
    browsed` binds to `INADDR_ANY:631`, causing it to trust any packet from any source, and can cause the
    `Get-Printer-Attributes` IPP request to an attacker controlled URL. Due to the service binding to `*:631 (
    INADDR_ANY )`, multiple bugs in `cups-browsed` can be exploited in sequence to introduce a malicious
    printer to the system. This chain of exploits ultimately enables an attacker to execute arbitrary commands
    remotely on the target machine without authentication when a print job is started. This poses a
    significant security risk over the network. Notably, this vulnerability is particularly concerning as it
    can be exploited from the public internet, potentially exposing a vast number of systems to remote attacks
    if their CUPS services are enabled. (CVE-2024-47176)

  - cups-browsed <= 2.0.1 binds on UDP INADDR_ANY:631 trusting any packet from any source to trigger a Get-
    Printer-Attributes IPP request to an attacker controlled URL. (CVE-2024-47176)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.390689
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a546b7da");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected cups-filters package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47176");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS IPP Attributes LAN Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:cups-browsed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:cups-filters");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '1.28.17', 'product' : 'cups-filters', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '2_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.28.17', 'product' : 'cups-filters', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '2_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.0.1', 'product' : 'cups-browsed', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'i686' },
    { 'fixed_version' : '2.0.1', 'product' : 'cups-browsed', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'x86_64' }
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
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
