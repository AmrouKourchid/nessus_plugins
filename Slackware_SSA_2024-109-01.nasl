#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-109-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193530);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/21");

  script_cve_id("CVE-2024-2961");

  script_name(english:"Slackware Linux 15.0 / current aaa_glibc-solibs  Vulnerability (SSA:2024-109-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to aaa_glibc-solibs.");
  script_set_attribute(attribute:"description", value:
"The version of aaa_glibc-solibs installed on the remote host is prior to 2.33 / 2.39. It is, therefore, affected by a
vulnerability as referenced in the SSA:2024-109-01 advisory.

  - The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to
    it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to
    crash an application or overwrite a neighbouring variable. (CVE-2024-2961)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.548384
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d60ef5db");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected aaa_glibc-solibs package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:aaa_glibc-solibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-profile");
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
    { 'fixed_version' : '2.33', 'product' : 'aaa_glibc-solibs', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '6_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '2.33', 'product' : 'glibc', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '6_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '2.33', 'product' : 'glibc-i18n', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '6_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '2.33', 'product' : 'glibc-profile', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '6_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '2.33', 'product' : 'aaa_glibc-solibs', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '6_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.33', 'product' : 'glibc', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '6_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.33', 'product' : 'glibc-i18n', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '6_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.33', 'product' : 'glibc-profile', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '6_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.39', 'product' : 'aaa_glibc-solibs', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'i586' },
    { 'fixed_version' : '2.39', 'product' : 'glibc', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'i586' },
    { 'fixed_version' : '2.39', 'product' : 'glibc-i18n', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'i586' },
    { 'fixed_version' : '2.39', 'product' : 'glibc-profile', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'i586' },
    { 'fixed_version' : '2.39', 'product' : 'aaa_glibc-solibs', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.39', 'product' : 'glibc', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.39', 'product' : 'glibc-i18n', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'x86_64' },
    { 'fixed_version' : '2.39', 'product' : 'glibc-profile', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '2', 'arch' : 'x86_64' }
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
