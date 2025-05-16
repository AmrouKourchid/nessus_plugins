#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-135-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197033);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id(
    "CVE-2024-4367",
    "CVE-2024-4767",
    "CVE-2024-4768",
    "CVE-2024-4769",
    "CVE-2024-4770",
    "CVE-2024-4777"
  );

  script_name(english:"Slackware Linux 15.0 / current mozilla-firefox  Multiple Vulnerabilities (SSA:2024-135-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-firefox.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-firefox installed on the remote host is prior to 115.11.0esr / 126.0. It is, therefore, affected
by multiple vulnerabilities as referenced in the SSA:2024-135-01 advisory.

  - A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution
    in the PDF.js context. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird <
    115.11. (CVE-2024-4367)

  - If the `browser.privatebrowsing.autostart` preference is enabled, IndexedDB files were not properly
    deleted when the window was closed. This preference is disabled by default in Firefox. This vulnerability
    affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11. (CVE-2024-4767)

  - A bug in popup notifications' interaction with WebAuthn made it easier for an attacker to trick a user
    into granting permissions. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird
    < 115.11. (CVE-2024-4768)

  - When importing resources using Web Workers, error messages would distinguish the difference between
    `application/javascript` responses and non-script responses. This could have been abused to learn
    information cross-origin. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird
    < 115.11. (CVE-2024-4769)

  - When saving a page to PDF, certain font styles could have led to a potential use-after-free crash. This
    vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11. (CVE-2024-4770)

  - Memory safety bugs present in Firefox 125, Firefox ESR 115.10, and Thunderbird 115.10. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and
    Thunderbird < 115.11. (CVE-2024-4777)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.383523
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d42a7de4");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4777");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '115.11.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '115.11.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '126.0', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '126.0', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
