#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-051-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190811);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-1546",
    "CVE-2024-1547",
    "CVE-2024-1548",
    "CVE-2024-1549",
    "CVE-2024-1550",
    "CVE-2024-1551",
    "CVE-2024-1552",
    "CVE-2024-1553"
  );
  script_xref(name:"IAVA", value:"2024-A-0108-S");

  script_name(english:"Slackware Linux 15.0 / current mozilla-firefox  Multiple Vulnerabilities (SSA:2024-051-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-firefox.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-firefox installed on the remote host is prior to 115.8.0esr. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA:2024-051-01 advisory.

  - When storing and re-accessing data on a networking channel, the length of buffers may have been confused,
    resulting in an out-of-bounds memory read. This vulnerability affects Firefox < 123, Firefox ESR < 115.8,
    and Thunderbird < 115.8. (CVE-2024-1546)

  - Through a series of API calls and redirects, an attacker-controlled alert dialog could have been displayed
    on another website (with the victim website's URL shown). This vulnerability affects Firefox < 123,
    Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1547)

  - A website could have obscured the fullscreen notification by using a dropdown select input element. This
    could have led to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 123,
    Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1548)

  - If a website set a large custom cursor, portions of the cursor could have overlapped with the permission
    dialog, potentially resulting in user confusion and unexpected granted permissions. This vulnerability
    affects Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1549)

  - A malicious website could have used a combination of exiting fullscreen mode and `requestPointerLock` to
    cause the user's mouse to be re-positioned unexpectedly, which could have led to user confusion and
    inadvertently granting permissions they did not intend to grant. This vulnerability affects Firefox < 123,
    Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1550)

  - Set-Cookie response headers were being incorrectly honored in multipart HTTP responses. If an attacker
    could control the Content-Type response header, as well as control part of the response body, they could
    inject Set-Cookie response headers that would have been honored by the browser. This vulnerability affects
    Firefox < 123, Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1551)

  - Incorrect code generation could have led to unexpected numeric conversions and potential undefined
    behavior.*Note:* This issue only affects 32-bit ARM devices. This vulnerability affects Firefox < 123,
    Firefox ESR < 115.8, and Thunderbird < 115.8. (CVE-2024-1552)

  - Memory safety bugs present in Firefox 122, Firefox ESR 115.7, and Thunderbird 115.7. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 123, Firefox ESR < 115.8, and
    Thunderbird < 115.8. (CVE-2024-1553)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.390001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef221115");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1552");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    { 'fixed_version' : '115.8.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '115.8.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '115.8.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '115.8.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
