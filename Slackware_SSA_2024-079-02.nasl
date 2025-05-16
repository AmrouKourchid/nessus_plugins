#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-079-02. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192270);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id(
    "CVE-2023-5388",
    "CVE-2024-0743",
    "CVE-2024-2605",
    "CVE-2024-2607",
    "CVE-2024-2608",
    "CVE-2024-2610",
    "CVE-2024-2611",
    "CVE-2024-2612",
    "CVE-2024-2614",
    "CVE-2024-2616"
  );

  script_name(english:"Slackware Linux 15.0 / current mozilla-firefox  Multiple Vulnerabilities (SSA:2024-079-02)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-firefox.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-firefox installed on the remote host is prior to 115.9.0esr. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA:2024-079-02 advisory.

  - NSS was susceptible to a timing side-channel attack when performing RSA decryption. This attack could
    potentially allow an attacker to recover the private data. This vulnerability affects Firefox < 124,
    Firefox ESR < 115.9, and Thunderbird < 115.9. (CVE-2023-5388)

  - An unchecked return value in TLS handshake code could have caused a potentially exploitable crash. This
    vulnerability affects Firefox < 122, Firefox ESR < 115.9, and Thunderbird < 115.9. (CVE-2024-0743)

  - An attacker could have leveraged the Windows Error Reporter to run arbitrary code on the system escaping
    the sandbox. *Note:* This issue only affected Windows operating systems. Other operating systems are
    unaffected. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird < 115.9.
    (CVE-2024-2605)

  - Return registers were overwritten which could have allowed an attacker to execute arbitrary code. *Note:*
    This issue only affected Armv7-A systems. Other operating systems are unaffected. This vulnerability
    affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird < 115.9. (CVE-2024-2607)

  - `AppendEncodedAttributeValue(), ExtraSpaceNeededForAttrEncoding()` and `AppendEncodedCharacters()` could
    have experienced integer overflows, causing underallocation of an output buffer leading to an out of
    bounds write. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird < 115.9.
    (CVE-2024-2608)

  - Using a markup injection an attacker could have stolen nonce values. This could have been used to bypass
    strict content security policies. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and
    Thunderbird < 115.9. (CVE-2024-2610)

  - A missing delay on when pointer lock was used could have allowed a malicious page to trick a user into
    granting permissions. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and Thunderbird <
    115.9. (CVE-2024-2611)

  - If an attacker could find a way to trigger a particular code path in `SafeRefPtr`, it could have triggered
    a crash or potentially be leveraged to achieve code execution. This vulnerability affects Firefox < 124,
    Firefox ESR < 115.9, and Thunderbird < 115.9. (CVE-2024-2612)

  - Memory safety bugs present in Firefox 123, Firefox ESR 115.8, and Thunderbird 115.8. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 124, Firefox ESR < 115.9, and
    Thunderbird < 115.9. (CVE-2024-2614)

  - To harden ICU against exploitation, the behavior for out-of-memory conditions was changed to crash instead
    of attempt to continue. This vulnerability affects Firefox ESR < 115.9 and Thunderbird < 115.9.
    (CVE-2024-2616)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.400247
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e59785fb");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2614");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/19");

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
    { 'fixed_version' : '115.9.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '115.9.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '115.9.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '115.9.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
