#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-107-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193370);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_cve_id(
    "CVE-2024-2609",
    "CVE-2024-3302",
    "CVE-2024-3852",
    "CVE-2024-3854",
    "CVE-2024-3857",
    "CVE-2024-3859",
    "CVE-2024-3861",
    "CVE-2024-3863",
    "CVE-2024-3864"
  );

  script_name(english:"Slackware Linux 15.0 / current mozilla-firefox  Multiple Vulnerabilities (SSA:2024-107-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-firefox.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-firefox installed on the remote host is prior to 115.10.0esr. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA:2024-107-01 advisory.

  - The permission prompt input delay could expire while the window is not in focus. This makes it vulnerable
    to clickjacking by malicious websites. This vulnerability affects Firefox < 124 and Firefox ESR < 115.10.
    (CVE-2024-2609)

  - There was no limit to the number of HTTP/2 CONTINUATION frames that would be processed. A server could
    abuse this to create an Out of Memory condition in the browser. This vulnerability affects Firefox < 125
    and Firefox ESR < 115.10. (CVE-2024-3302)

  - GetBoundName could return the wrong version of an object when JIT optimizations were applied. This
    vulnerability affects Firefox < 125 and Firefox ESR < 115.10. (CVE-2024-3852)

  - In some code patterns the JIT incorrectly optimized switch statements and generated code with out-of-
    bounds-reads. This vulnerability affects Firefox < 125 and Firefox ESR < 115.10. (CVE-2024-3854)

  - The JIT created incorrect code for arguments in certain cases. This led to potential use-after-free
    crashes during garbage collection. This vulnerability affects Firefox < 125 and Firefox ESR < 115.10.
    (CVE-2024-3857)

  - On 32-bit versions there were integer-overflows that led to an out-of-bounds-read that potentially could
    be triggered by a malformed OpenType font. This vulnerability affects Firefox < 125 and Firefox ESR <
    115.10. (CVE-2024-3859)

  - If an AlignedBuffer were assigned to itself, the subsequent self-move could result in an incorrect
    reference count and later use-after-free. This vulnerability affects Firefox < 125 and Firefox ESR <
    115.10. (CVE-2024-3861)

  - The executable file warning was not presented when downloading .xrm-ms files. *Note: This issue only
    affected Windows operating systems. Other operating systems are unaffected.* This vulnerability affects
    Firefox < 125 and Firefox ESR < 115.10. (CVE-2024-3863)

  - Memory safety bug present in Firefox 124, Firefox ESR 115.9, and Thunderbird 115.9. This bug showed
    evidence of memory corruption and we presume that with enough effort this could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 125 and Firefox ESR < 115.10. (CVE-2024-3864)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.396540
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e402b002");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3863");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/16");

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
    { 'fixed_version' : '115.10.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '115.10.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '115.10.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '115.10.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
