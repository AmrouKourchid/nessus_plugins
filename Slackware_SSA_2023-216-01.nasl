#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-216-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179369);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/04");

  script_cve_id(
    "CVE-2023-4045",
    "CVE-2023-4046",
    "CVE-2023-4047",
    "CVE-2023-4048",
    "CVE-2023-4049",
    "CVE-2023-4050",
    "CVE-2023-4052",
    "CVE-2023-4054",
    "CVE-2023-4055",
    "CVE-2023-4056",
    "CVE-2023-4057"
  );

  script_name(english:"Slackware Linux 15.0 / current mozilla-firefox  Multiple Vulnerabilities (SSA:2023-216-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-firefox.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-firefox installed on the remote host is prior to 115.1.0esr. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA:2023-216-01 advisory.

  - Offscreen Canvas did not properly track cross-origin tainting, which could have been used to access image
    data from another site in violation of same-origin policy. This vulnerability affects Firefox < 116,
    Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4045)

  - In some circumstances, a stale value could have been used for a global variable in WASM JIT analysis. This
    resulted in incorrect compilation and a potentially exploitable crash in the content process. This
    vulnerability affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4046)

  - A bug in popup notifications delay calculation could have made it possible for an attacker to trick a user
    into granting permissions. This vulnerability affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR
    < 115.1. (CVE-2023-4047)

  - An out-of-bounds read could have led to an exploitable crash when parsing HTML with DOMParser in low
    memory situations. This vulnerability affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR <
    115.1. (CVE-2023-4048)

  - Race conditions in reference counting code were found through code inspection. These could have resulted
    in potentially exploitable use-after-free vulnerabilities. This vulnerability affects Firefox < 116,
    Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4049)

  - In some cases, an untrusted input stream was copied to a stack buffer without checking its size. This
    resulted in a potentially exploitable crash which could have led to a sandbox escape. This vulnerability
    affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4050)

  - The Firefox updater created a directory writable by non-privileged users. When uninstalling Firefox, any
    files in that directory would be recursively deleted with the permissions of the uninstalling user
    account. This could be combined with creation of a junction (a form of symbolic link) to allow arbitrary
    file deletion controlled by the non-privileged user. *This bug only affects Firefox on Windows. Other
    operating systems are unaffected.* This vulnerability affects Firefox < 116 and Firefox ESR < 115.1.
    (CVE-2023-4052)

  - When opening appref-ms files, Firefox did not warn the user that these files may contain malicious code.
    *This bug only affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability
    affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4054)

  - When the number of cookies per domain was exceeded in `document.cookie`, the actual cookie jar sent to the
    host was no longer consistent with expected cookie jar state. This could have caused requests to be sent
    with some cookies missing. This vulnerability affects Firefox < 116, Firefox ESR < 102.14, and Firefox ESR
    < 115.1. (CVE-2023-4055)

  - Memory safety bugs present in Firefox 115, Firefox ESR 115.0, Firefox ESR 102.13, Thunderbird 115.0, and
    Thunderbird 102.13. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects
    Firefox < 116, Firefox ESR < 102.14, and Firefox ESR < 115.1. (CVE-2023-4056)

  - Memory safety bugs present in Firefox 115, Firefox ESR 115.0, and Thunderbird 115.0. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 116 and Firefox ESR < 115.1.
    (CVE-2023-4057)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.401033
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c2a2812");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
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
    { 'fixed_version' : '115.1.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '115.1.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '115.1.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '115.1.0esr', 'product' : 'mozilla-firefox', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
