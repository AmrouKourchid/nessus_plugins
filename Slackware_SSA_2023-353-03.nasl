#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-353-03. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187109);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id(
    "CVE-2023-6856",
    "CVE-2023-6857",
    "CVE-2023-6858",
    "CVE-2023-6859",
    "CVE-2023-6860",
    "CVE-2023-6861",
    "CVE-2023-6862",
    "CVE-2023-6863",
    "CVE-2023-6864",
    "CVE-2023-50761",
    "CVE-2023-50762"
  );
  script_xref(name:"IAVA", value:"2023-A-0703");

  script_name(english:"Slackware Linux 15.0 / current mozilla-thunderbird  Multiple Vulnerabilities (SSA:2023-353-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-thunderbird.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-thunderbird installed on the remote host is prior to 115.6.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA:2023-353-03 advisory.

  - The signature of a digitally signed S/MIME email message may optionally specify the signature creation
    date and time. If present, Thunderbird did not compare the signature creation date with the message date
    and time, and displayed a valid signature despite a date or time mismatch. This could be used to give
    recipients the impression that a message was sent at a different date or time. This vulnerability affects
    Thunderbird < 115.6. (CVE-2023-50761)

  - When processing a PGP/MIME payload that contains digitally signed text, the first paragraph of the text
    was never shown to the user. This is because the text was interpreted as a MIME message and the first
    paragraph was always treated as an email header section. A digitally signed text from a different context,
    such as a signed GIT commit, could be used to spoof an email message. This vulnerability affects
    Thunderbird < 115.6. (CVE-2023-50762)

  - The WebGL `DrawElementsInstanced` method was susceptible to a heap buffer overflow when used on systems
    with the Mesa VM driver. This issue could allow an attacker to perform remote code execution and sandbox
    escape. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6856)

  - When resolving a symlink, a race may occur where the buffer passed to `readlink` may actually be smaller
    than necessary. *This bug only affects Firefox on Unix-based operating systems (Android, Linux, MacOS).
    Windows is unaffected.* This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox <
    121. (CVE-2023-6857)

  - Firefox was susceptible to a heap buffer overflow in `nsTextFragment` due to insufficient OOM handling.
    This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6858)

  - A use-after-free condition affected TLS socket creation when under memory pressure. This vulnerability
    affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6859)

  - The `VideoBridge` allowed any content process to use textures produced by remote decoders. This could be
    abused to escape the sandbox. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6860)

  - The `nsWindow::PickerOpen(void)` method was susceptible to a heap buffer overflow when running in headless
    mode. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6861)

  - A use-after-free was identified in the `nsDNSService::Init`. This issue appears to manifest rarely during
    start-up. This vulnerability affects Firefox ESR < 115.6 and Thunderbird < 115.6. (CVE-2023-6862)

  - The `ShutdownObserver()` was susceptible to potentially undefined behavior due to its reliance on a
    dynamic type that lacked a virtual destructor. This vulnerability affects Firefox ESR < 115.6, Thunderbird
    < 115.6, and Firefox < 121. (CVE-2023-6863)

  - Memory safety bugs present in Firefox 120, Firefox ESR 115.5, and Thunderbird 115.5. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6864)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.405566
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a428f53");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6864");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    { 'fixed_version' : '115.6.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '115.6.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '115.6.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '115.6.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
