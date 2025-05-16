#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-328-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186243);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/09");

  script_cve_id(
    "CVE-2023-48231",
    "CVE-2023-48232",
    "CVE-2023-48233",
    "CVE-2023-48234",
    "CVE-2023-48235",
    "CVE-2023-48236",
    "CVE-2023-48237"
  );
  script_xref(name:"IAVA", value:"2023-A-0650-S");

  script_name(english:"Slackware Linux 15.0 / current vim  Multiple Vulnerabilities (SSA:2023-328-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to vim.");
  script_set_attribute(attribute:"description", value:
"The version of vim installed on the remote host is prior to 9.0.2127. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2023-328-01 advisory.

  - Vim is an open source command line text editor. When closing a window, vim may try to access already freed
    window structure. Exploitation beyond crashing the application has not been shown to be viable. This issue
    has been addressed in commit `25aabc2b` which has been included in release version 9.0.2106. Users are
    advised to upgrade. There are no known workarounds for this vulnerability. (CVE-2023-48231)

  - Vim is an open source command line text editor. A floating point exception may occur when calculating the
    line offset for overlong lines and smooth scrolling is enabled and the cpo-settings include the 'n' flag.
    This may happen when a window border is present and when the wrapped line continues on the next physical
    line directly in the window border because the 'cpo' setting includes the 'n' flag. Only users with non-
    default settings are affected and the exception should only result in a crash. This issue has been
    addressed in commit `cb0b99f0` which has been included in release version 9.0.2107. Users are advised to
    upgrade. There are no known workarounds for this vulnerability. (CVE-2023-48232)

  - Vim is an open source command line text editor. If the count after the :s command is larger than what fits
    into a (signed) long variable, abort with e_value_too_large. Impact is low, user interaction is required
    and a crash may not even happen in all situations. This issue has been addressed in commit `ac6378773`
    which has been included in release version 9.0.2108. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-48233)

  - Vim is an open source command line text editor. When getting the count for a normal mode z command, it may
    overflow for large counts given. Impact is low, user interaction is required and a crash may not even
    happen in all situations. This issue has been addressed in commit `58f9befca1` which has been included in
    release version 9.0.2109. Users are advised to upgrade. There are no known workarounds for this
    vulnerability. (CVE-2023-48234)

  - Vim is an open source command line text editor. When parsing relative ex addresses one may unintentionally
    cause an overflow. Ironically this happens in the existing overflow check, because the line number becomes
    negative and LONG_MAX - lnum will cause the overflow. Impact is low, user interaction is required and a
    crash may not even happen in all situations. This issue has been addressed in commit `060623e` which has
    been included in release version 9.0.2110. Users are advised to upgrade. There are no known workarounds
    for this vulnerability. (CVE-2023-48235)

  - Vim is an open source command line text editor. When using the z= command, the user may overflow the count
    with values larger than MAX_INT. Impact is low, user interaction is required and a crash may not even
    happen in all situations. This vulnerability has been addressed in commit `73b2d379` which has been
    included in release version 9.0.2111. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2023-48236)

  - Vim is an open source command line text editor. In affected versions when shifting lines in operator
    pending mode and using a very large value, it may be possible to overflow the size of integer. Impact is
    low, user interaction is required and a crash may not even happen in all situations. This issue has been
    addressed in commit `6bf131888` which has been included in version 9.0.2112. Users are advised to upgrade.
    There are no known workarounds for this vulnerability. (CVE-2023-48237)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.423197
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beb2e539");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected vim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48237");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:vim-gvim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '9.0.2127', 'product' : 'vim', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '9.0.2127', 'product' : 'vim-gvim', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '9.0.2127', 'product' : 'vim', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '9.0.2127', 'product' : 'vim-gvim', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '9.0.2127', 'product' : 'vim', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '9.0.2127', 'product' : 'vim-gvim', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '9.0.2127', 'product' : 'vim', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' },
    { 'fixed_version' : '9.0.2127', 'product' : 'vim-gvim', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
