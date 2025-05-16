#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0010. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193539);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2021-20271");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : rpm Vulnerability (NS-SA-2024-0010)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has rpm packages installed that are affected by a
vulnerability:

  - A flaw was found in RPM's signature check functionality when reading a package file. This flaw allows an
    attacker who can convince a victim to install a seemingly verifiable package, whose signature header was
    modified, to cause RPM database corruption and execute code. The highest threat from this vulnerability is
    to data integrity, confidentiality, and system availability. (CVE-2021-20271)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0010");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-20271");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL rpm packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-build-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-plugin-systemd-inhibit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:rpm-sign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-build-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-plugin-systemd-inhibit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rpm-sign");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'rpm-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-apidocs-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-build-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-build-libs-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-cron-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-debuginfo-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-devel-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-lang-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-libs-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-plugin-systemd-inhibit-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-python-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite',
    'rpm-sign-4.11.3-48.el7_9.cgslv5.0.11.gd75f5b4.lite'
  ],
  'CGSL MAIN 5.04': [
    'rpm-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-apidocs-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-build-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-build-libs-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-cron-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-debuginfo-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-devel-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-libs-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-plugin-systemd-inhibit-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-python-4.11.3-48.el7_9.cgslv5.0.11.g939b202',
    'rpm-sign-4.11.3-48.el7_9.cgslv5.0.11.g939b202'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rpm');
}
