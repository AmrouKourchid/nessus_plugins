#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0501 and 
# Oracle Linux Security Advisory ELSA-2010-0501 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68055);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2008-5913",
    "CVE-2009-5017",
    "CVE-2010-0182",
    "CVE-2010-1121",
    "CVE-2010-1125",
    "CVE-2010-1196",
    "CVE-2010-1197",
    "CVE-2010-1198",
    "CVE-2010-1199",
    "CVE-2010-1200",
    "CVE-2010-1202",
    "CVE-2010-1203"
  );
  script_xref(name:"RHSA", value:"2010:0501");

  script_name(english:"Oracle Linux 5 : firefox (ELSA-2010-0501)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2010-0501 advisory.

    devhelp:

    [0.12-21]
    - Rebuild against xulrunner

    esc:

    [1.1.0-12]
    - Rebuild for xulrunner update

    firefox:

    [3.6.4-8.0.1.el5]
    - Add firefox-oracle-default-prefs.js and firefox-oracle-default-bookmarks.html
      and remove the corresponding Red Hat ones

    [3.6.4-8]
    - Fixing NVR

    [3.6.4-7]
    - Update to 3.6.4 build7
    - Disable checking for updates since they can't be applied

    [3.6.4-6]
    - Update to 3.6.4 build6

    [3.6.4-5]
    - Update to 3.6.4 build5

    [3.6.4-4]
    - Update to 3.6.4 build4

    [3.6.4-3]
    - Update to 3.6.4 build 3

    [3.6.4-2]
    - Update to 3.6.4 build 2

    [3.6.4-1]
    - Update to 3.6.4

    [3.6.3-3]
    - Fixed language packs (#581392)

    [3.6.3-2]
    - Fixed multilib conflict

    [3.6.3-1]
    - Rebase to 3.6.3

    gnome-python2-extras:

    [2.14.2-7]
    - rebuild agains xulrunner

    totem:

    [2.16.7-7]
    - rebuild against new xulrunner

    xulrunner:

    [1.9.2.4-9.0.1]
    - Added xulrunner-oracle-default-prefs.js and removed the corresponding
      RedHat one.

    [1.9.2.4-9]
    - Update to 1.9.2.4 build 7

    [1.9.2.4-8]
    - Update to 1.9.2.4 build 6

    [1.9.2.4-7]
    - Update to 1.9.2.4 build 5

    [1.9.2.4-6]
    - Update to 1.9.2.4 build 4
    - Fixed mozbz#546270 patch

    [1.9.2.4-5]
    - Update to 1.9.2.4 build 3

    [1.9.2.4-4]
    - Update to 1.9.2.4 build 2
    - Enabled oopp

    [1.9.2.4-3]
    - Disabled libnotify

    [1.9.2.4-2]
    - Disabled oopp, causes TEXTREL

    [1.9.2.4-1]
    - Update to 1.9.2.4

    [1.9.2.3-3]
    - fixed js-config.h multilib conflict
    - fixed file list

    [1.9.2.3-2]
    - Added fix for rhbz#555760 -  Firefox Javascript anomily,
      landscape print orientation reverts to portrait (mozbz#546270)

    [1.9.2.3-1]
    - Update to 1.9.2.3

    [1.9.2.2-1]
    - Rebase to 1.9.2.2

    yelp:

    [2.16.0-26]
    - rebuild against xulrunner

    [2.16.0-25]
    - rebuild against xulrunner
    - added xulrunner fix
    - added -fno-strict-aliasing to build flags

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2010-0501.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1121");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-1197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:esc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-python2-libegg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:totem-mozplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'devhelp-0.12-21.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'devhelp-devel-0.12-21.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'esc-1.1.0-12.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'firefox-3.6.4-8.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'gnome-python2-extras-2.14.2-7.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-python2-gtkhtml2-2.14.2-7.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-python2-gtkmozembed-2.14.2-7.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-python2-gtkspell-2.14.2-7.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-python2-libegg-2.14.2-7.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'totem-2.16.7-7.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'totem-devel-2.16.7-7.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'totem-mozplugin-2.16.7-7.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-1.9.2.4-9.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-devel-1.9.2.4-9.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yelp-2.16.0-26.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'devhelp-0.12-21.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'devhelp-devel-0.12-21.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'esc-1.1.0-12.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'firefox-3.6.4-8.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'gnome-python2-extras-2.14.2-7.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-python2-gtkhtml2-2.14.2-7.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-python2-gtkmozembed-2.14.2-7.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-python2-gtkspell-2.14.2-7.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-python2-libegg-2.14.2-7.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'totem-2.16.7-7.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'totem-devel-2.16.7-7.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'totem-mozplugin-2.16.7-7.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-1.9.2.4-9.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-devel-1.9.2.4-9.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yelp-2.16.0-26.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'devhelp / devhelp-devel / esc / etc');
}
