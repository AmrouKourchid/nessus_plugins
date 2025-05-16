#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0271 and 
# Oracle Linux Security Advisory ELSA-2013-0271 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68732);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2013-0775",
    "CVE-2013-0776",
    "CVE-2013-0780",
    "CVE-2013-0782",
    "CVE-2013-0783"
  );
  script_bugtraq_id(
    58037,
    58042,
    58043,
    58044,
    58047
  );
  script_xref(name:"RHSA", value:"2013:0271");

  script_name(english:"Oracle Linux 5 / 6 : firefox (ELSA-2013-0271)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2013-0271 advisory.

    firefox
    [17.0.3-1.0.1]
    - Add firefox-oracle-default-prefs.js and remove the corresponding Red Hat ones

    [17.0.3-1]
    - Update to 17.0.3 ESR

    [17.0.2-4]
    - Added NM preferences

    [17.0.2-3]
    - Update to 17.0.2 ESR

    [17.0.1-2]
    - Update to 17.0.1 ESR

    [17.0-1]
    - Update to 17.0 ESR

    [17.0-0.2.b4]
    - Update to 17 Beta 4

    [17.0-0.1.beta1]
    - Update to 17 Beta 1


    libproxy
    [0.3.0-4]
    - Rebuild against newer gecko

    xulrunner
    [17.0.3-1.0.2]
    - Increase release number and rebuild.

    [17.0.3-1.0.1]
    - Replaced xulrunner-redhat-default-prefs.js with xulrunner-oracle-default-prefs.js
    - Removed XULRUNNER_VERSION from SOURCE21

    [17.0.3-1]
    - Update to 17.0.3 ESR

    [17.0.2-5]
    - Fixed NetworkManager preferences
    - Added fix for NM regression (mozbz#791626)

    [17.0.2-2]
    - Added fix for rhbz#816234 - NFS fix

    [17.0.2-1]
    - Update to 17.0.2 ESR

    [17.0.1-3]
    - Update to 17.0.1 ESR

    [17.0-1]
    - Update to 17.0 ESR

    [17.0-0.6.b5]
    - Update to 17 Beta 5
    - Updated fix for rhbz#872752 - embeded crash

    [17.0-0.5.b4]
    - Added fix for rhbz#872752 - embeded crash

    [17.0-0.4.b4]
    - Update to 17 Beta 4

    [17.0-0.3.b3]
    - Update to 17 Beta 3
    - Updated ppc(64) patch (mozbz#746112)

    [17.0-0.2.b2]
    - Built with system nspr/nss

    [17.0-0.1.b2]
    - Update to 17 Beta 2

    [17.0-0.1.b1]
    - Update to 17 Beta 1

    yelp
    [2.28.1-17]
    - Rebuild against gecko 17.0.2

    [2.28.1-15]
    - Build fixes for gecko 17

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0271.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0783");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-0782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-mozjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libproxy-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5 / 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'devhelp-0.12-23.el5_9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'devhelp-devel-0.12-23.el5_9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'firefox-17.0.3-1.0.1.el5_9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'xulrunner-17.0.3-1.0.1.el5_9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-devel-17.0.3-1.0.1.el5_9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yelp-2.16.0-30.el5_9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'devhelp-0.12-23.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'devhelp-devel-0.12-23.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'firefox-17.0.3-1.0.1.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'xulrunner-17.0.3-1.0.1.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-devel-17.0.3-1.0.1.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yelp-2.16.0-30.el5_9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'firefox-17.0.3-1.0.1.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'libproxy-0.3.0-4.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-bin-0.3.0-4.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-devel-0.3.0-4.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-gnome-0.3.0-4.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-kde-0.3.0-4.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-mozjs-0.3.0-4.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-python-0.3.0-4.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-webkit-0.3.0-4.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-17.0.3-1.0.2.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-devel-17.0.3-1.0.2.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yelp-2.28.1-17.el6_3', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'firefox-17.0.3-1.0.1.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'libproxy-0.3.0-4.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-bin-0.3.0-4.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-devel-0.3.0-4.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-gnome-0.3.0-4.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-kde-0.3.0-4.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-mozjs-0.3.0-4.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-python-0.3.0-4.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libproxy-webkit-0.3.0-4.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-17.0.3-1.0.2.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xulrunner-devel-17.0.3-1.0.2.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yelp-2.28.1-17.el6_3', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'devhelp / devhelp-devel / firefox / etc');
}
