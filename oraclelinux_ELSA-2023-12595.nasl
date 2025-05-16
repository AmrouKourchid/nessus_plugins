#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12595.
##

include('compat.inc');

if (description)
{
  script_id(178685);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2023-2319", "CVE-2023-27530", "CVE-2023-27539");

  script_name(english:"Oracle Linux 9 : pcs (ELSA-2023-12595)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-12595 advisory.

    [0.11.4-7]
    - Fix displaying differences between configuration checkpoints in pcs config checkpoint diff command
    - Fix pcs stonith update-scsi-devices command which was broken since Pacemaker-2.1.5-rc1
    - Fixed loading of cluster status in the web interface when fencing levels are configured
    - Fixed a vulnerability in pcs-web-ui-node-modules
    - Updated bundled rubygem rack
    - Resolves: rhbz#2179901 rhbz#2180697 rhbz#2180704 rhbz#2180708 rhbz#2180978 rhbz#2183180

    [0.11.4-6]
    - Fixed broken filtering in create resource/fence device wizards in the web interface
    - Added BuildRequires: pam - needed for tier0 tests during build
    - Resolves: rhbz#2167471

    [0.11.4-5]
    - Fixed enabling/disabling sbd when cluster is not running
    - Resolves: rhbz#2166249

    [0.11.4-4]
    - Rebuilt with fixed patches
    - Resolves: rhbz#2158790 rhbz#2159454

    [0.11.4-3]
    - Allow time values in stonith-watchdog-time property
    - Resource/stonith agent self-validation of instance attributes is now disabled by default, as many agents
    do not work with it properly.
    - Updated bundled rubygems: rack, rack-protection, sinatra
    - Added license for ruby2_keywords
    - Resolves: rhbz#2158790 rhbz#2159454

    [0.11.4-2]
    - Fixed stopping of pcsd service using systemctl stop pcsd command
    - Fixed smoke test execution during gating
    - Added warning when omitting validation of misconfigured resource
    - Fixed displaying of bool and integer values in pcs resource config command
    - Updated bundled rubygems: ethon, rack-protection, sinatra
    - Resolves: rhbz#2148124 rhbz#2151164 rhbz#2151524

    [0.11.4-1]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Updated pcs-web-ui
    - Resolves: rhbz#1620043 rhbz#2019464 rhbz#2099653 rhbz#2109633 rhbz#2112293 rhbz#2116295 rhbz#2117600
    rhbz#2117601

    [0.11.3-5]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Updated pcs-web-ui
    - Added bundled rubygem: childprocess
    - Removed bundled rubygem: open4
    - Updated bundled rubygems: mustermann, rack, rack-protection, rack-test, sinatra, tilt
    - Resolves: rhbz#1493416 rhbz#1796827 rhbz#2059147 rhbz#2092950 rhbz#2112079 rhbz#2112270 rhbz#2112293
    rhbz#2117599 rhbz#2117601

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12595.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected pcs and / or pcs-snmp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2319");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::addons");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pcs-snmp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'pcs-0.11.4-7.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-snmp-0.11.4-7.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-0.11.4-7.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-snmp-0.11.4-7.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pcs / pcs-snmp');
}
