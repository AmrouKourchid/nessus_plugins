##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9513.
##

include('compat.inc');

if (description)
{
  script_id(162813);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2022-29970");

  script_name(english:"Oracle Linux 9 : pcs (ELSA-2022-9513)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-9513 advisory.

    [0.11.1-10.el9_0.1]
    - Updated bundled rubygems: sinatra, rack-protection
    - Resolves: rhbz#2081333

    [0.11.1-10]
    - Fixed snmp client
    - Fixed translating resource roles in colocation constraint
    - Resolves: rhbz#2048640

    [0.11.1-9]
    - Fixed cluster destroy in web ui
    - Fixed covscan issue in web ui
    - Resolves: rhbz#2044409

    [0.11.1-8]
    - Fixed 'pcs resource move' command
    - Fixed removing of unavailable fence-scsi storage device
    - Fixed ocf validation of ocf linbit drdb agent
    - Fixed creating empty cib
    - Updated pcs-web-ui
    - Resolves: rhbz#1990787 rhbz#2033248 rhbz#2039883 rhbz#2040420

    [0.11.1-7]
    - Fixed enabling corosync-qdevice
    - Fixed resource update command when unable to get agent metadata
    - Fixed revert of disallowing to clone a group with a stonith
    - Resolves: rhbz#1811072 rhbz#2019836 rhbz#2032473

    [0.11.1-6]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Updated pcs web ui
    - Resolves: rhbz#1990787 rhbz#1997019 rhbz#2012129 rhbz#2024542 rhbz#2027678 rhbz#2027679

    [0.11.1-5]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Resolves: rhbz#1990787 rhbz#2018969 rhbz#2019836 rhbz#2023752 rhbz#2012129

    [0.11.1-4]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Updated pcs web ui
    - Enabled wui patching
    - Resolves: rhbz#1811072 rhbz#1945305 rhbz#1997019 rhbz#2012129

    [0.11.1-1]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Resolves: rhbz#1283805 rhbz#1910644 rhbz#1910645  rhbz#1956703 rhbz#1956706 rhbz#1985981 rhbz#1991957
    rhbz#1996062 rhbz#1996067

    [0.11.0.alpha.1-1]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Updated pcs web ui
    - Resolves: rhbz#1283805 rhbz#1910644 rhbz#1910645 rhbz#1985981 rhbz#1991957 rhbz#1996067

    [0.10.9-2]
    - Rebuilt for libffi 3.4.2 SONAME transition.
      Related: rhbz#1891914

    [0.10.9-1]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Resolves: rhbz#1991957

    [0.10.8-11]
    - Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
      Related: rhbz#1991688

    [0.10.8-10]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Fixed web-ui build
    - Fixed tests for pacemaker 2.1
    - Resolves: rhbz#1975440 rhbz#1922302

    [0.10.8-9]
    - Rebuilt for RHEL 9 BETA for openssl 3.0
      Related: rhbz#1971065

    [0.10.8-8]
    - Rebuild with fixed gaiting tests
    - Stopped bundling rubygem-json (use distribution package instead)
    - Fixed patches
    - Resolves: rhbz#1881064

    [0.10.8-7]
    - Fixed License tag
    - Rebuild with fixed dependency for gating tier0 tests
    - Resolves: rhbz#1881064

    [0.10.8-6]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Removed clufter related commands
    - Resolves: rhbz#1881064

    [0.10.8-5]
    - Updated pcs web ui node modules
    - Fixed build issue on low memory build hosts
    - Resolves: rhbz#1951272

    [0.10.8-4]
    - Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

    [0.10.8-3]
    - Replace pyOpenSSL with python-cryptography
    - Resolves: rhbz#1927404

    [0.10.8-2]
    - Bundle rubygem depedencies and python3-tornado
    - Resolves: rhbz#1929710

    [0.10.8-1]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Updated pcs-web-ui
    - Updated bundled python dependency: dacite
    - Changed BuildRequires from git to git-core
    - Added conditional (Build)Requires: rubygem(rexml)
    - Added conditional Requires: rubygem(webrick)

    [0.10.7-4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

    [0.10.7-3]
    - Rebuilt for https://fedoraproject.org/wiki/Changes/Ruby_3.0

    [0.10.7-2]
    - Python 3.10 related fix

    [0.10.7-1]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Added dependency on python packages pyparsing and dateutil
    - Fixed virtual bundle provides for ember, handelbars, jquery and jquery-ui
    - Removed dependency on python3-clufter

    [0.10.6-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

    [0.10.6-1]
    - Rebased to latest upstream sources (see CHANGELOG.md)
    - Updated pcs-web-ui
    - Stopped bundling tornado (use distribution package instead)
    - Stopped bundling rubygem-tilt (use distribution package instead)
    - Removed rubygem bundling
    - Removed unneeded BuildRequires: execstack, gcc, gcc-c++
    - Excluded some tests for tornado daemon

    [0.10.5-8]
    - Use make macros
    - https://fedoraproject.org/wiki/Changes/UseMakeBuildInstallMacro

    [0.10.5-7]
    - Use fixed upstream version of dacite with Python 3.9 support
    - Split upstream tests in gating into tiers

    [0.10.5-6]
    - Use patched version of dacite compatible with Python 3.9
    - Resolves: rhbz#1838327

    [0.10.5-5]
    - Rebuilt for Python 3.9

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9513.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected pcs and / or pcs-snmp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29970");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pcs-snmp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'pcs-0.11.1-10.el9_0.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-snmp-0.11.1-10.el9_0.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-0.11.1-10.el9_0.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-snmp-0.11.1-10.el9_0.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
