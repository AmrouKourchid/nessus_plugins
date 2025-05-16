#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-2184.
##

include('compat.inc');

if (description)
{
  script_id(181077);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2015-2704");

  script_name(english:"Oracle Linux 7 : realmd (ELSA-2015-2184)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2015-2184 advisory.

    [0.16.1-5]
    - Revert 0.16.1-4
    - Use samba by default
    - Resolves: rhbz#1271618

    [0.16.1-4]
    - Fix regressions in 0.16.x releases
    - Resolves: rhbz#1258745
    - Resolves: rhbz#1258488

    [0.16.1-3]
    - Fix regression accepting DNS domain names
    - Resolves: rhbz#1243771

    [0.16.1-2]
    - Fix discarded patch: ipa-packages.patch

    [0.16.1-1]
    - Updated to upstream 0.16.1
    - Resolves: rhbz#1241832
    - Resolves: rhbz#1230941

    [0.16.0-1]
    - Updated to upstream 0.16.0
    - Resolves: rhbz#1174911
    - Resolves: rhbz#1142191
    - Resolves: rhbz#1142148

    [0.14.6-5]
    - Don't crash when full_name_format is not in sssd.conf [#1051033]
      This is a regression from a prior update.

    [0.14.6-4]
    - Fix full_name_format printf(3) related failure [#1048087]

    [0.14.6-3]
    - Mass rebuild 2013-12-27

    [0.14.6-2]
    - Start oddjob after joining a domain [#967023]

    [0.14.6-1]
    - Update to upstream 0.14.6 point release
    - Set 'kerberos method = system keytab' in smb.conf properly [#997580]
    - Limit Netbios name to 15 chars when joining AD domain [#1001667]

    [0.14.5-1]
    - Update to upstream 0.14.5 point release
    - Fix regression conflicting --unattended and -U as in --user args [#996223]
    - Pass discovered server address to adcli tool [#996995]

    [0.14.4-1]
    - Update to upstream 0.14.4 point release
    - Fix up the [sssd] section in sssd.conf if it's screwed up [#987491]
    - Add an --unattended argument to realm command line client [#976593]
    - Clearer 'realm permit' manual page example [#985800]

    [0.14.3-1]
    - Update to upstream 0.14.3 point release
    - Populate LoginFormats correctly [#967011]
    - Documentation clarifications [#985773] [#967565]
    - Set sssd.conf default_shell per domain [#967569]
    - Notify in terminal output when installing packages [#984960]
    - If joined via adcli, delete computer with adcli too [#967008]
    - If input is not a tty, then read from stdin without getpass()
    - Configure pam_winbind.conf appropriately [#985819]
    - Refer to FreeIPA as IPA [#967019]
    - Support use of kerberos ccache to join when winbind [#985817]

    [0.14.2-3]
    - Run test suite when building the package
    - Fix rpmlint errors

    [0.14.2-2]
    - Install oddjobd and oddjob-mkhomedir when joining domains [#969441]

    [0.14.2-1]
    - Update to upstream 0.14.2 version
    - Discover FreeIPA 3.0 with AD trust correctly [#966148]
    - Only allow joining one realm by default [#966650]
    - Enable the oddjobd service after joining a domain [#964971]
    - Remove sssd.conf allow lists when permitting all [#965760]
    - Add dependency on authconfig [#964675]
    - Remove glib-networking dependency now that we no longer use SSL.

    [0.14.1-1]
    - Update to upstream 0.14.1 version
    - Fix crasher/regression using passwords with joins [#961435]
    - Make second Ctrl-C just quit realm tool [#961325]
    - Fix critical warning when leaving IPA realm [#961320]
    - Don't print out journalctl command in obvious situations [#961230]
    - Document the --all option to 'realm discover' [#961279]
    - No need to require sssd-tools package [#961254]
    - Enable services even in install mode [#960887]
    - Use the AD domain name in sssd.conf directly [#960270]
    - Fix critical warning when service Release() method [#961385]

    [0.14.0-1]
    - Work around broken krb5 with empty passwords [#960001]
    - Add manual page for realmd.conf [#959357]
    - Update to upstream 0.14.0 version

    [0.13.91-1]
    - Fix regression when using one time password [#958667]
    - Support for permitting logins by group [#887675]

    [0.13.90-1]
    - Add option to disable package-kit installs [#953852]
    - Add option to use unqualified names [#953825]
    - Better discovery of domains [#953153]
    - Concept of managing parts of the system [#914892]
    - Fix problems with cache directory [#913457]
    - Clearly explain when realm cannot be joined [#878018]
    - Many other upstream enhancements and fixes

    [0.13.3-2]
    - Add missing glib-networking dependency, currently used
      for FreeIPA discovery [#953151]

    [0.13.3-1]
    - Update for upstream 0.13.3 version
    - Add dependency on systemd for installing service file

    [0.13.2-2]
    - Fix problem with sssd not starting after joining

    [0.13.2-1]
    - Update to upstream 0.13.2 version

    [0.13.1-1]
    - Update to upstream 0.13.1 version for bug fixes

    [0.12-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

    [0.12-1]
    - Update to upstream 0.12 version for bug fixes

    [0.11-1]
    - Update to upstream 0.11 version

    [0.10-1]
    - Update to upstream 0.10 version

    [0.9-1]
    - Update to upstream 0.9 version

    [0.8-2]
    - Add openldap-devel build requirement

    [0.8-1]
    - Update to upstream 0.8 version
    - Add support for translations

    [0.7-2]
    - Build requires gtk-doc

    [0.7-1]
    - Update to upstream 0.7 version
    - Remove files no longer present in upstream version
    - Put documentation in its own realmd-devel-docs subpackage
    - Update upstream URLs

    [0.6-1]
    - Update to upstream 0.6 version

    [0.5-2]
    - Remove missing SssdIpa.service file from the files list.
      This file will return upstream in 0.6

    [0.5-1]
    - Update to upstream 0.5 version

    [0.4-1]
    - Update to upstream 0.4 version
    - Cleanup various rpmlint warnings

    [0.3-2]
    - Add doc files
    - Own directories
    - Remove obsolete parts of spec file
    - Remove explicit dependencies
    - Updated License line to LGPLv2+

    [0.3]
    - Build fixes

    [0.2]
    - Initial RPM

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-2184.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected realmd and / or realmd-devel-docs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:realmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:realmd-devel-docs");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'realmd-0.16.1-5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'realmd-devel-docs-0.16.1-5.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'realmd / realmd-devel-docs');
}
