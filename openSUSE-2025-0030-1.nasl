#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0030-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214572);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-54662");

  script_name(english:"openSUSE 15 Security Update : dante (openSUSE-SU-2025:0030-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2025:0030-1 advisory.

    - Update to version 1.4.4
      * Fixed incorrect access control for some sockd.conf configurations
        involving socksmethod (boo#1234688, CVE-2024-54662).

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234688");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IWNRHV4HZ3KU4VHYWJQPULNK5D444I3X/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da17259c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-54662");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54662");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dante");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dante-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dante-devel-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dante-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsocks0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsocks0-64bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'dante-1.4.4-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dante-devel-1.4.4-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dante-devel-64bit-1.4.4-bp156.4.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dante-server-1.4.4-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsocks0-1.4.4-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsocks0-64bit-1.4.4-bp156.4.3.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dante / dante-devel / dante-devel-64bit / dante-server / libsocks0 / etc');
}
