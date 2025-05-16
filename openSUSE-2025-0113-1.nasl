#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0113-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(233803);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-48423",
    "CVE-2024-48424",
    "CVE-2024-48425",
    "CVE-2024-53425",
    "CVE-2025-2151",
    "CVE-2025-2591",
    "CVE-2025-2592",
    "CVE-2025-3015",
    "CVE-2025-3016"
  );

  script_name(english:"openSUSE 15 Security Update : assimp (openSUSE-SU-2025:0113-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0113-1 advisory.

    - CVE-2024-48425: Fixed SEGV in Assimp:SplitLargeMeshesProcess_Triangle:UpdateNode (boo#1232324)
    - CVE-2024-48423: Fixed a arbitrary code execution via CallbackToLogRedirector() (boo#1232322)
    - CVE-2024-48424: Fixed a heap-buffer-overflow in OpenDDLParser:parseStructure() (boo#1232323)
    - CVE-2024-53425: Fixed a heap-based buffer overflow in SkipSpacesAndLineEnd() (boo#1233633)
    - CVE-2025-2592: Fixed a heap-based buffer overflow in Assimp::CSMImporter::InternReadFile() (boo#1239916)
    - CVE-2025-3015: Fixed out-of-bounds read caused by manipulation of the argument mIndices (boo#1240412)
    - CVE-2025-3016: Fixed a denial of service caused by manipulation of the argument mWidth/mHeight
    (boo#1240413)
    - CVE-2025-2591: Fixed a denial of service in code/AssetLib/MDL/MDLLoader.cpp (boo#1239920)
    - CVE-2025-2151: Fixed a stack-based buffer overflow in Assimp::GetNextLine() (boo#1239220)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240413");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GUXUVZ7SBZK5ZFR45B223UXCWUMD4XQD/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b757fbb");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48423");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-2151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-2591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-2592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3016");
  script_set_attribute(attribute:"solution", value:
"Update the affected assimp-devel and / or libassimp5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2592");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-48423");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-3016");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:assimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libassimp5");
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
    {'reference':'assimp-devel-5.3.1-bp156.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libassimp5-5.3.1-bp156.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'assimp-devel / libassimp5');
}
