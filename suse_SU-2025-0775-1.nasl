#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0775-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(225811);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id(
    "CVE-2023-45288",
    "CVE-2024-1753",
    "CVE-2024-6104",
    "CVE-2024-9341",
    "CVE-2024-9407",
    "CVE-2024-9675",
    "CVE-2024-9676",
    "CVE-2024-11218",
    "CVE-2025-27144"
  );
  script_xref(name:"IAVA", value:"2024-A-0599");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0775-1");

  script_name(english:"SUSE SLES15 Security Update : podman (SUSE-SU-2025:0775-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0775-1 advisory.

    - CVE-2025-27144: Fixed denial of service in parsing function of embedded library Go JOSE (bsc#1237641)
    - CVE-2024-9676: github.com/containers/storage: Fixed symlink traversal vulnerability in the
    containers/storage library can cause Denial of Service (DoS) (bsc#1231698)
    - CVE-2024-9675: Fixed cache arbitrary directory mount in buildah (bsc#1231499)
    - CVE-2024-9407: Fixed Improper Input Validation in bind-propagation Option of Dockerfile RUN --mount
    Instruction in buildah (bsc#1231208)
    - CVE-2024-9341: cri-o: FIPS Crypto-Policy Directory Mounting Issue in containers/common Go Library
    (bsc#1231230)
    - CVE-2024-1753: Fixed full container escape at build time in buildah (bsc#1221677)
    - CVE-2024-11218: Fixed a container breakout by using --jobs=2 and a race condition when building a
    malicious Containerfile. (bsc#1236270)
    - CVE-2024-6104: Fixed hashicorp/go-retryablehttp writing sensitive information to log files (bsc#1227052)
    - CVE-2023-45288: Fixed golang.org/x/net/http2 excessive resource consumption when receiving too many
    headers (bsc#1236507)


    - Load ip_tables and ip6_tables kernel module (bsc#1214612)
      * Required for rootless mode as a regular user has no permission
        to load kernel modules


    - Refactor network backend dependencies:
      * podman requires either netavark or cni-plugins. On ALP, require
        netavark, otherwise prefer netavark but don't force it.
      * This fixes missing cni-plugins in some scenarios
      * Default to netavark everywhere where it's available

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237641");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-March/020479.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6804acae");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-11218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9407");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-27144");
  script_set_attribute(attribute:"solution", value:
"Update the affected podman and / or podman-remote packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9341");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-27144");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'podman-4.9.5-150300.9.43.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'podman-remote-4.9.5-150300.9.43.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'podman-4.9.5-150300.9.43.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'podman-4.9.5-150300.9.43.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'podman-remote-4.9.5-150300.9.43.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'podman-remote-4.9.5-150300.9.43.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'podman-4.9.5-150300.9.43.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'podman-remote-4.9.5-150300.9.43.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'podman / podman-remote');
}
