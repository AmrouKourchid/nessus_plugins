#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4319-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213069);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id("CVE-2023-45142", "CVE-2023-47108", "CVE-2024-41110");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4319-1");
  script_xref(name:"IAVA", value:"2024-A-0438-S");

  script_name(english:"SUSE SLES12 Security Update : docker (SUSE-SU-2024:4319-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:4319-1 advisory.

    - Update docker-buildx to v0.19.2. See upstream changelog online at
      <https://github.com/docker/buildx/releases/tag/v0.19.2>.

      Some notable changelogs from the last update:
        * <https://github.com/docker/buildx/releases/tag/v0.19.0>
        * <https://github.com/docker/buildx/releases/tag/v0.18.0>

    - Add a new toggle file /etc/docker/suse-secrets-enable which allows users to
      disable the SUSEConnect integration with Docker (which creates special mounts
      in /run/secrets to allow container-suseconnect to authenticate containers
      with registries on registered hosts). bsc#1231348 bsc#1232999

      In order to disable these mounts, just do

        echo 0 > /etc/docker/suse-secrets-enable

      and restart Docker. In order to re-enable them, just do

        echo 1 > /etc/docker/suse-secrets-enable

      and restart Docker. Docker will output information on startup to tell you
      whether the SUSE secrets feature is enabled or not.

    - Disable docker-buildx builds for SLES. It turns out that build containers
      with docker-buildx don't currently get the SUSE secrets mounts applied,
      meaning that container-suseconnect doesn't work when building images.
      bsc#1233819

    - Remove DOCKER_NETWORK_OPTS from docker.service. This was removed from
      sysconfig a long time ago, and apparently this causes issues with systemd in
      some cases.

    - Allow a parallel docker-stable RPM to exists in repositories.

    - Update to docker-buildx v0.17.1 to match standalone docker-buildx package we
      are replacing. See upstream changelog online at
      <https://github.com/docker/buildx/releases/tag/v0.17.1>

    - Allow users to disable SUSE secrets support by setting
      DOCKER_SUSE_SECRETS_ENABLE=0 in /etc/sysconfig/docker. (bsc#1231348)

    - Mark docker-buildx as required since classic 'docker build' has been
      deprecated since Docker 23.0. (bsc#1230331)

    - Import docker-buildx v0.16.2 as a subpackage. Previously this was a separate
      package, but with docker-stable it will be necessary to maintain the packages
      together and it makes more sense to have them live in the same OBS package.
      (bsc#1230333)

    - Update to Docker 26.1.5-ce. See upstream changelog online at
      <https://docs.docker.com/engine/release-notes/26.1/#2615>
      bsc#1230294

    - This update includes fixes for:
      * CVE-2024-41110. bsc#1228324
      * CVE-2023-47108. bsc#1217070 bsc#1229806
      * CVE-2023-45142. bsc#1228553 bsc#1229806

    - Update to Docker 26.1.4-ce. See upstream changelog online at
      <https://docs.docker.com/engine/release-notes/26.1/#2614>

    - Update to Docker 26.1.0-ce. See upstream changelog online at
      <https://docs.docker.com/engine/release-notes/26.1/#2610>

    - Update --add-runtime to point to correct binary path.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233819");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/020003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80080c38");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41110");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker and / or docker-bash-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47108");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'docker-26.1.5_ce-98.120.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'docker-bash-completion-26.1.5_ce-98.120.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'docker-26.1.5_ce-98.120.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'docker-bash-completion-26.1.5_ce-98.120.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'docker / docker-bash-completion');
}
