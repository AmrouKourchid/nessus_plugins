#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4205-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212321);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2024-41110");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4205-1");

  script_name(english:"SUSE SLES12 Security Update : docker-stable (SUSE-SU-2024:4205-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2024:4205-1 advisory.

    - Remove DOCKER_NETWORK_OPTS from docker.service. This was removed from
      sysconfig a long time ago, and apparently this causes issues with systemd in
      some cases.
    - Update --add-runtime to point to correct binary path.

    - Further merge docker and docker-stable specfiles to minimise the differences.
      The main thing is that we now include both halves of the
      Conflicts/Provides/Obsoletes dance in both specfiles.

    - Update to docker-buildx v0.17.1 to match standalone docker-buildx package we
      are replacing. See upstream changelog online at
      <https://github.com/docker/buildx/releases/tag/v0.17.1>

    - Allow users to disable SUSE secrets support by setting
      DOCKER_SUSE_SECRETS_ENABLE=0 in /etc/sysconfig/docker. bsc#1231348

    - Import specfile changes for docker-buildx as well as the changes to help
      reduce specfile differences between docker-stable and docker. bsc#1230331
      bsc#1230333

    - Backport patch for CVE-2024-41110. bsc#1228324

    - Initial docker-stable release, forked from Docker 24.0.6-ce release
      (packaged on 2023-10-11).

    - Update to Docker 24.0.9-ce, which is the latest version of the 24.0.x branch.
      It seems likely this will be the last upstream version of the 24.0.x branch
      (it seems Mirantis is going to do LTS for 23.0.x, not 24.0.x).
      <https://docs.docker.com/engine/release-notes/24.0/#2409>
    - Fix BuildKit's symlink resolution logic to correctly handle non-lexical
      symlinks. Backport of <https://github.com/moby/buildkit/pull/4896> and
      <https://github.com/moby/buildkit/pull/5060>. bsc#1221916
    - Write volume options atomically so sudden system crashes won't result in
      future Docker starts failing due to empty files. Backport of
      <https://github.com/moby/moby/pull/48034>. bsc#1214855

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231348");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/019929.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?817ff7e7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41110");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker-stable and / or docker-stable-bash-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41110");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-stable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-stable-bash-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'docker-stable-24.0.9_ce-1.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'docker-stable-bash-completion-24.0.9_ce-1.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'docker-stable-24.0.9_ce-1.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'docker-stable-bash-completion-24.0.9_ce-1.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'docker-stable / docker-stable-bash-completion');
}
