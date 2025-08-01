#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0531-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158221);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id(
    "CVE-2021-3807",
    "CVE-2021-3918",
    "CVE-2021-23343",
    "CVE-2021-32803",
    "CVE-2021-32804"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0531-1");

  script_name(english:"SUSE SLES12 Security Update : nodejs12 (SUSE-SU-2022:0531-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0531-1 advisory.

  - All versions of package path-parse are vulnerable to Regular Expression Denial of Service (ReDoS) via
    splitDeviceRe, splitTailRe, and splitPathRe regular expressions. ReDoS exhibits polynomial worst-case time
    complexity. (CVE-2021-23343)

  - The npm package tar (aka node-tar) before versions 6.1.2, 5.0.7, 4.4.15, and 3.2.3 has an arbitrary File
    Creation/Overwrite vulnerability via insufficient symlink protection. `node-tar` aims to guarantee that
    any file whose location would be modified by a symbolic link is not extracted. This is, in part, achieved
    by ensuring that extracted directories are not symlinks. Additionally, in order to prevent unnecessary
    `stat` calls to determine whether a given path is a directory, paths are cached when directories are
    created. This logic was insufficient when extracting tar files that contained both a directory and a
    symlink with the same name as the directory. This order of operations resulted in the directory being
    created and added to the `node-tar` directory cache. When a directory is present in the directory cache,
    subsequent calls to mkdir for that directory are skipped. However, this is also where `node-tar` checks
    for symlinks occur. By first creating a directory, and then replacing that directory with a symlink, it
    was thus possible to bypass `node-tar` symlink checks on directories, essentially allowing an untrusted
    tar file to symlink into an arbitrary location and subsequently extracting arbitrary files into that
    location, thus allowing arbitrary file creation and overwrite. This issue was addressed in releases 3.2.3,
    4.4.15, 5.0.7 and 6.1.2. (CVE-2021-32803)

  - The npm package tar (aka node-tar) before versions 6.1.1, 5.0.6, 4.4.14, and 3.3.2 has a arbitrary File
    Creation/Overwrite vulnerability due to insufficient absolute path sanitization. node-tar aims to prevent
    extraction of absolute file paths by turning absolute paths into relative paths when the `preservePaths`
    flag is not set to `true`. This is achieved by stripping the absolute path root from any absolute file
    paths contained in a tar file. For example `/home/user/.bashrc` would turn into `home/user/.bashrc`. This
    logic was insufficient when file paths contained repeated path roots such as `////home/user/.bashrc`.
    `node-tar` would only strip a single path root from such paths. When given an absolute file path with
    repeating path roots, the resulting path (e.g. `///home/user/.bashrc`) would still resolve to an absolute
    path, thus allowing arbitrary file creation and overwrite. This issue was addressed in releases 3.2.2,
    4.4.14, 5.0.6 and 6.1.1. Users may work around this vulnerability without upgrading by creating a custom
    `onentry` method which sanitizes the `entry.path` or a `filter` method which removes entries with absolute
    paths. See referenced GitHub Advisory for details. Be aware of CVE-2021-32803 which fixes a similar bug in
    later versions of tar. (CVE-2021-32804)

  - ansi-regex is vulnerable to Inefficient Regular Expression Complexity (CVE-2021-3807)

  - json-schema is vulnerable to Improperly Controlled Modification of Object Prototype Attributes ('Prototype
    Pollution') (CVE-2021-3918)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3918");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-February/010279.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebcc18fb");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs12, nodejs12-devel, nodejs12-docs and / or npm12 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3918");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP0/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'nodejs12-12.22.10-1.42.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-12.22.10-1.42.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-12.22.10-1.42.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-12.22.10-1.42.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-devel-12.22.10-1.42.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-devel-12.22.10-1.42.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-devel-12.22.10-1.42.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-devel-12.22.10-1.42.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-docs-12.22.10-1.42.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-docs-12.22.10-1.42.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-docs-12.22.10-1.42.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs12-docs-12.22.10-1.42.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'npm12-12.22.10-1.42.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'npm12-12.22.10-1.42.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'npm12-12.22.10-1.42.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'npm12-12.22.10-1.42.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs12 / nodejs12-devel / nodejs12-docs / npm12');
}
