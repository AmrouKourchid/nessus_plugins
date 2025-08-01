#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3886-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155834);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id(
    "CVE-2021-22959",
    "CVE-2021-22960",
    "CVE-2021-37701",
    "CVE-2021-37712",
    "CVE-2021-37713",
    "CVE-2021-39134",
    "CVE-2021-39135"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3886-1");

  script_name(english:"SUSE SLES12 Security Update : nodejs14 (SUSE-SU-2021:3886-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3886-1 advisory.

  - The parser in accepts requests with a space (SP) right after the header name before the colon. This can
    lead to HTTP Request Smuggling (HRS) in llhttp < v2.1.4 and < v6.0.6. (CVE-2021-22959)

  - The parse function in llhttp < 2.1.4 and < 6.0.6. ignores chunk extensions when parsing the body of
    chunked requests. This leads to HTTP Request Smuggling (HRS) under certain conditions. (CVE-2021-22960)

  - The npm package tar (aka node-tar) before versions 4.4.16, 5.0.8, and 6.1.7 has an arbitrary file
    creation/overwrite and arbitrary code execution vulnerability. node-tar aims to guarantee that any file
    whose location would be modified by a symbolic link is not extracted. This is, in part, achieved by
    ensuring that extracted directories are not symlinks. Additionally, in order to prevent unnecessary stat
    calls to determine whether a given path is a directory, paths are cached when directories are created.
    This logic was insufficient when extracting tar files that contained both a directory and a symlink with
    the same name as the directory, where the symlink and directory names in the archive entry used
    backslashes as a path separator on posix systems. The cache checking logic used both `\` and `/`
    characters as path separators, however `\` is a valid filename character on posix systems. By first
    creating a directory, and then replacing that directory with a symlink, it was thus possible to bypass
    node-tar symlink checks on directories, essentially allowing an untrusted tar file to symlink into an
    arbitrary location and subsequently extracting arbitrary files into that location, thus allowing arbitrary
    file creation and overwrite. Additionally, a similar confusion could arise on case-insensitive
    filesystems. If a tar archive contained a directory at `FOO`, followed by a symbolic link named `foo`,
    then on case-insensitive file systems, the creation of the symbolic link would remove the directory from
    the filesystem, but _not_ from the internal directory cache, as it would not be treated as a cache hit. A
    subsequent file entry within the `FOO` directory would then be placed in the target of the symbolic link,
    thinking that the directory had already been created. These issues were addressed in releases 4.4.16,
    5.0.8 and 6.1.7. The v3 branch of node-tar has been deprecated and did not receive patches for these
    issues. If you are still using a v3 release we recommend you update to a more recent version of node-tar.
    If this is not possible, a workaround is available in the referenced GHSA-9r2w-394v-53qc. (CVE-2021-37701)

  - The npm package tar (aka node-tar) before versions 4.4.18, 5.0.10, and 6.1.9 has an arbitrary file
    creation/overwrite and arbitrary code execution vulnerability. node-tar aims to guarantee that any file
    whose location would be modified by a symbolic link is not extracted. This is, in part, achieved by
    ensuring that extracted directories are not symlinks. Additionally, in order to prevent unnecessary stat
    calls to determine whether a given path is a directory, paths are cached when directories are created.
    This logic was insufficient when extracting tar files that contained both a directory and a symlink with
    names containing unicode values that normalized to the same value. Additionally, on Windows systems, long
    path portions would resolve to the same file system entities as their 8.3 short path counterparts. A
    specially crafted tar archive could thus include a directory with one form of the path, followed by a
    symbolic link with a different string that resolves to the same file system entity, followed by a file
    using the first form. By first creating a directory, and then replacing that directory with a symlink that
    had a different apparent name that resolved to the same entry in the filesystem, it was thus possible to
    bypass node-tar symlink checks on directories, essentially allowing an untrusted tar file to symlink into
    an arbitrary location and subsequently extracting arbitrary files into that location, thus allowing
    arbitrary file creation and overwrite. These issues were addressed in releases 4.4.18, 5.0.10 and 6.1.9.
    The v3 branch of node-tar has been deprecated and did not receive patches for these issues. If you are
    still using a v3 release we recommend you update to a more recent version of node-tar. If this is not
    possible, a workaround is available in the referenced GHSA-qq89-hq3f-393p. (CVE-2021-37712)

  - The npm package tar (aka node-tar) before versions 4.4.18, 5.0.10, and 6.1.9 has an arbitrary file
    creation/overwrite and arbitrary code execution vulnerability. node-tar aims to guarantee that any file
    whose location would be outside of the extraction target directory is not extracted. This is, in part,
    accomplished by sanitizing absolute paths of entries within the archive, skipping archive entries that
    contain `..` path portions, and resolving the sanitized paths against the extraction target directory.
    This logic was insufficient on Windows systems when extracting tar files that contained a path that was
    not an absolute path, but specified a drive letter different from the extraction target, such as
    `C:some\path`. If the drive letter does not match the extraction target, for example `D:\extraction\dir`,
    then the result of `path.resolve(extractionDirectory, entryPath)` would resolve against the current
    working directory on the `C:` drive, rather than the extraction target directory. Additionally, a `..`
    portion of the path could occur immediately after the drive letter, such as `C:../foo`, and was not
    properly sanitized by the logic that checked for `..` within the normalized and split portions of the
    path. This only affects users of `node-tar` on Windows systems. These issues were addressed in releases
    4.4.18, 5.0.10 and 6.1.9. The v3 branch of node-tar has been deprecated and did not receive patches for
    these issues. If you are still using a v3 release we recommend you update to a more recent version of
    node-tar. There is no reasonable way to work around this issue without performing the same path
    normalization procedures that node-tar now does. Users are encouraged to upgrade to the latest patched
    versions of node-tar, rather than attempt to sanitize paths themselves. (CVE-2021-37713)

  - `@npmcli/arborist`, the library that calculates dependency trees and manages the `node_modules` folder
    hierarchy for the npm command line interface, aims to guarantee that package dependency contracts will be
    met, and the extraction of package contents will always be performed into the expected folder. This is, in
    part, accomplished by resolving dependency specifiers defined in `package.json` manifests for dependencies
    with a specific name, and nesting folders to resolve conflicting dependencies. When multiple dependencies
    differ only in the case of their name, Arborist's internal data structure saw them as separate items that
    could coexist within the same level in the `node_modules` hierarchy. However, on case-insensitive file
    systems (such as macOS and Windows), this is not the case. Combined with a symlink dependency such as
    `file:/some/path`, this allowed an attacker to create a situation in which arbitrary contents could be
    written to any location on the filesystem. For example, a package `pwn-a` could define a dependency in
    their `package.json` file such as `foo: file:/some/path`. Another package, `pwn-b` could define a
    dependency such as `FOO: file:foo.tgz`. On case-insensitive file systems, if `pwn-a` was installed, and
    then `pwn-b` was installed afterwards, the contents of `foo.tgz` would be written to `/some/path`, and any
    existing contents of `/some/path` would be removed. Anyone using npm v7.20.6 or earlier on a case-
    insensitive filesystem is potentially affected. This is patched in @npmcli/arborist 2.8.2 which is
    included in npm v7.20.7 and above. (CVE-2021-39134)

  - `@npmcli/arborist`, the library that calculates dependency trees and manages the node_modules folder
    hierarchy for the npm command line interface, aims to guarantee that package dependency contracts will be
    met, and the extraction of package contents will always be performed into the expected folder. This is
    accomplished by extracting package contents into a project's `node_modules` folder. If the `node_modules`
    folder of the root project or any of its dependencies is somehow replaced with a symbolic link, it could
    allow Arborist to write package dependencies to any arbitrary location on the file system. Note that
    symbolic links contained within package artifact contents are filtered out, so another means of creating a
    `node_modules` symbolic link would have to be employed. 1. A `preinstall` script could replace
    `node_modules` with a symlink. (This is prevented by using `--ignore-scripts`.) 2. An attacker could
    supply the target with a git repository, instructing them to run `npm install --ignore-scripts` in the
    root. This may be successful, because `npm install --ignore-scripts` is typically not capable of making
    changes outside of the project directory, so it may be deemed safe. This is patched in @npmcli/arborist
    2.8.2 which is included in npm v7.20.7 and above. For more information including workarounds please see
    the referenced GHSA-gmw6-94gg-2rc2. (CVE-2021-39135)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39135");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009816.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64718fc5");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs14, nodejs14-devel, nodejs14-docs and / or npm14 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22959");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37713");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs14-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'nodejs14-14.18.1-6.18.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-14.18.1-6.18.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-14.18.1-6.18.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-14.18.1-6.18.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-devel-14.18.1-6.18.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-devel-14.18.1-6.18.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-devel-14.18.1-6.18.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-devel-14.18.1-6.18.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-docs-14.18.1-6.18.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-docs-14.18.1-6.18.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-docs-14.18.1-6.18.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'nodejs14-docs-14.18.1-6.18.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'npm14-14.18.1-6.18.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'npm14-14.18.1-6.18.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'npm14-14.18.1-6.18.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']},
    {'reference':'npm14-14.18.1-6.18.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-web-scripting-release-12-0']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs14 / nodejs14-devel / nodejs14-docs / npm14');
}
