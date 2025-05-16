#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205237);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/08");

  script_cve_id(
    "CVE-2024-32002",
    "CVE-2024-32004",
    "CVE-2024-32020",
    "CVE-2024-32021",
    "CVE-2024-32465"
  );

  script_name(english:"EulerOS 2.0 SP11 : git (EulerOS-SA-2024-2098)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the git packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

    Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and
    2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be
    fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows
    writing a hook that will be executed while the clone operation is still running, giving the user no
    opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1,
    2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via
    `git config --global core.symlinks false`), the described attack won't work. As always, it is best to
    avoid cloning repositories from untrusted sources.(CVE-2024-32002)

    Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and
    2.39.4, local clones may end up hardlinking files into the target repository's object database when source
    and target repository reside on the same disk. If the source repository is owned by a different user, then
    those hardlinked files may be rewritten at any point in time by the untrusted user. Cloning local
    repositories will cause Git to either copy or hardlink files of the source repository into the target
    repository. This significantly speeds up such local clones compared to doing a 'proper' clone and saves
    both disk space and compute time. When cloning a repository located on the same disk that is owned by a
    different user than the current user we also end up creating such hardlinks. These files will continue to
    be owned and controlled by the potentially-untrusted user and can be rewritten by them at will in the
    future. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and
    2.39.4.(CVE-2024-32020)

    Git is a revision control system. The Git project recommends to avoid working in untrusted repositories,
    and instead to clone it first with `git clone --no-local` to obtain a clean copy. Git has specific
    protections to make that a safe operation even with an untrusted source repository, but vulnerabilities
    allow those protections to be bypassed. In the context of cloning local repositories owned by other users,
    this vulnerability has been covered in CVE-2024-32004. But there are circumstances where the fixes for
    CVE-2024-32004 are not enough: For example, when obtaining a `.zip` file containing a full copy of a Git
    repository, it should not be trusted by default to be safe, as e.g. hooks could be configured to run
    within the context of that repository. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4,
    2.42.2, 2.41.1, 2.40.2, and 2.39.4. As a workaround, avoid using Git in repositories that have been
    obtained via archives from untrusted sources.(CVE-2024-32465)

    Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and
    2.39.4, an attacker can prepare a local repository in such a way that, when cloned, will execute arbitrary
    code during the operation. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2,
    2.41.1, 2.40.2, and 2.39.4. As a workaround, avoid cloning repositories from untrusted
    sources.(CVE-2024-32004)

    Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and
    2.39.4, when cloning a local source repository that contains symlinks via the filesystem, Git may create
    hardlinks to arbitrary user-readable files on the same filesystem as the target repository in the
    `objects/` directory. Cloning a local repository over the filesystem may creating hardlinks to arbitrary
    user-owned files on the same filesystem in the target Git repository's `objects/` directory. When cloning
    a repository over the filesystem (without explicitly specifying the `file://` protocol or `--no-local`),
    the optimizations for local cloning will be used, which include attempting to hard link the object files
    instead of copying them. While the code includes checks against symbolic links in the source repository,
    which were added during the fix for CVE-2022-39253, these checks can still be raced because the hard link
    operation ultimately follows symlinks. If the object on the filesystem appears as a file during the check,
    and then a symlink during the operation, this will allow the adversary to bypass the check and create
    hardlinks in the destination objects directory to arbitrary, user-readable files. The problem has been
    patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4.(CVE-2024-32021)

Tenable has extracted the preceding description block directly from the EulerOS git security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d25e9889");
  script_set_attribute(attribute:"solution", value:
"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:git-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "git-2.33.0-1.h13.eulerosv2r11",
  "git-help-2.33.0-1.h13.eulerosv2r11",
  "perl-Git-2.33.0-1.h13.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git");
}
