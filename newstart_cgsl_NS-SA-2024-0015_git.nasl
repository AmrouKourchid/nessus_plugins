#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0015. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193535);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id(
    "CVE-2022-23521",
    "CVE-2022-41903",
    "CVE-2023-25652",
    "CVE-2023-29007"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : git Multiple Vulnerabilities (NS-SA-2024-0015)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has git packages installed that are affected by
multiple vulnerabilities:

  - Git is distributed revision control system. gitattributes are a mechanism to allow defining attributes for
    paths. These attributes can be defined by adding a `.gitattributes` file to the repository, which contains
    a set of file patterns and the attributes that should be set for paths matching this pattern. When parsing
    gitattributes, multiple integer overflows can occur when there is a huge number of path patterns, a huge
    number of attributes for a single pattern, or when the declared attribute names are huge. These overflows
    can be triggered via a crafted `.gitattributes` file that may be part of the commit history. Git silently
    splits lines longer than 2KB when parsing gitattributes from a file, but not when parsing them from the
    index. Consequentially, the failure mode depends on whether the file exists in the working tree, the index
    or both. This integer overflow can result in arbitrary heap reads and writes, which may result in remote
    code execution. The problem has been patched in the versions published on 2023-01-17, going back to
    v2.30.7. Users are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-23521)

  - Git is distributed revision control system. `git log` can display commits in an arbitrary format using its
    `--format` specifiers. This functionality is also exposed to `git archive` via the `export-subst`
    gitattribute. When processing the padding operators, there is a integer overflow in
    `pretty.c::format_and_pad_commit()` where a `size_t` is stored improperly as an `int`, and then added as
    an offset to a `memcpy()`. This overflow can be triggered directly by a user running a command which
    invokes the commit formatting machinery (e.g., `git log --format=...`). It may also be triggered
    indirectly through git archive via the export-subst mechanism, which expands format specifiers inside of
    files within the repository during a git archive. This integer overflow can result in arbitrary heap
    writes, which may result in arbitrary code execution. The problem has been patched in the versions
    published on 2023-01-17, going back to v2.30.7. Users are advised to upgrade. Users who are unable to
    upgrade should disable `git archive` in untrusted repositories. If you expose git archive via `git
    daemon`, disable it by running `git config --global daemon.uploadArch false`. (CVE-2022-41903)

  - Git is a revision control system. Prior to versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8,
    2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1, by feeding specially crafted input to `git apply --reject`, a
    path outside the working tree can be overwritten with partially controlled contents (corresponding to the
    rejected hunk(s) from the given patch). A fix is available in versions 2.30.9, 2.31.8, 2.32.7, 2.33.8,
    2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1. As a workaround, avoid using `git apply` with
    `--reject` when applying patches from an untrusted source. Use `git apply --stat` to inspect a patch
    before applying; avoid applying one that create a conflict where a link corresponding to the `*.rej` file
    exists. (CVE-2023-25652)

  - Git is a revision control system. Prior to versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8,
    2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1, a specially crafted `.gitmodules` file with submodule URLs
    that are longer than 1024 characters can used to exploit a bug in
    `config.c::git_config_copy_or_rename_section_in_file()`. This bug can be used to inject arbitrary
    configuration into a user's `$GIT_DIR/config` when attempting to remove the configuration section
    associated with that submodule. When the attacker injects configuration values which specify executables
    to run (such as `core.pager`, `core.editor`, `core.sshCommand`, etc.) this can lead to a remote code
    execution. A fix A fix is available in versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8, 2.36.6,
    2.37.7, 2.38.5, 2.39.3, and 2.40.1. As a workaround, avoid running `git submodule deinit` on untrusted
    repositories or without prior inspection of any submodule sections in `$GIT_DIR/config`. (CVE-2023-29007)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0015");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-23521");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-41903");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-25652");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-29007");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL git packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41903");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-instaweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'emacs-git-1.8.3.1-25.el7_9',
    'emacs-git-el-1.8.3.1-25.el7_9',
    'git-1.8.3.1-25.el7_9',
    'git-all-1.8.3.1-25.el7_9',
    'git-bzr-1.8.3.1-25.el7_9',
    'git-cvs-1.8.3.1-25.el7_9',
    'git-daemon-1.8.3.1-25.el7_9',
    'git-debuginfo-1.8.3.1-25.el7_9',
    'git-email-1.8.3.1-25.el7_9',
    'git-gnome-keyring-1.8.3.1-25.el7_9',
    'git-gui-1.8.3.1-25.el7_9',
    'git-hg-1.8.3.1-25.el7_9',
    'git-instaweb-1.8.3.1-25.el7_9',
    'git-p4-1.8.3.1-25.el7_9',
    'git-svn-1.8.3.1-25.el7_9',
    'gitk-1.8.3.1-25.el7_9',
    'gitweb-1.8.3.1-25.el7_9',
    'perl-Git-1.8.3.1-25.el7_9',
    'perl-Git-SVN-1.8.3.1-25.el7_9'
  ],
  'CGSL MAIN 5.04': [
    'emacs-git-1.8.3.1-25.el7_9',
    'emacs-git-el-1.8.3.1-25.el7_9',
    'git-1.8.3.1-25.el7_9',
    'git-all-1.8.3.1-25.el7_9',
    'git-bzr-1.8.3.1-25.el7_9',
    'git-cvs-1.8.3.1-25.el7_9',
    'git-daemon-1.8.3.1-25.el7_9',
    'git-debuginfo-1.8.3.1-25.el7_9',
    'git-email-1.8.3.1-25.el7_9',
    'git-gnome-keyring-1.8.3.1-25.el7_9',
    'git-gui-1.8.3.1-25.el7_9',
    'git-hg-1.8.3.1-25.el7_9',
    'git-instaweb-1.8.3.1-25.el7_9',
    'git-p4-1.8.3.1-25.el7_9',
    'git-svn-1.8.3.1-25.el7_9',
    'gitk-1.8.3.1-25.el7_9',
    'gitweb-1.8.3.1-25.el7_9',
    'perl-Git-1.8.3.1-25.el7_9',
    'perl-Git-SVN-1.8.3.1-25.el7_9'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'git');
}
