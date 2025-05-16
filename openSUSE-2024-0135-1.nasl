#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0135-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197717);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/23");

  script_cve_id("CVE-2023-48795");
  script_xref(name:"IAVA", value:"2024-A-0236");

  script_name(english:"openSUSE 15 Security Update : gitui (openSUSE-SU-2024:0135-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by a vulnerability as referenced in the openSUSE-
SU-2024:0135-1 advisory.

    - update to version 0.26.2:
      * respect configuration for remote when fetching (also applies
        to pulling)
      * add : character to sign-off trailer to comply with Conventional
        Commits standard
      * support overriding build_date for reproducible builds
    - update vendored dependencies for CVE-2023-48795 (boo#1218264)

    - Update to version 0.26.1:
      Added:
      * sign commits using openpgp
      * support ssh commit signing (when user.signingKey and gpg.format
        = ssh of gitconfig are set; ssh-agent isn't yet supported)
      * provide nightly builds (see NIGHTLIES.md)
      * more version info in gitui -V and help popup (including git
        hash)
      * support core.commitChar filtering
      * allow reset in branch popup
      * respect configuration for remote when pushing
      Changed:
      * Make info and error message popups scrollable
      * clarify x86_64 linux binary in artifact names:
        gitui-linux-x86_64.tar.gz (formerly known as musl)
      Fixes:
      * add syntax highlighting support for more file types, e.g.
        Typescript, TOML, etc.

    - Update to version 0.25.1:
      Added:
      * support for new-line in text-input (e.g. commit message editor)
      * add syntax highlighting for blame view
      * allow aborting pending commit log search
      * theme.ron now supports customizing line break symbol
      * add confirmation for dialog for undo commit
      * support prepare-commit-msg hook
      * new style block_title_focused to allow customizing title text
        of focused frame/block
      * allow fetch command in both tabs of branchlist popup
      * check branch name validity while typing
      Changed:
      * do not allow tagging when tag.gpgsign enabled until gpg-signing
        is supported
      Fixes:
      * bump yanked dependency bumpalo to fix build from source
      * pin ratatui version to fix building without locked cargo
        install gitui
      * stash window empty after file history popup closes
      * allow push to empty remote
      * better diagnostics for theme file loading
      * fix ordering of commits in diff view

    - Update to version 0.24.3:
      * log: fix major lag when going beyond last search hit
      * parallelise log search - performance gain ~100%
      * search message body/summary separately
      * fix commit log not updating after branch switch
      * fix stashlist not updating after pop/drop
      * fix commit log corruption when tabbing in/out while parsing log
      * fix performance problem in big repo with a lot of incoming commits
      * fix error switching to a branch with '/' in the name
      * search commits by message, author or files in diff
      * support 'n'/'p' key to move to the next/prev hunk in diff component
      * simplify theme overrides
      * support for sign-off of commits
      * switched from textwrap to bwrap for text wrapping
      * more logging diagnostics when a repo cannot be
      * added to anaconda
      * visualize empty line substituted with content in diff better
      * checkout branch works with non-empty status report
      * jump to commit by SHA
      * fix commit dialog char count for multibyte characters
      * fix wrong hit highlighting in fuzzy find popup
      * fix symlink support for configuration files
      * fix expansion of ~ in commit.template
      * fix hunk (un)staging/reset for # of context lines != 3
      * fix delay when opening external editor

    - Update to version 0.23.0
      - Breaking Change
        * focus_XYZ key bindings are merged into the move_XYZ set, so only one way to bind arrow-like keys
    from now on
      - Added
        * allow reset (soft,mixed,hard) from commit log
        * support reword of commit from log
        * fuzzy find branch
        * list changes in commit message inside external editor
        * allow detaching HEAD and checking out specific commit from log view
        * add no-verify option on commits to not run hooks
        * allow fetch on status tab
        * allow copy file path on revision files and status tree
        * print message of where log will be written if -l is set
        * show remote branches in log
      - Fixes
        * fixed side effect of crossterm 0.26 on windows that caused double input of all keys
        * commit msg history ordered the wrong way
        * improve help documentation for amend cmd
        * lag issue when showing files tab
        * fix key binding shown in bottom bar for stash_open
        * --bugreport does not require param
        * edit-file command shown on commits msg
        * crash on branches popup in small terminal
        * edit command duplication
        * syntax errors in key_bindings.ron will be logged
        * Fix UI freeze when copying with xclip installed on Linux
        * Fix UI freeze when copying with wl-copy installed on Linux
        * commit hooks report 'command not found' on Windows with wsl2 installed
        * crashes on entering submodules
        * fix race issue: revlog messages sometimes appear empty
        * default to tick-based updates
        * add support for options handling in log and stashes views
      - Changed
        * minimum supported rust version bumped to 1.65 (thank you time crate)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218264");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NJ4UKYMVT5L6QOJVM6JMV6AQINAVT4JW/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13d4b571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48795");
  script_set_attribute(attribute:"solution", value:
"Update the affected gitui package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gitui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'gitui-0.26.2-bp155.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gitui');
}
