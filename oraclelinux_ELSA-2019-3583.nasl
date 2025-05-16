#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-3583.
##

include('compat.inc');

if (description)
{
  script_id(180746);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2018-20534", "CVE-2019-3817");

  script_name(english:"Oracle Linux 8 : yum (ELSA-2019-3583)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-3583 advisory.

    createrepo_c
    [0.11.0-3]
    - Backport patch to switch off timestamps on documentation in order to remove
      file conflicts (RhBug:1738788)

    [0.11.0-2]
    - Consistently produce valid URLs by prepending protocol. (RhBug:1632121)
    - modifyrepo_c: Prevent doubling of compression (test.gz.gz) (RhBug:1639287)
    - Correct pkg count in headers if there were invalid pkgs (RhBug:1596211)
    - Add support for modular errata (RhBug:1656584)

    dnf
    [4.2.7-6]
    - Remove patch to not fail when installing modular RPMs without modular metadata

    [4.2.7-5]
    - Fix: --setopt and repo with dots (RhBug:1746349)

    [4.2.7-4]
    - Prevent printing empty Error Summary (RhBug:1690414)

    [4.2.7-3]
    - Update localizations from zanata (RhBug:1689982)
    - Accept multiple specs in repoquery options (RhBug:1667898,1656801)
    - Prevent switching modules in all cases (RhBug:1706215)
    - Change synchronization of rpm transaction to swdb (RhBug:1737328)
    - Print rpm error messages during transaction (RhBug:1677199)
    - Report missing default profile as an error (RhBug:1669527,1724564)
    - Describe a behavior when plugin is removed (RhBug:1700741)

    [4.2.7-2]
    - Add patch to not fail when installing modular RPMs without modular metadata

    [4.2.7-1]
    - Update to 4.2.7
    - Fix package reinstalls during yum module remove (RhBug:1700529)
    - Fail when '-c' option is given nonexistent file (RhBug:1512457)
    - Reuse empty lock file instead of stopping dnf (RhBug:1581824)
    - Propagate comps 'default' value correctly (RhBug:1674562)
    - Better search of provides in /(s)bin/ (RhBug:1657993)
    - Add detection for armv7hcnl (RhBug:1691430)
    - Fix group install/upgrade when group is not available (RhBug:1707624)
    - Report not matching plugins when using --enableplugin/--disableplugin
      (RhBug:1673289) (RhBug:1467304)
    - Add support of modular FailSafe (RhBug:1623128)
    - Replace logrotate with build-in log rotation for dnf.log and dnf.rpm.log
      (RhBug:1702690)

    [4.2.6-1]
    - Update to 4.2.6
    - Use improved config parser that preserves order of data
    - Follow RPM security policy for package verification
    - Update modules regardless of installed profiles
    - [conf] Use environment variables prefixed with DNF_VAR_
    - Allow adjustment of repo from --repofrompath (RhBug:1689591)
    - Allow globs in setopt in repoid part
    - Add command abbreviations (RhBug:1634232)
    - Installroot now requires absolute path
    - librepo: Turn on debug logging only if debuglevel is greater than 2 (RhBug:1355764,1580022)
    - Document cachedir option (RhBug:1691365)
    - Enhance documentation - API examples
    - Enhance documentation of --whatdepends option (RhBug:1687070)
    - Update documentation: implemented plugins; options; deprecated commands (RhBug:1670835,1673278)
    - [doc] Add info of relation update_cache with fill_sack (RhBug:1658694)
    - Rename man page from dnf.automatic to dnf-automatic to match command name
    - Fix alias list command (RhBug:1666325)
    - Fix behavior  of --bz option when specifying more values
    - Add protection of yum package (RhBug:1639363)
    - Fix list --showduplicates (RhBug:1655605)
    - Retain order of headers in search results (RhBug:1613860)
    - Solve traceback with the 'dnf install @module' (RhBug:1688823)
    - Fix multilib obsoletes (RhBug:1672947)
    - Do not remove group package if other packages depend on it
    - Remove duplicates from 'dnf list' and 'dnf info' outputs
    - Fix the installation of completion_helper.py
    - Fix formatting of message about free space required
    - Fix installation failiure when duplicit RPMs are specified (RhBug:1687286)
    - Fix issues with terminal hangs when attempting bash completion (RhBug:1702854)
    - Allow plugins to terminate dnf (RhBug:1701807)
    - [provides] Enhanced detecting of file provides (RhBug:1702621)
    - [provides] Sort the output packages alphabetically

    [4.0.9.2-6]
    - Backport patch to unify --help with man for module-spec (RhBug:1678689)

    dnf-plugins-core
    [4.0.8-3]
    - Generate yum-utils(1) instead of symlinking (RhBug:1676418)

    [4.0.8-2]
    - Update localizations from zanata (RhBug:1689984)
    - Rename dnf-utils to yum-utils (RhBug:1722093)
    - [builddep] Report all rpm errors (RhBug:1724668)
    - [config-manager] Behaviour of --setopt (RhBug:1702678)

    [4.0.8-1]
    - Update to 4.0.8
    - [reposync] Enable timestamp preserving for downloaded data (RhBug:1688537)
    - [reposync] Download packages from all streams (RhBug:1714788)
    - Make yum-copr manpage available (RhBug:1673902)
    - [needs-restarting] Add --reboothint option (RhBug:1192946) (RhBug:1639468)
    - Set the cost of _dnf_local repo to 500, to make it preferred to normal
      repos

    [4.0.7-1]
    - Update to 4.0.7
    - Use improved config parser that preserves order of data
    - Fix: copr disable command traceback (RhBug:1693551)
    - [doc] state repoid as repo identifier of config-manager (RhBug:1686779)
    - [leaves] Show multiply satisfied dependencies as leaves
    - [download] Fix downloading an rpm from a URL (RhBug:1678582)
    - [download] Do not download src without --source (RhBug:1666648)
    - [download] Fix problem with downloading src pkgs (RhBug:1649627)
    - [download] Fix download of src when not the latest requested (RhBug:1649627)

    libcomps
    [0.1.11-2]
    - Backport patch: Fix order of asserts in unit test (RhBug:1713220)

    [0.1.11-1]
    - Update to 0.1.11

    libdnf
    [0.35.1-8.0.1]
    - Disable rhsm [Orabug: 29901202]
    - Replaced bugzilla.redhat.com with bugzilla.oracle.com in config [Orabug: 29656932]
    - Add support for apps that use libdnf to access yum url with 'ociregion' variable [Orabug: 30121584]
    (Frank Deng)

    [0.35.1-8]
    - Enhanced fix of moving directories in minimal container (RhBug:1700341)

    [0.35.1-7]
    - Remove patch to not fail when installing modular RPMs without modular metadata

    [0.35.1-6]
    - Fix moving directories in minimal container (RhBug:1700341)

    [0.35.1-5]
    - Add suport for query sequence conversions

    [0.35.1-4]
    - Fix typo in error message (RhBug:1726661)
    - Update localizations from zanata (RhBug:1689991)
    - Dont disable nonexistent but required repositories (RhBug:1689331)
    - Ignore trailing blank lines of multiline value (RhBug:1722493)
    - Re-size includes map before re-computation (RhBug:1725213)

    [0.35.1-3]
    - Fix attaching and detaching of libsolvRepo and repo_internalize_trigger()
      (RhBug:1730224)

    [0.35.1-2]
    - Add patch to not fail when installing modular RPMs without modular metadata

    [0.35.1-1]
    - Update to 0.35.1
    - Skip invalid key files in '/etc/pki/rpm-gpg' with warning (RhBug:1644040)
    - Enable timestamp preserving for downloaded data (RhBug:1688537)
    - Fix 'database is locked' error (RhBug:1631533)
    - Replace the 'Failed to synchronize cache' message (RhBug:1712055)
    - Fix 'no such table: main.trans_cmdline' error (RhBug:1596540)
    - Fix: skip_if_unavailable=true for local repositories (RhBug:1716313)
    - Add support of modular FailSafe (RhBug:1623128)
    - Add support of DNF main config file in context; used by PackageKit and
      microdnf (RhBug:1689331)
    - Exit gpg-agent after repokey import (RhBug:1650266)

    [0.33.0-1]
    - Update to 0.33.0
    - Enhance sorting for module list (RhBug:1590358)
    - [DnfRepo] Add methods for alternative repository metadata type and download (RhBug:1656314)
    - Remove installed profile on module enable or disable (RhBug:1653623)
    - Enhance modular solver to handle enabled and default module streams differently (RhBug:1648839)
    - Add support of wild cards for modules (RhBug:1644588)
    - Exclude module pkgs that have conflict
    - Enhance config parser to preserve order of data, and keep comments and format
    - Improve ARM detection
    - Add support for SHA-384
    - Return empty query if incorrect reldep (RhBug:1687135)
    - ConfigParser: Improve compatibility with Python ConfigParser and dnf-plugin-spacewalk (RhBug:1692044)
    - ConfigParser: Unify default set of string represenation of boolean values
    - Fix segfault when interrupting dnf process (RhBug:1610456)
    - Installroot now requires absolute path
    - Support '_none_' value for repo option 'proxy' (RhBug:1680272)
    - Add support for Module advisories
    - Add support for xml:base attribute from primary.xml (RhBug:1691315)
    - Improve detection of Platform ID (RhBug:1688462)

    [0.22.5-6]
    - Rebuild for libsolv soname bump (in libsolve update to 0.7.4)

    librepo
    [1.10.3-3]
    - Backport patch: Fix: Verification of checksum from file attr

    [1.10.3-2]
    - Backport patch: Define LRO_SUPPORTS_CACHEDIR only with zchunk (RhBug:1726141,1719830)

    [1.10.3-1]
    - Update to 1.10.3
    - Exit gpg-agent after repokey import (RhBug:1650266)

    [1.10.1-1]
    - Update to 1.10.1
    - Reduce download delays
    - Add an option to preserve timestamps of the downloaded files (RhBug:1688537)
    - Append the '?' part of repo URL after the path
    - Fix memory leaks

    librhsm
    [0.0.3-3]
    - Generate repofile for any architecture if 'ALL' is specified

    libsolv
    [0.7.4-3]
    - Backport patches: Use OpenSSL for computing hashes (RhBug:1630300)

    [0.7.4-2]
    - Backport patch: Not considered excluded packages as a best candidate (RhBug:1677583)

    [0.7.4-1]
    - soname bump to '1'
    - incompatible API changes:
      * bindings: Selection.flags is now an attribute
      * repodata_lookup_num now works like the other lookup_num functions
    - new functions:
      * selection_make_matchsolvable
      * selection_make_matchsolvablelist
      * pool_whatmatchessolvable
      * repodata_search_arrayelement
      * repodata_lookup_kv_uninternalized
      * repodata_search_uninternalized
      * repodata_translate_dir
    - new repowriter interface to write solv files allowing better
      control over what gets written
    - support for filtered file lists with a custom filter
    - dropped support of (since a long time unused) REPOKEY_TYPE_U32
    - selected bug fixes:
      * fix nasty off-by-one error in repo_write
      * do not autouninstall packages because of forcebest updates
      * fixed a couple of null pointer derefs and potential memory
        leaks
      * made disfavoring recommended packages work if strong recommends
        is enabled
      * no longer disable infarch rules when they dont conflict with
        the job
      * repo_add_rpmdb: do not copy bad solvables from the old solv file
      * fix cleandeps updates not updating all packages
    - new features:
      * support rpms new '^' version separator
      * support set/get_considered_list in bindings
      * new experimental SOLVER_FLAG_ONLY_NAMESPACE_RECOMMENDED flag
      * do favor evaluation before pruning allowing to (dis)favor
        specific package versions
      * bindings: support pool.matchsolvable(), pool.whatmatchessolvable()
        pool.best_solvables() and selection.matchsolvable()
      * experimental DISTTYPE_CONDA and REL_CONDA support

    microdnf
    [3.0.1-3]
    - Fix microdnf --help coredump (RhBug:1744979)

    [3.0.1-2]
    - Fix minor memory leaks (RhBug:1702283)
    - Use help2man to generate a man page (RhBug:1612520)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-3583.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3817");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:createrepo_c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:createrepo_c-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dnf-automatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dnf-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dnf-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcomps-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libdnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:librepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:librhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsolv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:microdnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-dnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-dnf-plugin-versionlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-dnf-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-hawkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-libdnf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-librepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:yum-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'createrepo_c-0.11.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'createrepo_c-devel-0.11.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'createrepo_c-libs-0.11.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-4.2.7-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-automatic-4.2.7-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-data-4.2.7-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-plugins-core-4.0.8-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcomps-0.1.11-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcomps-devel-0.1.11-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-0.35.1-8.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librepo-1.10.3-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librhsm-0.0.3-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsolv-0.7.4-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'microdnf-3.0.1-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-createrepo_c-0.11.0-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-4.2.7-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugin-versionlock-4.0.8-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugins-core-4.0.8-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hawkey-0.35.1-8.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libcomps-0.1.11-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libdnf-0.35.1-8.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-librepo-1.10.3-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-4.2.7-6.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-utils-4.0.8-3.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'createrepo_c-devel-0.11.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'createrepo_c-libs-0.11.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-4.2.7-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-automatic-4.2.7-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-data-4.2.7-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-plugins-core-4.0.8-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcomps-0.1.11-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcomps-devel-0.1.11-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-0.35.1-8.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librepo-1.10.3-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librhsm-0.0.3-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsolv-0.7.4-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'microdnf-3.0.1-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-createrepo_c-0.11.0-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-4.2.7-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugin-versionlock-4.0.8-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugins-core-4.0.8-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hawkey-0.35.1-8.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libcomps-0.1.11-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libdnf-0.35.1-8.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-librepo-1.10.3-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-4.2.7-6.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-utils-4.0.8-3.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'createrepo_c-0.11.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'createrepo_c-devel-0.11.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'createrepo_c-libs-0.11.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-4.2.7-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-automatic-4.2.7-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-data-4.2.7-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dnf-plugins-core-4.0.8-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcomps-0.1.11-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcomps-devel-0.1.11-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdnf-0.35.1-8.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librepo-1.10.3-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'librhsm-0.0.3-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsolv-0.7.4-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'microdnf-3.0.1-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-createrepo_c-0.11.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-4.2.7-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugin-versionlock-4.0.8-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-dnf-plugins-core-4.0.8-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-hawkey-0.35.1-8.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libcomps-0.1.11-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libdnf-0.35.1-8.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-librepo-1.10.3-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-4.2.7-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yum-utils-4.0.8-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'createrepo_c / createrepo_c-devel / createrepo_c-libs / etc');
}
