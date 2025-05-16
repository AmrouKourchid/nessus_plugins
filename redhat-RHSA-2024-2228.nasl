#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:2228. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194795);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2023-47038");
  script_xref(name:"RHSA", value:"2024:2228");

  script_name(english:"RHEL 9 : perl (RHSA-2024:2228)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for perl.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2024:2228 advisory.

    Perl is a high-level programming language that is commonly used for system administration utilities and
    web programming.

    Security Fix(es):

    * perl: Write past buffer end via illegal user-defined Unicode property (CVE-2023-47038)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 9.4 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_2228.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?507e1d1c");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/9.4_release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d922e0bf");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:2228");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249523");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL perl package based on the guidance in RHSA-2024:2228.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47038");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-AutoLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-AutoSplit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-B");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-Struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Config-Extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DBM_Filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DirHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Dumpvalue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DynaLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-English");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-ExtUtils-Constant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Fcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-File-Basename");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-File-Compare");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-File-Copy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-File-DosGlob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-File-Find");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-File-stat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-FileCache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-FileHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-FindBin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-GDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Getopt-Std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Hash-Util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Hash-Util-FieldHash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-I18N-Collate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-I18N-LangTags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-I18N-Langinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-IPC-Open3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NEXT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-ODBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Opcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-POSIX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Pod-Functions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Search-Dict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-SelectSaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Term-Complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Term-ReadLine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Text-Abbrev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Thread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Thread-Semaphore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Tie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Tie-File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Tie-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Unicode-UCD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-User-pwent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-autouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-blib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-deprecate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-diagnostics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-encoding-warnings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-fields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-filetest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-if");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-less");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-meta-notation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-mro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-overload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-overloading");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-ph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-sigtrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-sort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-subs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-vars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-vmsish");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/aarch64/appstream/debug',
      'content/dist/rhel9/9.1/aarch64/appstream/os',
      'content/dist/rhel9/9.1/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/appstream/debug',
      'content/dist/rhel9/9.1/ppc64le/appstream/os',
      'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/appstream/debug',
      'content/dist/rhel9/9.1/s390x/appstream/os',
      'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/appstream/debug',
      'content/dist/rhel9/9.1/x86_64/appstream/os',
      'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/appstream/debug',
      'content/dist/rhel9/9.2/aarch64/appstream/os',
      'content/dist/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/appstream/debug',
      'content/dist/rhel9/9.2/ppc64le/appstream/os',
      'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/appstream/debug',
      'content/dist/rhel9/9.2/s390x/appstream/os',
      'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/appstream/debug',
      'content/dist/rhel9/9.2/x86_64/appstream/os',
      'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/appstream/debug',
      'content/dist/rhel9/9.3/aarch64/appstream/os',
      'content/dist/rhel9/9.3/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/appstream/debug',
      'content/dist/rhel9/9.3/ppc64le/appstream/os',
      'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/appstream/debug',
      'content/dist/rhel9/9.3/s390x/appstream/os',
      'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/appstream/debug',
      'content/dist/rhel9/9.3/x86_64/appstream/os',
      'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/appstream/debug',
      'content/dist/rhel9/9.4/aarch64/appstream/os',
      'content/dist/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/appstream/debug',
      'content/dist/rhel9/9.4/ppc64le/appstream/os',
      'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/appstream/debug',
      'content/dist/rhel9/9.4/s390x/appstream/os',
      'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/appstream/debug',
      'content/dist/rhel9/9.4/x86_64/appstream/os',
      'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/appstream/debug',
      'content/dist/rhel9/9.5/aarch64/appstream/os',
      'content/dist/rhel9/9.5/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/appstream/debug',
      'content/dist/rhel9/9.5/ppc64le/appstream/os',
      'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/appstream/debug',
      'content/dist/rhel9/9.5/s390x/appstream/os',
      'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/appstream/debug',
      'content/dist/rhel9/9.5/x86_64/appstream/os',
      'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/aarch64/appstream/debug',
      'content/dist/rhel9/9/aarch64/appstream/os',
      'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/appstream/debug',
      'content/dist/rhel9/9/ppc64le/appstream/os',
      'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9/s390x/appstream/debug',
      'content/dist/rhel9/9/s390x/appstream/os',
      'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'perl-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Attribute-Handlers-1.01-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-AutoLoader-5.74-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-AutoSplit-5.74-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-autouse-1.11-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-B-1.80-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-base-2.27-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Benchmark-1.23-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-blib-1.07-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Class-Struct-0.66-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Config-Extensions-0.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DBM_Filter-0.06-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-debugger-1.56-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-deprecate-0.04-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-devel-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Devel-Peek-1.28-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-SelfStubber-1.06-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-diagnostics-1.37-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DirHandle-1.05-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-doc-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Dumpvalue-2.27-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DynaLoader-1.47-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-encoding-warnings-0.13-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-English-1.11-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Errno-1.30-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-Constant-0.25-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-Embed-1.35-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-Miniperl-1.09-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Fcntl-1.13-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-fields-2.27-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Basename-2.85-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Compare-1.100.600-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Copy-2.34-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-DosGlob-1.12-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Find-1.37-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-stat-1.09-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FileCache-1.10-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FileHandle-2.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-filetest-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FindBin-1.51-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-GDBM_File-1.18-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Getopt-Std-1.12-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Hash-Util-0.23-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Hash-Util-FieldHash-1.20-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-Collate-1.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-Langinfo-0.19-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-LangTags-0.44-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-if-0.60.800-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-interpreter-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-IO-1.43-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IPC-Open3-1.21-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-less-0.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-lib-0.65-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-libnetcfg-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-libs-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-locale-1.09-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Locale-Maketext-Simple-0.21-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-macros-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Math-Complex-1.59-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Memoize-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-meta-notation-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Module-Loaded-0.08-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-mro-1.23-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-NDBM_File-1.15-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Net-1.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-NEXT-0.67-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ODBM_File-1.16-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Opcode-1.48-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-open-1.12-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-overload-1.31-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-overloading-0.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ph-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Functions-1.13-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Html-1.25-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-POSIX-1.94-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Safe-2.41-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Search-Dict-1.07-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-SelectSaver-1.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-SelfLoader-1.26-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-sigtrap-1.09-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-sort-2.04-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-subs-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Symbol-1.08-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Hostname-1.23-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-Complete-1.403-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-ReadLine-1.17-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Test-1.31-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Abbrev-1.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Thread-3.05-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Thread-Semaphore-2.13-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-4.6-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-File-1.06-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-Memoize-1.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Time-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Time-Piece-1.3401-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Unicode-UCD-0.75-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-User-pwent-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-utils-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-vars-1.05-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-vmsish-1.04-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl / perl-Attribute-Handlers / perl-AutoLoader / perl-AutoSplit / etc');
}
