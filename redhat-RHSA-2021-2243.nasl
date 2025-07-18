#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:2243. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(165121);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2020-36317", "CVE-2020-36318");
  script_xref(name:"RHSA", value:"2021:2243");

  script_name(english:"RHEL 7 : rust-toolset-1.49 and rust-toolset-1.49-rust update (Low) (RHSA-2021:2243)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:2243 advisory.

    Rust Toolset provides the Rust programming language compiler rustc, the cargo build tool and dependency
    manager, the cargo-vendor plugin, and required libraries.

    This enhancement update adds the rust-toolset-1.49 packages to Red Hat Developer Tools. (BZ#1902240)

    Security Fix(es):

    * rust: use-after-free or double free in VecDeque::make_contiguous (CVE-2020-36318)

    * rust: memory safety violation in String::retain() (CVE-2020-36317)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_2243.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17cc485f");
  # https://access.redhat.com/documentation/en-us/red_hat_developer_tools/1/html/using_rust_1.49.0_toolset/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5562b9ce");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:2243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949192");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36318");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 416);
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-cargo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rust-debugger-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rust-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rust-lldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rust-toolset-1.49-rustfmt");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/power-le/7/7Server/ppc64le/devtools/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/devtools/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/devtools/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/devtools/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/devtools/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/devtools/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/devtools/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/devtools/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/devtools/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/devtools/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/devtools/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rust-toolset-1.49-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-build-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-build-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-build-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-build-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-cargo-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-cargo-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-cargo-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-cargo-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-cargo-doc-1.49.0-1.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-clippy-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-clippy-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-clippy-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-clippy-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rls-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rls-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rls-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rls-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-runtime-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-runtime-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-runtime-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-runtime-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-analysis-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-analysis-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-analysis-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-analysis-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-debugger-common-1.49.0-1.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-doc-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-doc-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-doc-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-doc-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-gdb-1.49.0-1.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-lldb-1.49.0-1.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-src-1.49.0-1.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-std-static-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-std-static-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-std-static-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rust-std-static-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rustfmt-1.49.0-1.el7_9', 'cpu':'ppc64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rustfmt-1.49.0-1.el7_9', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rustfmt-1.49.0-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rust-toolset-1.49-rustfmt-1.49.0-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rust-toolset-1.49 / rust-toolset-1.49-build / etc');
}
