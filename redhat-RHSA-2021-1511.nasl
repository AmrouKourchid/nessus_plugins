#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:1511. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149319);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2021-21290", "CVE-2021-21295", "CVE-2021-21409");
  script_xref(name:"RHSA", value:"2021:1511");
  script_xref(name:"IAVA", value:"2021-A-0347");

  script_name(english:"RHEL 7 / 8 : AMQ Clients 2.9.1 (RHSA-2021:1511)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for AMQ Clients 2.9.1.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:1511 advisory.

    Red Hat AMQ Clients enable connecting, sending, and receiving messages over the AMQP 1.0 wire transport
    protocol to or from AMQ Broker 6 and 7.

    This update provides various bug fixes and enhancements in addition to the client package versions
    previously released on Red Hat Enterprise Linux 7 and 8.

    Security Fix(es):

    * netty: Information disclosure via the local system temporary directory (CVE-2021-21290)

    * netty: possible request smuggling in HTTP/2 due missing validation (CVE-2021-21295)

    * netty: Request smuggling via content-length header (CVE-2021-21409)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_1511.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1294c441");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/documentation/en-us/red_hat_amq/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1927028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944888");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL AMQ Clients 2.9.1 package based on the guidance in RHSA-2021:1511.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21409");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 444);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-cpp-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-qpid_proton");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/amq/2/debug',
      'content/dist/layered/rhel8/x86_64/amq/2/os',
      'content/dist/layered/rhel8/x86_64/amq/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-qpid-proton-docs-0.33.0-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-qpid-proton-0.33.0-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-0.33.0-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-devel-0.33.0-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-docs-0.33.0-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-0.33.0-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-devel-0.33.0-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-docs-0.33.0-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-tests-0.33.0-8.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-qpid_proton-0.33.0-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/7/7Client/x86_64/amq/2/debug',
      'content/dist/rhel/client/7/7Client/x86_64/amq/2/os',
      'content/dist/rhel/client/7/7Client/x86_64/amq/2/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/amq/2/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/amq/2/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/amq/2/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/amq/2/debug',
      'content/dist/rhel/server/7/7Server/x86_64/amq/2/os',
      'content/dist/rhel/server/7/7Server/x86_64/amq/2/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/amq/2/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/amq/2/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/amq/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-qpid-proton-0.33.0-6.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-qpid-proton-docs-0.33.0-6.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-0.33.0-6.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-devel-0.33.0-6.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-c-docs-0.33.0-6.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-0.33.0-6.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-devel-0.33.0-6.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-cpp-docs-0.33.0-6.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-proton-tests-0.33.0-6.el7_9', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-qpid_proton-0.33.0-6.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-qpid-proton / python-qpid-proton-docs / python3-qpid-proton / etc');
}
