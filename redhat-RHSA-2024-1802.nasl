#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:1802. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193322);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-1488");
  script_xref(name:"RHSA", value:"2024:1802");

  script_name(english:"RHEL 8 : unbound (RHSA-2024:1802)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for unbound.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2024:1802 advisory.

    The unbound packages provide a validating, recursive, and caching DNS or DNSSEC resolver.

    Security Fix(es):

    * A vulnerability was found in Unbound due to incorrect default permissions,
    allowing any process outside the unbound group to modify the unbound runtime
    configuration. The default combination of the control-use-cert: no option with
    either explicit or implicit use of an IP address in the control-interface
    option could allow improper access. If a process can connect over localhost to
    port 8953, it can alter the configuration of unbound.service. This flaw allows
    an unprivileged local process to manipulate a running instance, potentially
    altering forwarders, allowing them to track all queries forwarded by the local
    resolver, and, in some cases, disrupting resolving altogether.

    To mitigate the vulnerability, a new file
    /etc/unbound/conf.d/remote-control.conf has been added and included in the
    main unbound configuration file, unbound.conf. The file contains two
    directives that should limit access to unbound.conf:

        control-interface: /run/unbound/control
        control-use-cert: yes

    For details about these directives, run man unbound.conf.

    Updating to the version of unbound provided by this advisory should, in most
    cases, address the vulnerability. To verify that your configuration is not
    vulnerable, use the unbound-control status | grep control command. If the
    output contains control(ssl) or control(namedpipe), your configuration is
    not vulnerable. If the command output returns only control, the configuration
    is vulnerable because it does not enforce access only to the unbound group
    members. To fix your configuration, add the line include:
    /etc/unbound/conf.d/remote-control.conf to the end of the file
    /etc/unbound/unbound.conf. If you use a custom
    /etc/unbound/conf.d/remote-control.conf file, add the new directives to this
    file. (CVE-2024-1488)

    For more details about the security issue(s), including the impact, a CVSS
    score, acknowledgments, and other related information, refer to the CVE page(s)
    listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264183");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_1802.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f95b7b07");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:1802");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL unbound package based on the guidance in RHSA-2024:1802.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1488");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(15);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:unbound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:unbound-libs");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.8')) audit(AUDIT_OS_NOT, 'Red Hat 8.8', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.8/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.8/ppc64le/appstream/os',
      'content/e4s/rhel8/8.8/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.8/x86_64/appstream/debug',
      'content/e4s/rhel8/8.8/x86_64/appstream/os',
      'content/e4s/rhel8/8.8/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.8/aarch64/appstream/debug',
      'content/eus/rhel8/8.8/aarch64/appstream/os',
      'content/eus/rhel8/8.8/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.8/ppc64le/appstream/debug',
      'content/eus/rhel8/8.8/ppc64le/appstream/os',
      'content/eus/rhel8/8.8/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.8/s390x/appstream/debug',
      'content/eus/rhel8/8.8/s390x/appstream/os',
      'content/eus/rhel8/8.8/s390x/appstream/source/SRPMS',
      'content/eus/rhel8/8.8/x86_64/appstream/debug',
      'content/eus/rhel8/8.8/x86_64/appstream/os',
      'content/eus/rhel8/8.8/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.8/x86_64/appstream/debug',
      'content/tus/rhel8/8.8/x86_64/appstream/os',
      'content/tus/rhel8/8.8/x86_64/appstream/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python3-unbound-1.16.2-5.el8_8.4', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'unbound-1.16.2-5.el8_8.4', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'unbound-devel-1.16.2-5.el8_8.4', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'unbound-libs-1.16.2-5.el8_8.4', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-unbound / unbound / unbound-devel / unbound-libs');
}
