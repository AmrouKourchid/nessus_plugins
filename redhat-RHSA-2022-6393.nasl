#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:6393. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164843);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2021-22096",
    "CVE-2021-23358",
    "CVE-2022-2806",
    "CVE-2022-31129"
  );
  script_xref(name:"RHSA", value:"2022:6393");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");

  script_name(english:"RHEL 8 : RHV Manager (ovirt-engine) [ovirt-4.5.2] (RHSA-2022:6393)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for RHV Manager (ovirt-engine) [ovirt-4.5.2].");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:6393 advisory.

    The ovirt-engine package provides the Red Hat Virtualization Manager, a centralized management platform
    that allows system administrators to view and manage virtual machines. The Manager provides a
    comprehensive range of features including search capabilities, resource management, live migrations, and
    virtual infrastructure provisioning.

    Security Fix(es):

    * nodejs-underscore: Arbitrary code execution via the template function (CVE-2021-23358)

    * moment: inefficient parsing algorithm resulting in DoS (CVE-2022-31129)

    * jquery: Cross-site scripting due to improper injQuery.htmlPrefilter method (CVE-2020-11022)

    * jquery: Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods
    (CVE-2020-11023)

    * ovirt-log-collector: RHVM admin password is logged unfiltered (CVE-2022-2806)

    * springframework: malicious input leads to insertion of additional log entries (CVE-2021-22096)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Previously, running engine-setup did not always renew OVN certificates close to expiration or expired.
    With this release, OVN certificates are always renewed by engine-setup when needed. (BZ#2097558)

    * Previously, the Manager issued warnings of approaching certificate expiration before engine-setup could
    update certificates. In this release expiration warnings and certificate update periods are aligned, and
    certificates are updated as soon as expiration warnings occur. (BZ#2097725)

    * With this release, OVA export or import work on hosts with a non-standard SSH port. (BZ#2104939)

    * With this release, the certificate validity test is compatible with RHEL 8 and RHEL 7 based hypervisors.
    (BZ#2107250)

    * RHV 4.4 SP1 and later are only supported on RHEL 8.6, customers cannot use RHEL 8.7 or later, and must
    stay with RHEL 8.6 EUS. (BZ#2108985)

    * Previously, importing templates from the Administration Portal did not work. With this release,
    importing templates from the Administration Portal is possible. (BZ#2109923)

    * ovirt-provider-ovn certificate expiration is checked along with other RHV certificates. If ovirt-
    provider-ovn is about to expire or already expired, a warning or alert is raised in the audit log. To
    renew the ovirt-provider-ovn certificate, administators must run engine-setup. If your ovirt-provider-ovn
    certificate expires on a previous RHV version, upgrade to RHV 4.4 SP1 batch 2 or later, and ovirt-
    provider-ovn certificate will be renewed automatically in the engine-setup. (BZ#2097560)

    * Previously, when importing a virtual machine with manual CPU pinning, the manual pinning string was
    cleared, but the CPU pinning policy was not set to NONE. As a result, importing failed. In this release,
    the CPU pinning policy is set to NONE if the CPU pinning string is cleared, and importing succeeds.
    (BZ#2104115)

    * Previously, the Manager could start a virtual machine with a Resize and Pin NUMA policy on a host
    without an equal number of physical sockets to NUMA nodes. As a result, wrong pinning was assigned to the
    policy. With this release, the Manager does not allow the virtual machine to be scheduled on such a
    virtual machine, and the pinning is correct based on the algorithm. (BZ#1955388)

    * Rebase package(s) to version: 4.4.7.
    Highlights, important fixes, or notable enhancements: fixed BZ#2081676 (BZ#2104831)

    * In this release, rhv-log-collector-analyzer provides detailed output for each problematic image,
    including disk names, associated virtual machine, the host running the virtual machine, snapshots, and
    current SPM. The detailed view is now the default. The compact option can be set by using the --compact
    switch in the command line. (BZ#2097536)

    * UnboundID LDAP SDK has been rebased on upstream version 6.0.4. See
    https://github.com/pingidentity/ldapsdk/releases for changes since version 4.0.14 (BZ#2092478)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_6393.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fc4c87c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:6393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1828406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1850004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1939284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1955388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1974974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2034584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2080005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2094577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2104115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2104831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2104939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2105075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2108985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2109923");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL RHV Manager (ovirt-engine) [ovirt-4.5.2] package based on the guidance in RHSA-2022:6393.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23358");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 94, 200, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-health-check-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-cinderlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-imageio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-ui-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-log-collector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-web-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ovirt-engine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhvm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/debug',
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/os',
      'content/dist/layered/rhel8/x86_64/rhv-manager/4.4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ovirt-engine-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-backend-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-dbscripts-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-health-check-bundler-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-restapi-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-setup-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-setup-base-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-setup-plugin-cinderlib-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-setup-plugin-imageio-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-setup-plugin-ovirt-engine-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-setup-plugin-ovirt-engine-common-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-setup-plugin-vmconsole-proxy-helper-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-setup-plugin-websocket-proxy-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-tools-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-tools-backup-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-ui-extensions-1.3.5-1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2022-31129']},
      {'reference':'ovirt-engine-vmconsole-proxy-helper-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-webadmin-portal-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-engine-websocket-proxy-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'ovirt-log-collector-4.4.7-2.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2022-2806']},
      {'reference':'ovirt-web-ui-1.9.1-1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2021-23358']},
      {'reference':'python3-ovirt-engine-lib-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']},
      {'reference':'rhvm-4.5.2.4-0.1.el8ev', 'release':'8', 'el_string':'el8ev', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-', 'cves':['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2021-22096']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ovirt-engine / ovirt-engine-backend / ovirt-engine-dbscripts / etc');
}
