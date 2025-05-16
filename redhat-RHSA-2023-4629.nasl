#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:4629. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179879);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-24963",
    "CVE-2022-36760",
    "CVE-2022-37436",
    "CVE-2022-48279",
    "CVE-2023-24021",
    "CVE-2023-27522",
    "CVE-2023-28319",
    "CVE-2023-28321",
    "CVE-2023-28322"
  );
  script_xref(name:"RHSA", value:"2023:4629");

  script_name(english:"RHEL 7 / 8 : Red Hat JBoss Core Services Apache HTTP Server 2.4.57 (RHSA-2023:4629)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Core Services Apache HTTP Server
2.4.57.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:4629 advisory.

    Red Hat JBoss Core Services is a set of supplementary software for Red Hat JBoss middleware products. This
    software, such as Apache HTTP Server, is common to multiple JBoss middleware products and packaged under
    Red Hat JBoss Core Services, to allow for faster distribution of updates and for a more consistent update
    experience.

    This release of Red Hat JBoss Core Services Apache HTTP Server 2.4.57 serves as a replacement for Red Hat
    JBoss Core Services Apache HTTP Server 2.4.51 Service Pack 2, and includes bug fixes and enhancements,
    which are documented in the Release Notes linked to in the References section.

    Security Fix(es):

    * apr-util: integer overflow/wraparound in apr_encode (CVE-2022-24963)

    * httpd: mod_proxy_ajp: Possible request smuggling (CVE-2022-36760)

    * httpd: mod_proxy: HTTP response splitting (CVE-2022-37436)

    * mod_security: incorrect parsing of HTTP multipart requests leads to web application firewall bypass
    (CVE-2022-48279)

    * modsecurity: lacking the complete content in FILES_TMP_CONTENT leads to web application firewall bypass
    (CVE-2023-24021)

    * httpd: mod_proxy_uwsgi HTTP response splitting (CVE-2023-27522)

    * curl: use after free in SSH sha256 fingerprint check (CVE-2023-28319)

    * curl: IDN wildcard match may lead to Improper Cerificate Validation (CVE-2023-28321)

    * curl: more POST-after-PUT confusion (CVE-2023-28322)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_4629.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3aa4cac");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2161773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2161777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2169465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2176211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2196778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2196786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2196793");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:4629");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Core Services Apache HTTP Server 2.4.57 package based on the guidance in RHSA-2023:4629.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24963");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(113, 190, 295, 402, 416, 440, 444, 1389);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-mod_ssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/layered/rhel8/x86_64/jbcs/1/debug',
      'content/dist/layered/rhel8/x86_64/jbcs/1/os',
      'content/dist/layered/rhel8/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-apr-1.7.0-8.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-24963']},
      {'reference':'jbcs-httpd24-apr-devel-1.7.0-8.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-24963']},
      {'reference':'jbcs-httpd24-curl-8.2.1-1.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2023-28319', 'CVE-2023-28321', 'CVE-2023-28322']},
      {'reference':'jbcs-httpd24-httpd-2.4.57-5.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.57-5.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.57-5.el8jbcs', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.57-5.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.57-5.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-libcurl-8.2.1-1.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2023-28319', 'CVE-2023-28321', 'CVE-2023-28322']},
      {'reference':'jbcs-httpd24-libcurl-devel-8.2.1-1.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2023-28319', 'CVE-2023-28321', 'CVE-2023-28322']},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.57-5.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.57-5.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-mod_security-2.9.3-29.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-48279', 'CVE-2023-24021']},
      {'reference':'jbcs-httpd24-mod_session-2.4.57-5.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.57-5.el8jbcs', 'cpu':'x86_64', 'release':'8', 'el_string':'el8jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbcs/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'jbcs-httpd24-apr-1.7.0-8.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-24963']},
      {'reference':'jbcs-httpd24-apr-devel-1.7.0-8.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-24963']},
      {'reference':'jbcs-httpd24-curl-8.2.1-1.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2023-28319', 'CVE-2023-28321', 'CVE-2023-28322']},
      {'reference':'jbcs-httpd24-httpd-2.4.57-5.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-httpd-devel-2.4.57-5.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-httpd-manual-2.4.57-5.el7jbcs', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-httpd-selinux-2.4.57-5.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-httpd-tools-2.4.57-5.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-libcurl-8.2.1-1.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2023-28319', 'CVE-2023-28321', 'CVE-2023-28322']},
      {'reference':'jbcs-httpd24-libcurl-devel-8.2.1-1.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2023-28319', 'CVE-2023-28321', 'CVE-2023-28322']},
      {'reference':'jbcs-httpd24-mod_ldap-2.4.57-5.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-mod_proxy_html-2.4.57-5.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-mod_security-2.9.3-29.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-48279', 'CVE-2023-24021']},
      {'reference':'jbcs-httpd24-mod_session-2.4.57-5.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']},
      {'reference':'jbcs-httpd24-mod_ssl-2.4.57-5.el7jbcs', 'cpu':'x86_64', 'release':'7', 'el_string':'el7jbcs', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jbcs-httpd24', 'cves':['CVE-2022-36760', 'CVE-2022-37436', 'CVE-2023-27522']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jbcs-httpd24-apr / jbcs-httpd24-apr-devel / jbcs-httpd24-curl / etc');
}
