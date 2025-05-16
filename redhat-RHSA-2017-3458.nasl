#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3458. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105252);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id(
    "CVE-2016-4978",
    "CVE-2016-4993",
    "CVE-2016-5406",
    "CVE-2016-6311",
    "CVE-2016-7046",
    "CVE-2016-7061",
    "CVE-2016-8627",
    "CVE-2016-8656",
    "CVE-2016-9589",
    "CVE-2017-12165",
    "CVE-2017-12167",
    "CVE-2017-2595",
    "CVE-2017-2666",
    "CVE-2017-2670",
    "CVE-2017-7525",
    "CVE-2017-7536",
    "CVE-2017-7559"
  );
  script_xref(name:"RHSA", value:"2017:3458");

  script_name(english:"RHEL 6 / 7 : eap7-jboss-ec2-eap (RHSA-2017:3458)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for eap7-jboss-ec2-eap.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:3458 advisory.

    The eap7-jboss-ec2-eap packages provide scripts for Red Hat JBoss Enterprise Application Platform running
    on the Amazon Web Services (AWS) Elastic Compute Cloud (EC2).

    With this update, the eap7-jboss-ec2-eap package has been updated to ensure compatibility with Red Hat
    JBoss Enterprise Application Platform 7.1.

    Refer to the JBoss Enterprise Application Platform 7.1 Release Notes, linked to in the References section,
    for information on the most significant bug fixes and enhancements included in this release.

    Security Fix(es):

    * A Denial of Service can be caused when a long request is sent to EAP 7. (CVE-2016-7046)

    * The jboss init script unsafe file handling resulting in local privilege escalation. (CVE-2016-8656)

    * A deserialization vulnerability via readValue method of ObjectMapper which allows arbitrary code
    execution. (CVE-2017-7525)

    * JMSObjectMessage deserializes potentially malicious objects allowing Remote Code Execution.
    (CVE-2016-4978)

    * Undertow is vulnerable to the injection of arbitrary HTTP headers, and also response splitting.
    (CVE-2016-4993)

    * The domain controller will not propagate its administrative RBAC configuration to some slaves leading to
    escalate their privileges. (CVE-2016-5406)

    * Internal IP address disclosed on redirect when request header Host field is not set. (CVE-2016-6311)

    * Potential EAP resource starvation DOS attack via GET requests for server log files. (CVE-2016-8627)

    * Inefficient Header Cache could cause denial of service. (CVE-2016-9589)

    * The log file viewer allows arbitrary file read to authenticated user via path traversal. (CVE-2017-2595)

    * HTTP Request smuggling vulnerability due to permitting invalid characters in HTTP requests.
    (CVE-2017-2666)

    * Websocket non clean close can cause IO thread to get stuck in a loop. (CVE-2017-2670)

    * Privilege escalation with security manager's reflective permissions when granted to Hibernate Validator.
    (CVE-2017-7536)

    * Potential http request smuggling as Undertow parses the http headers with unusual whitespaces.
    (CVE-2017-7559)

    * Properties based files of the management and the application realm are world readable allowing access to
    users and roles information to all the users logged in to the system. (CVE-2017-12167)

    * RBAC configuration allows users with a Monitor role to view the sensitive information. (CVE-2016-7061)

    * Improper whitespace parsing leading to potential HTTP request smuggling. (CVE-2017-12165)

    Red Hat would like to thank Liao Xinxi (NSFOCUS) for reporting CVE-2017-7525; Calum Hutton (NCC Group) and
    Mikhail Egorov (Odin) for reporting CVE-2016-4993; Luca Bueti for reporting CVE-2016-6311; Gabriel Lavoie
    (Halogen Software) for reporting CVE-2016-9589; and Gregory Ramsperger and Ryan Moak for reporting
    CVE-2017-2670. The CVE-2016-5406 issue was discovered by Tomaz Cerar (Red Hat); the CVE-2016-8627 issue
    was discovered by Darran Lofthouse (Red Hat) and Brian Stansberry (Red Hat); the CVE-2017-2666 issue was
    discovered by Radim Hatlapatka (Red Hat); the CVE-2017-7536 issue was discovered by Gunnar Morling (Red
    Hat); the CVE-2017-7559 and CVE-2017-12165 issues were discovered by Stuart Douglas (Red Hat); and the
    CVE-2017-12167 issue was discovered by Brian Stansberry (Red Hat) and Jeremy Choi (Red Hat). Upstream
    acknowledges WildFly as the original reporter of CVE-2016-6311.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_3458.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc1c58f2");
  # https://access.redhat.com/documentation/en/jboss-enterprise-application-platform/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e41b214b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:3458");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1344321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1359014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1362735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1376646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1379207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1380852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1388240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1400344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1404782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1413028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1436163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1438885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1462702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1465573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1481665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1490301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1491612");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JBEAP-5324");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL eap7-jboss-ec2-eap package based on the guidance in RHSA-2017:3458.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7525");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(113, 119, 20, 200, 22, 284, 400, 444, 732, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ec2-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ec2-eap-samples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/7.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/7.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-jboss-ec2-eap-7.1.0-5.GA_redhat_5.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-ec2-eap-samples-7.1.0-5.GA_redhat_5.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.1/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/7.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'eap7-jboss-ec2-eap-7.1.0-5.GA_redhat_5.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'},
      {'reference':'eap7-jboss-ec2-eap-samples-7.1.0-5.GA_redhat_5.ep7.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eap7-jboss-ec2-eap / eap7-jboss-ec2-eap-samples');
}
