#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0662. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(81728);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2015-0203", "CVE-2015-0223", "CVE-2015-0224");
  script_bugtraq_id(72030, 72317, 72319);
  script_xref(name:"RHSA", value:"2015:0662");

  script_name(english:"RHEL 5 : qpid-cpp (RHSA-2015:0662)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for qpid-cpp.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2015:0662 advisory.

    Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a next-generation
    IT infrastructure for enterprise computing. MRG offers increased
    performance, reliability, interoperability, and faster computing for
    enterprise customers.

    The Qpid packages provide a message broker daemon that receives, stores and
    routes messages using the open AMQP messaging protocol along with run-time
    libraries for AMQP client applications developed using Qpid C++. Clients
    exchange messages with an AMQP message broker using the AMQP protocol.

    It was discovered that the Qpid daemon (qpidd) did not restrict access to
    anonymous users when the ANONYMOUS mechanism was disallowed.
    (CVE-2015-0223)

    Multiple flaws were found in the way the Qpid daemon (qpidd) processed
    certain protocol sequences. An unauthenticated attacker able to send a
    specially crafted protocol sequence set could use these flaws to crash
    qpidd. (CVE-2015-0203, CVE-2015-0224)

    Red Hat would like to thank the Apache Software Foundation for reporting
    the CVE-2015-0203 issue. Upstream acknowledges G. Geshev from MWR Labs as
    the original reporter.

    This update also fixes the following bug:

    * Prior to this update, because message purging was performed on a timer
    thread, large purge events could have caused all other timer tasks to be
    delayed. Because heartbeats were also driven by a timer on this thread,
    this could have resulted in clients timing out because they were not
    receiving heartbeats. The fix moves expired message purging from the timer
    thread to a worker thread, which allow long-running expired message purges
    to not affect timer tasks such as the heartbeat timer. (BZ#1142833)

    All users of Red Hat Enterprise MRG Messaging 2.5 for Red Hat Enterprise
    Linux 5 are advised to upgrade to these updated packages, which correct
    these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2015/rhsa-2015_0662.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a193488");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:0662");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1181721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1186302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1186308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191757");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL qpid-cpp package based on the guidance in RHSA-2015:0662.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0223");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-mrg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/mrg-g/2/os',
      'content/dist/rhel/server/5/5Server/i386/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/mrg-m/2/os',
      'content/dist/rhel/server/5/5Server/i386/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/mrg-g/2/os',
      'content/dist/rhel/server/5/5Server/x86_64/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/mrg-m/2/os',
      'content/dist/rhel/server/5/5Server/x86_64/mrg-m/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qpid-cpp-client-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-devel-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-devel-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-devel-docs-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-devel-docs-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-rdma-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-rdma-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-ssl-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-client-ssl-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-cluster-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-cluster-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-devel-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-devel-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-rdma-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-rdma-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-ssl-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-ssl-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-store-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-store-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-xml-0.18-38.el5_10', 'cpu':'i386', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'qpid-cpp-server-xml-0.18-38.el5_10', 'cpu':'x86_64', 'release':'5', 'el_string':'el5_10', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qpid-cpp-client / qpid-cpp-client-devel / etc');
}
