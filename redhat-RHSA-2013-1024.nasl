#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1024. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76661);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2013-1909");
  script_bugtraq_id(60800);
  script_xref(name:"RHSA", value:"2013:1024");

  script_name(english:"RHEL 6 : Red Hat Enterprise MRG Messaging 2.3.3 (RHSA-2013:1024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat Enterprise MRG Messaging 2.3.3.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2013:1024 advisory.

    Red Hat Enterprise MRG (Messaging, Realtime, and Grid) is a next-generation
    IT infrastructure for enterprise computing. MRG offers increased
    performance, reliability, interoperability, and faster computing for
    enterprise customers.

    MRG Messaging is a high-speed reliable messaging distribution for Linux
    based on AMQP (Advanced Message Queuing Protocol), an open protocol
    standard for enterprise messaging that is designed to make mission critical
    messaging widely available as a standard service, and to make enterprise
    messaging interoperable across platforms, programming languages, and
    vendors. MRG Messaging includes an AMQP 0-10 messaging broker; AMQP 0-10
    client libraries for C++, Java JMS, and Python; as well as persistence
    libraries and management tools.

    It was discovered that the Qpid Python client library for AMQP did not
    properly perform TLS/SSL certificate validation of the remote server's
    certificate, even when the 'ssl_trustfile' connection option was specified.
    A rogue server could use this flaw to conduct man-in-the-middle attacks,
    possibly leading to the disclosure of sensitive information.
    (CVE-2013-1909)

    With this update, Python programs can instruct the library to validate
    server certificates by specifying a path to a file containing trusted CA
    certificates.

    This issue was discovered by Petr Matousek of the Red Hat MRG Messaging
    team.

    This update also fixes multiple bugs. Documentation for these changes will
    be available shortly from the Technical Notes document linked to in the
    References section.

    All users of the Messaging capabilities of Red Hat Enterprise MRG 2.3 are
    advised to upgrade to these updated packages, which resolve the issues
    noted in the Red Hat Enterprise MRG 2 Technical Notes. After installing the
    updated packages, stop the cluster by either running service qpidd stop
    on all nodes, or qpid-cluster --all-stop on any one of the cluster nodes.
    Once stopped, restart the cluster with service qpidd start on all nodes
    for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_MRG/2/html/Technical_Notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cff5eec4");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2013/rhsa-2013_1024.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f15936db");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1024");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=928530");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Enterprise MRG Messaging 2.3.3 package based on the guidance in RHSA-2013:1024.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1909");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-java-example");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-g-execute/2/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-g-execute/2/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-mgmt/2/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-mgmt/2/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/mrg-mgmt/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-qpid-0.18-5.el6_4', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'python-qpid-qmf-0.18-18.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'python-qpid-qmf-0.18-18.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-devel-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-devel-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-devel-docs-0.18-17.el6_4', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-rdma-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-rdma-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-ssl-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-client-ssl-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-cluster-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-cluster-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-devel-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-devel-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-rdma-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-rdma-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-ssl-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-ssl-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-store-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-store-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-xml-0.18-17.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-cpp-server-xml-0.18-17.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-qmf-0.18-18.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-qmf-0.18-18.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-qmf-devel-0.18-18.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-qmf-devel-0.18-18.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-tools-0.18-10.el6_4', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-qpid-qmf-0.18-18.el6_4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'ruby-qpid-qmf-0.18-18.el6_4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/debug',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/os',
      'content/dist/rhel/server/6/6Server/i386/mrg-mgmt/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g-execute/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-g/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-m/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-mgmt/2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/os',
      'content/dist/rhel/server/6/6Server/x86_64/mrg-r/2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qpid-java-client-0.18-8.el6_4', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-java-common-0.18-8.el6_4', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'},
      {'reference':'qpid-java-example-0.18-8.el6_4', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'mrg-release'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-qpid / python-qpid-qmf / qpid-cpp-client / etc');
}
