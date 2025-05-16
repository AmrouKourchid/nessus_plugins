#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0938. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63962);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2010-3708", "CVE-2010-3862", "CVE-2010-3878");
  script_xref(name:"RHSA", value:"2010:0938");

  script_name(english:"RHEL 5 : JBoss Enterprise Application Platform 4.3.0.CP09 update (Important) (RHSA-2010:0938)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2010:0938 advisory.

    JBoss Enterprise Application Platform is the market leading platform for
    innovative and scalable Java applications; integrating the JBoss
    Application Server, with JBoss Hibernate and JBoss Seam into a complete,
    simple enterprise solution.

    This release of JBEAP for Red Hat Enterprise Linux 5 serves as a
    replacement to JBEAP 4.3.0.CP08.

    These updated packages include multiple bug fixes which are detailed in the
    Release Notes. The Release Notes will be available shortly from the link in
    the References section.

    The following security issues are also fixed with this release:

    An input sanitization flaw was found in the way JBoss Drools implemented
    certain rule base serialization. If a remote attacker supplied
    specially-crafted input to a JBoss Seam based application that accepts
    serialized input, it could lead to arbitrary code execution with the
    privileges of the JBoss server process. (CVE-2010-3708)

    A Cross-Site Request Forgery (CSRF) flaw was found in the JMX Console. A
    remote attacker could use this flaw to deploy a WAR file of their choosing
    on the target server, if they are able to trick a user, who is logged into
    the JMX Console as the admin user, into visiting a specially-crafted web
    page. (CVE-2010-3878)

    A flaw was found in the JBoss Remoting component. A remote attacker could
    use specially-crafted input to cause the JBoss Remoting listeners to become
    unresponsive, resulting in a denial of service condition for services
    communicating via JBoss Remoting sockets. (CVE-2010-3862)

    Red Hat would like to thank Ole Husgaard of eXerp.com for reporting the
    CVE-2010-3862 issue.

    Warning: Before applying this update, please backup the JBEAP
    server/[configuration]/deploy/ directory, and any other customized
    configuration files.

    All users of JBEAP 4.3 on Red Hat Enterprise Linux 5 are advised to upgrade
    to these updated packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://docs.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/4.3/html-single/Release_Notes_CP09/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a85db51d");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0938.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac2a1546");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=604617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=633859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=638236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=641389");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0938");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3708");
  script_cwe_id(352, 502);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.3.0.GA_CP09-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/5/5Server/i386/jbeap/4.3.0/os',
      'content/dist/rhel/server/5/5Server/i386/jbeap/4.3.0/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbeap/4.3.0/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbeap/4.3.0/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glassfish-jaxb-2.1.4-1.17.patch04.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'glassfish-jaxws-2.1.1-1jpp.ep1.13.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'hibernate3-3.2.4-1.SP1_CP11.0jpp.ep2.0.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap4'},
      {'reference':'hibernate3-annotations-3.3.1-2.0.GA_CP04.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'hibernate3-annotations-javadoc-3.3.1-2.0.GA_CP04.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'hibernate3-javadoc-3.2.4-1.SP1_CP11.0jpp.ep2.0.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap4'},
      {'reference':'javassist-3.9.0-2.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-common-1.2.2-1.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-messaging-1.4.0-4.SP3_CP11.1.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-remoting-2.2.3-4.SP3.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-seam-1.2.1-3.JBPAPP_4_3_0_GA.ep1.22.el5.1', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-seam-docs-1.2.1-3.JBPAPP_4_3_0_GA.ep1.22.el5.1', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-seam2-2.0.2.FP-1.ep1.26.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-seam2-docs-2.0.2.FP-1.ep1.26.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossas-4.3.0-8.GA_CP09.2.1.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossas-4.3.0.GA_CP09-bin-4.3.0-8.GA_CP09.2.1.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossas-client-4.3.0-8.GA_CP09.2.1.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossts-4.2.3-2.SP5_CP10.1jpp.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap4'},
      {'reference':'jbossweb-2.0.0-7.CP15.0jpp.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossws-2.0.1-6.SP2_CP09.2.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossws-common-1.0.0-3.GA_CP06.1.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jgroups-2.4.9-1.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap4'},
      {'reference':'quartz-1.5.2-1jpp.patch01.ep1.4.2.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'rh-eap-docs-4.3.0-8.GA_CP09.ep1.3.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'rh-eap-docs-examples-4.3.0-8.GA_CP09.ep1.3.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'xalan-j2-2.7.1-4.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glassfish-jaxb / glassfish-jaxws / hibernate3 / etc');
}
