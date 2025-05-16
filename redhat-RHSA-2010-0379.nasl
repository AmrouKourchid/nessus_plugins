#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0379. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63931);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2010-0738", "CVE-2010-1428", "CVE-2010-1429");
  script_xref(name:"RHSA", value:"2010:0379");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"RHEL 5 : JBoss Enterprise Application Platform 4.3.0.CP08 update (Critical) (RHSA-2010:0379)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2010:0379 advisory.

    JBoss Enterprise Application Platform is the market leading platform for
    innovative and scalable Java applications; integrating the JBoss
    Application Server, with JBoss Hibernate and JBoss Seam into a complete,
    simple enterprise solution.

    This release of JBEAP for Red Hat Enterprise Linux 5 serves as a
    replacement to JBEAP 4.3.0.CP07.

    These updated packages include multiple bug fixes which are detailed in the
    Release Notes. The Release Notes will be available shortly from the link
    in the References section.

    The following security issues are also fixed with this release:

    The JMX Console configuration only specified an authentication requirement
    for requests that used the GET and POST HTTP verbs. A remote attacker
    could create an HTTP request that does not specify GET or POST, causing it
    to be executed by the default GET handler without authentication. This
    release contains a JMX Console with an updated configuration that no longer
    specifies the HTTP verbs. This means that the authentication requirement is
    applied to all requests. (CVE-2010-0738)

    For the CVE-2010-0738 issue, if an immediate upgrade is not possible or the
    server deployment has been customized, a manual fix can be applied. Refer
    to the Security subsection of the Issues fixed in this release section
    (JBPAPP-3952) of the JBEAP Release Notes, linked to in the References, for
    details. Contact Red Hat JBoss Support for advice before making the changes
    noted in the Release Notes.

    Red Hat would like to thank Stefano Di Paola and Giorgio Fedon of Minded
    Security for responsibly reporting the CVE-2010-0738 issue.

    Unauthenticated access to the JBoss Application Server Web Console
    (/web-console) is blocked by default. However, it was found that this block
    was incomplete, and only blocked GET and POST HTTP verbs. A remote attacker
    could use this flaw to gain access to sensitive information. This release
    contains a Web Console with an updated configuration that now blocks all
    unauthenticated access to it by default. (CVE-2010-1428)

    The RHSA-2008:0828 update fixed an issue (CVE-2008-3273) where
    unauthenticated users were able to access the status servlet; however, a
    bug fix included in the RHSA-2009:0349 update re-introduced the issue. A
    remote attacker could use this flaw to acquire details about deployed web
    contexts. (CVE-2010-1429)

    Warning: Before applying this update, please backup the JBEAP
    server/[configuration]/deploy/ directory, and any other customized
    configuration files.

    All users of JBEAP 4.3 on Red Hat Enterprise Linux 5 are advised to upgrade
    to these updated packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=571905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=574105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=585899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=585900");
  # http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/4.3.0.cp08/html-single/Release_Notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfb49798");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0379.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3339cba");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0379");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1429");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-1428");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'JBoss JMX Console Deployer Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-132");
  script_cwe_id(284);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.3.0.GA_CP08-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
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
      {'reference':'hibernate3-3.2.4-1.SP1_CP10.0jpp.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap4'},
      {'reference':'hibernate3-annotations-3.3.1-1.12.GA_CP03.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'hibernate3-annotations-javadoc-3.3.1-1.12.GA_CP03.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'hibernate3-javadoc-3.2.4-1.SP1_CP10.0jpp.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap4'},
      {'reference':'jacorb-2.3.0-1jpp.ep1.10.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-aop-1.5.5-3.CP05.2.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-cache-1.4.1-6.SP14.1.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-messaging-1.4.0-3.SP3_CP10.2.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-remoting-2.2.3-3.SP2.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-seam-1.2.1-3.JBPAPP_4_3_0_GA.ep1.20.el5.1', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-seam-docs-1.2.1-3.JBPAPP_4_3_0_GA.ep1.20.el5.1', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-seam2-2.0.2.FP-1.ep1.23.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jboss-seam2-docs-2.0.2.FP-1.ep1.23.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossas-4.3.0-7.GA_CP08.5.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossas-4.3.0.GA_CP08-bin-4.3.0-7.GA_CP08.5.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossas-client-4.3.0-7.GA_CP08.5.ep1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossts-4.2.3-1.SP5_CP09.1jpp.ep1.1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap4'},
      {'reference':'jbossweb-2.0.0-6.CP13.0jpp.ep1.1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'jbossws-2.0.1-5.SP2_CP08.1.ep1.1.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'rh-eap-docs-4.3.0-7.GA_CP08.ep1.5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'},
      {'reference':'rh-eap-docs-examples-4.3.0-7.GA_CP08.ep1.5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hibernate3 / hibernate3-annotations / etc');
}
