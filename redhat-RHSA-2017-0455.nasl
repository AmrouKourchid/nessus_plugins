#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0455. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(97595);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2016-0762",
    "CVE-2016-1240",
    "CVE-2016-3092",
    "CVE-2016-5018",
    "CVE-2016-6325",
    "CVE-2016-6794",
    "CVE-2016-6796",
    "CVE-2016-6797",
    "CVE-2016-6816",
    "CVE-2016-8735",
    "CVE-2016-8745"
  );
  script_xref(name:"RHSA", value:"2017:0455");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"RHEL 6 : Red Hat JBoss Web Server 3.1.0 (RHSA-2017:0455)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Web Server 3.1.0.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:0455 advisory.

    Red Hat JBoss Web Server is a fully integrated and certified set of components for hosting Java web
    applications. It is comprised of the Apache HTTP Server, the Apache Tomcat Servlet container, Apache
    Tomcat Connector (mod_jk), JBoss HTTP Connector (mod_cluster), Hibernate, and the Tomcat Native library.

    This release of Red Hat JBoss Web Server 3.1.0 serves as a replacement for Red Hat JBoss Web Server 3.0.3,
    and includes enhancements.

    Security Fix(es):

    * It was reported that the Tomcat init script performed unsafe file handling, which could result in local
    privilege escalation. (CVE-2016-1240)

    * It was discovered that the Tomcat packages installed certain configuration files read by the Tomcat
    initialization script as writeable to the tomcat group. A member of the group or a malicious web
    application deployed on Tomcat could use this flaw to escalate their privileges. (CVE-2016-6325)

    * The JmxRemoteLifecycleListener was not updated to take account of Oracle's fix for CVE-2016-3427.
    JMXRemoteLifecycleListener is only included in EWS 2.x and JWS 3.x source distributions. If you deploy a
    Tomcat instance built from source, using the EWS 2.x, or JWS 3.x distributions, an attacker could use this
    flaw to launch a remote code execution attack on your deployed instance. (CVE-2016-8735)

    * A denial of service vulnerability was identified in Commons FileUpload that occurred when the length of
    the multipart boundary was just below the size of the buffer (4096 bytes) used to read the uploaded file
    if the boundary was the typical tens of bytes long. (CVE-2016-3092)

    * It was discovered that the code that parsed the HTTP request line permitted invalid characters. This
    could be exploited, in conjunction with a proxy that also permitted the invalid characters but with a
    different interpretation, to inject data into the HTTP response. By manipulating the HTTP response the
    attacker could poison a web-cache, perform an XSS attack, or obtain sensitive information from requests
    other then their own. (CVE-2016-6816)

    * A bug was discovered in the error handling of the send file code for the NIO HTTP connector. This led to
    the current Processor object being added to the Processor cache multiple times allowing information
    leakage between requests including, and not limited to, session ID and the response body. (CVE-2016-8745)

    * The Realm implementations did not process the supplied password if the supplied user name did not exist.
    This made a timing attack possible to determine valid user names. Note that the default configuration
    includes the LockOutRealm which makes exploitation of this vulnerability harder. (CVE-2016-0762)

    * It was discovered that a malicious web application could bypass a configured SecurityManager via a
    Tomcat utility method that was accessible to web applications. (CVE-2016-5018)

    * It was discovered that when a SecurityManager is configured Tomcat's system property replacement feature
    for configuration files could be used by a malicious web application to bypass the SecurityManager and
    read system properties that should not be visible. (CVE-2016-6794)

    * It was discovered that a malicious web application could bypass a configured SecurityManager via
    manipulation of the configuration parameters for the JSP Servlet. (CVE-2016-6796)

    * It was discovered that it was possible for a web application to access any global JNDI resource whether
    an explicit ResourceLink had been configured or not. (CVE-2016-6797)

    The CVE-2016-6325 issue was discovered by Red Hat Product Security.

    Enhancement(s):

    This enhancement update adds the Red Hat JBoss Web Server 3.1.0 packages to Red Hat Enterprise Linux 6.
    These packages provide a number of enhancements over the previous version of Red Hat JBoss Web Server.
    (JIRA#JWS-267)

    Users of Red Hat JBoss Web Server are advised to upgrade to these updated packages, which add this
    enhancement.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_0455.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?095e39a4");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:0455");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1349468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1367447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1376712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1390493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1390515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1390520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1390525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1390526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1397484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1397485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1403824");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/JWS-267");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Web Server 3.1.0 package based on the guidance in RHSA-2017:0455.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8735");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Tomcat on Ubuntu Log Init Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 284, 444, 502);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-c3p0-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-core-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-entitymanager-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate4-envers-eap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apache-commons-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-apache-commons-daemon-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-vault");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat7-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-jsp-2.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-servlet-3.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat8-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/6/6Server/i386/jws/3/debug',
      'content/dist/rhel/server/6/6Server/i386/jws/3/os',
      'content/dist/rhel/server/6/6Server/i386/jws/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jws/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jws/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/jws/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'hibernate4-c3p0-eap6-4.2.23-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'hibernate4-core-eap6-4.2.23-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'hibernate4-eap6-4.2.23-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'hibernate4-entitymanager-eap6-4.2.23-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'hibernate4-envers-eap6-4.2.23-1.Final_redhat_1.1.ep6.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'jbcs-httpd24-apache-commons-daemon-1.0.15-1.redhat_2.1.jbcs.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'jbcs-httpd24-apache-commons-daemon-jsvc-1.0.15-17.redhat_2.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jws-3'},
      {'reference':'jbcs-httpd24-apache-commons-daemon-jsvc-1.0.15-17.redhat_2.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'jws-3'},
      {'reference':'jbcs-httpd24-runtime-1-3.jbcs.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'mod_cluster-1.3.5-2.Final_redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'mod_cluster-tomcat7-1.3.5-2.Final_redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'mod_cluster-tomcat8-1.3.5-2.Final_redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat-native-1.2.8-9.redhat_9.ep7.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat-native-1.2.8-9.redhat_9.ep7.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat-vault-1.0.8-9.Final_redhat_2.1.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-admin-webapps-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-docs-webapp-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-el-2.2-api-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-javadoc-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-jsp-2.2-api-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-jsvc-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-lib-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-log4j-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-selinux-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-servlet-3.0-api-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat7-webapps-7.0.70-16.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-admin-webapps-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-docs-webapp-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-el-2.2-api-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-javadoc-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-jsp-2.3-api-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-jsvc-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-lib-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-log4j-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-selinux-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-servlet-3.1-api-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'},
      {'reference':'tomcat8-webapps-8.0.36-17.ep7.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'jws-3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hibernate4-c3p0-eap6 / hibernate4-core-eap6 / hibernate4-eap6 / etc');
}
