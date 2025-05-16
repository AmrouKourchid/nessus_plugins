#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3240. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104699);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2016-2183", "CVE-2017-9788", "CVE-2017-9798");
  script_xref(name:"RHSA", value:"2017:3240");

  script_name(english:"RHEL 6 / 7 : Red Hat JBoss Enterprise Application Platform 6.4.18 (RHSA-2017:3240)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat JBoss Enterprise Application Platform
6.4.18.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:3240 advisory.

    Red Hat JBoss Enterprise Application Platform is a platform for Java applications based on the JBoss
    Application Server.

    This release provides an update to httpd and OpenSSL. The updates are documented in the Release Notes
    document linked to in the References.

    The httpd packages provide the Apache HTTP Server, a powerful, efficient, and extensible web server.

    OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL) and Transport Layer Security (TLS)
    protocols, as well as a full-strength general-purpose cryptography library.

    This release of JBoss Enterprise Application Platform 6.4.18 Natives serves as an update to the JBoss
    Enterprise Application Platform 6.4.16 Natives and includes bug fixes which are documented in the Release
    Notes document linked to in the References.

    All users of Red Hat JBoss Enterprise Application Platform 6.4 Natives are advised to upgrade to these
    updated packages.

    Security Fix(es):

    * It was discovered that the httpd's mod_auth_digest module did not properly initialize memory before
    using it when processing certain headers related to digest authentication. A remote attacker could
    possibly use this flaw to disclose potentially sensitive information or cause httpd child process to crash
    by sending specially crafted requests to a server. (CVE-2017-9788)

    * A flaw was found in the way the DES/3DES cipher was used as part of the TLS/SSL protocol. A man-in-the-
    middle attacker could use this flaw to recover some plaintext data by capturing large amounts of encrypted
    traffic between TLS/SSL server and client if the communication used a DES/3DES based ciphersuite.
    (CVE-2016-2183)

    * A use-after-free flaw was found in the way httpd handled invalid and previously unregistered HTTP
    methods specified in the Limit directive used in an .htaccess file. A remote attacker could possibly use
    this flaw to disclose portions of the server memory, or cause httpd child process to crash.
    (CVE-2017-9798)

    Red Hat would like to thank OpenVPN for reporting CVE-2016-2183 and Hanno Bck for reporting
    CVE-2017-9798. Upstream acknowledges Karthikeyan Bhargavan (Inria) and Gatan Leurent (Inria) as the
    original reporters of CVE-2016-2183.

    Bug Fix(es):

    * CRL checking of very large CRLs fails with OpenSSL 1.0.2 (BZ#1508880)

    * mod_cluster segfaults in process_info() due to wrongly generated assembler instruction movslq
    (BZ#1508884)

    * Corruption in nodestatsmem in multiple core dumps but in different functions of each core dump.
    (BZ#1508885)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_3240.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0664a13e");
  # https://access.redhat.com/documentation/en/red-hat-jboss-enterprise-application-platform/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85cfe5e0");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/3229231");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:3240");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1369383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1470748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1490344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1508880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1508884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1508885");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat JBoss Enterprise Application Platform 6.4.18 package based on the guidance in RHSA-2017:3240.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(327, 416, 456);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd22-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbcs-httpd24-openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl22");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/debug',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/os',
      'content/dist/rhel/power/6/6Server/ppc64/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/debug',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/os',
      'content/dist/rhel/server/6/6Server/i386/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/debug',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbeap/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'httpd-2.2.26-57.ep6.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-2.2.26-57.ep6.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-2.2.26-57.ep6.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-devel-2.2.26-57.ep6.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-devel-2.2.26-57.ep6.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-devel-2.2.26-57.ep6.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-manual-2.2.26-57.ep6.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-manual-2.2.26-57.ep6.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-manual-2.2.26-57.ep6.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-tools-2.2.26-57.ep6.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-tools-2.2.26-57.ep6.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd-tools-2.2.26-57.ep6.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-1.0.2h-14.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-1.0.2h-14.jbcs.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-1.0.2h-14.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-devel-1.0.2h-14.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-devel-1.0.2h-14.jbcs.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-devel-1.0.2h-14.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-libs-1.0.2h-14.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-libs-1.0.2h-14.jbcs.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-libs-1.0.2h-14.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-perl-1.0.2h-14.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-perl-1.0.2h-14.jbcs.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-perl-1.0.2h-14.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-static-1.0.2h-14.jbcs.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-static-1.0.2h-14.jbcs.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-static-1.0.2h-14.jbcs.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.13-9.Final_redhat_2.ep6.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.13-9.Final_redhat_2.ep6.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.13-9.Final_redhat_2.ep6.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ldap-2.2.26-57.ep6.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ldap-2.2.26-57.ep6.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ldap-2.2.26-57.ep6.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ssl-2.2.26-57.ep6.el6', 'cpu':'i386', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'mod_ssl-2.2.26-57.ep6.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'mod_ssl-2.2.26-57.ep6.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.3/debug',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.3/os',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.4/debug',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.4/os',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6/debug',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6/os',
      'content/dist/rhel/power/7/7Server/ppc64/jbeap/6/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.4/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6.4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6/debug',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6/os',
      'content/dist/rhel/server/7/7Server/x86_64/jbeap/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'httpd22-2.2.26-58.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-2.2.26-58.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-devel-2.2.26-58.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-devel-2.2.26-58.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-manual-2.2.26-58.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-manual-2.2.26-58.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-tools-2.2.26-58.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'httpd22-tools-2.2.26-58.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-1.0.2h-14.jbcs.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-1.0.2h-14.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-devel-1.0.2h-14.jbcs.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-devel-1.0.2h-14.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-libs-1.0.2h-14.jbcs.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-libs-1.0.2h-14.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-perl-1.0.2h-14.jbcs.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-perl-1.0.2h-14.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-static-1.0.2h-14.jbcs.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'jbcs-httpd24-openssl-static-1.0.2h-14.jbcs.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.13-9.Final_redhat_2.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_cluster-native-1.2.13-9.Final_redhat_2.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ldap22-2.2.26-58.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ldap22-2.2.26-58.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'eap6'},
      {'reference':'mod_ssl22-2.2.26-58.ep6.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'},
      {'reference':'mod_ssl22-2.2.26-58.ep6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'eap6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-devel / httpd-manual / httpd-tools / httpd22 / etc');
}
