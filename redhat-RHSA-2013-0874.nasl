#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0874. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210215);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2012-5575");
  script_xref(name:"RHSA", value:"2013:0874");

  script_name(english:"RHEL 5 / 6 : JBoss Enterprise Web Platform 5.2.0 (RHSA-2013:0874)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for JBoss Enterprise Web Platform 5.2.0.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 host has packages installed that are affected by a vulnerability as referenced
in the RHSA-2013:0874 advisory.

    The Enterprise Web Platform is a slimmed down profile of the JBoss
    Enterprise Application Platform intended for mid-size workloads with light
    and rich Java applications.

    XML encryption backwards compatibility attacks were found against various
    frameworks, including Apache CXF. An attacker could force a server to use
    insecure, legacy cryptosystems, even when secure cryptosystems were enabled
    on endpoints. By forcing the use of legacy cryptosystems, flaws such as
    CVE-2011-1096 and CVE-2011-2487 would be exposed, allowing plain text to be
    recovered from cryptograms and symmetric keys. This issue affected both the
    JBoss Web Services CXF (jbossws-cxf) and JBoss Web Services Native
    (jbossws-native) stacks. (CVE-2012-5575)

    Red Hat would like to thank Tibor Jager, Kenneth G. Paterson and Juraj
    Somorovsky of Ruhr-University Bochum for reporting this issue.

    If you are using jbossws-cxf, then automatic checks to prevent this flaw
    are only run when WS-SecurityPolicy is used to enforce security
    requirements. It is best practice to use WS-SecurityPolicy to enforce
    security requirements.

    If you are using jbossws-native, the fix for this flaw is implemented by
    two new configuration parameters in the 'encryption' element. This element
    can be a child of 'requires' in both client and server wsse configuration
    descriptors (set on a per-application basis via the application's
    jboss-wsse-server.xml and jboss-wsse-client.xml files). The new attributes
    are 'algorithms' and 'keyWrapAlgorithms'. These attributes should contain a
    blank space or comma separated list of algorithm IDs that are allowed for
    the encrypted incoming message, both for encryption and private key
    wrapping. For backwards compatibility, no algorithm checks are performed by
    default for empty lists or missing attributes.

    For example (do not include the line break in your configuration):

    encryption algorithms=aes-192-gcm aes-256-gcm
    keyWrapAlgorithms=rsa_oaep

    Specifies that incoming messages are required to be encrypted, and that the
    only permitted encryption algorithms are AES-192 and 256 in GCM mode, and
    RSA-OAEP only for key wrapping.

    Before performing any decryption, the jbossws-native stack will verify that
    each algorithm specified in the incoming messages is included in the
    allowed algorithms lists from these new encryption element attributes. The
    algorithm values to be used for 'algorithms' and 'keyWrapAlgorithms' are
    the same as for 'algorithm' and 'keyWrapAlgorithm' in the 'encrypt'
    element.

    Warning: Before applying this update, back up your existing JBoss
    Enterprise Web Platform installation (including all applications and
    configuration files).

    All users of JBoss Enterprise Web Platform 5.2.0 on Red Hat Enterprise
    Linux 4, 5, and 6 are advised to upgrade to these updated packages. The
    JBoss server process must be restarted for the update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"http://ws.apache.org/wss4j/best_practice.html");
  script_set_attribute(attribute:"see_also", value:"http://cxf.apache.org/cve-2012-5575.html");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=880443");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2013/rhsa-2013_0874.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e28cbbd");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:0874");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL JBoss Enterprise Web Platform 5.2.0 package based on the guidance in RHSA-2013:0874.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5575");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(327);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5','6'])) audit(AUDIT_OS_NOT, 'Red Hat 5.x / 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/jbewp/5/os',
      'content/dist/rhel/server/5/5Server/i386/jbewp/5/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/jbewp/5/os',
      'content/dist/rhel/server/5/5Server/x86_64/jbewp/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'apache-cxf-2.2.12-12.patch_07.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossws-3.1.2-14.SP15_patch_02.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'wss4j-1.5.12-6_patch_03.ep5.el5', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/i386/jbewp/5/os',
      'content/dist/rhel/server/6/6Server/i386/jbewp/5/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/jbewp/5/os',
      'content/dist/rhel/server/6/6Server/x86_64/jbewp/5/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'apache-cxf-2.2.12-12.patch_07.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'jbossws-3.1.2-14.SP15_patch_02.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'wss4j-1.5.12-6_patch_03.ep5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache-cxf / jbossws / wss4j');
}
