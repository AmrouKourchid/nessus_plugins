#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2560. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210259);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id("CVE-2017-7509");
  script_xref(name:"RHSA", value:"2017:2560");

  script_name(english:"RHEL 5 : Red Hat Certificate System 8 (RHSA-2017:2560)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2017:2560 advisory.

    Red Hat Certificate System is a complete implementation of an enterprise software system designed to
    manage enterprise public key infrastructure (PKI) deployments.

    Security Fix(es):

    * An input validation error was found in Red Hat Certificate System's handling of client provided
    certificates. If the certreq field is not present in a certificate an assertion error is triggered causing
    a denial of service. (CVE-2017-7509)

    Bug Fix(es):

    * Previously, the Token Management System (TMS) required that certificates that were on hold must first
    become valid before they can be revoked. This update removes that limitation, and it is now possible to
    directly revoke currently on hold certificates. (BZ#1262000)

    * With this update, Red Hat Certificate System instances can be installed using existing CA signing
    certificate/keys. This existing CA can be a functional CA from a different vendor, or keys or CSR
    generated to be signed by an external CA for the purpose of chaining it to a publicly recognized CA.

    Note that this feature is only supported when installing with the pkisilent tool, not when using the
    graphical user interface. Additionally, since the CSR is generated externally prior to configuration of
    the CA instance and is not stored in the NSS security databases, it should be understood that the CSR
    value attached to the ca.signing.certreq variable stored inside the /var/lib/pki-ca/conf/CS.cfg file
    is a reconstruction of the CSR created during configuration, and not the original CSR utilized to obtain
    the existing CA certificate. (BZ#1280391)

    * Previously, a bug in CRLDistributionPointsExtension caused some certificate profiles to encounter
    problems when being viewed in the Certificate Manager graphical interface. This bug is now fixed, and
    aforementioned profile can now be viewed normally. (BZ#1282589)

    * Previously, if access to a component such as an HSM or an LDAP server was lost during Certificate
    Revocation List (CRL) generation, the CA could become stuck in a loop that generated large amounts of log
    entries until the problem was resolved. To avoid these scenarios, two new configuration parameters are
    being introduced in this patch to allow the CA to slow down. (BZ#1290650)

    * A patch has been applied to the Token Processing System (TPS) to ensure that the
    symmetricKeys.requiredVersion option is being handled correctly in all cases. (BZ#1302103)

    * A patch has been applied to the Certificate System Token Processing System (TPS) to fix a bug where
    existing objects were not always cleared when enrolling over an active token. (BZ#1302116)

    * This update fixes a bug where the Token Processing System (TPS) could not correctly execute re-
    enrollment operations (taking a currently enrolled token and enrolling it again with new certificates) on
    some G&D smart cards. (BZ#1320283)

    * The Token Processing System (TPS) could previously leave old data in a token's Coolkey applet when re-
    enrolling the token with new certificates and keys. This bug is now fixed, and only data associated with
    certificates which are actually on the token is preserved after a successful re-enrollment. (BZ#1327653)

    * Previously, a problem when setting the final life cycle state of a token at the end of a re-enrollment
    operation could cause it to fail to report that it is properly enrolled. This bug is now fixed, and re-
    enrolled token now report their enrolled status accurately. (BZ#1382376)

    * Prior to this update, ECDSA certificates were issued with a NULL value in the parameter field. These
    certificates were not compliant with the RFC 5758 specification which mandates this field to be omitted
    completely. This bug has been fixed, and ECDSA certificates are now issued without the parameter field.
    (BZ#1454414)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1456030");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_2560.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd52c5ad");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2560");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-common-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-kra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-silent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-tps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-util-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki-ca-ui");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/certificate-system-advanced/8/os',
      'content/dist/rhel/server/5/5Server/i386/certificate-system-advanced/8/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/certificate-system/8/os',
      'content/dist/rhel/server/5/5Server/i386/certificate-system/8/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/certificate-system-advanced/8/os',
      'content/dist/rhel/server/5/5Server/x86_64/certificate-system-advanced/8/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/certificate-system/8/os',
      'content/dist/rhel/server/5/5Server/x86_64/certificate-system/8/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'pki-ca-8.1.9-2.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-common-8.1.20-1.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-common-javadoc-8.1.20-1.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-kra-8.1.7-2.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-silent-8.1.2-3.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-tps-8.1.30-1.el5pki', 'cpu':'i386', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-tps-8.1.30-1.el5pki', 'cpu':'x86_64', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-util-8.1.3-2.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-util-javadoc-8.1.3-2.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'redhat-pki-ca-ui-8.1.1-2.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pki-ca / pki-common / pki-common-javadoc / pki-kra / pki-silent / etc');
}
