#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0838. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193666);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2004-2761", "CVE-2010-3868", "CVE-2010-3869");
  script_xref(name:"RHSA", value:"2010:0838");

  script_name(english:"RHEL 5 : pki (RHSA-2010:0838)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for pki.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2010:0838 advisory.

    Red Hat Certificate System is an enterprise software system designed to
    manage enterprise public key infrastructure (PKI) deployments. Simple
    Certificate Enrollment Protocol (SCEP) is a PKI communication protocol
    used to automatically enroll certificates for network devices.

    The certificate authority allowed unauthenticated users to request the
    one-time PIN in an SCEP request to be decrypted. An attacker able to sniff
    an SCEP request from a network device could request the certificate
    authority to decrypt the request, allowing them to obtain the one-time
    PIN. With this update, the certificate authority only handles decryption
    requests from authenticated registration authorities. (CVE-2010-3868)

    The certificate authority allowed the one-time PIN used in SCEP requests
    to be re-used. An attacker possessing a valid SCEP enrollment one-time PIN
    could use it to generate an unlimited number of certificates.
    (CVE-2010-3869)

    The certificate authority used the MD5 hash algorithm to sign all SCEP
    protocol responses. As MD5 is not collision resistant, an attacker could
    use this flaw to perform an MD5 chosen-prefix collision attack to generate
    attack-chosen output signed using the certificate authority's key.
    (CVE-2004-2761)

    This update also adds the following enhancements:

    * New configuration options for the SCEP server can define the default and
    allowed encryption and hash algorithms. These options allow disabling uses
    of the weaker algorithms not required by network devices and prevent
    possible downgrade attacks. These can be configured by adding the following
    options to the certificate authority's CS.cfg configuration file:

       ca.scep.encryptionAlgorithm=DES3
       ca.scep.allowedEncryptionAlgorithms=DES3
       ca.scep.hashAlgorithm=SHA1
       ca.scep.allowedHashAlgorithms=SHA1,SHA256,SHA512

    * With this update, the certificate authority's SCEP server is disabled by
    default. The SCEP server can be enabled by adding the 'ca.scep.enable=true'
    option to the certificate authority's CS.cfg configuration file.

    * A separate key pair can now be configured for use in SCEP communication.
    Previously, the main certificate authority's key pair was used for SCEP
    communication too. A designated SCEP key pair can be referenced by adding
    a new option, ca.scep.nickname=[scep certificate nickname], to the
    certificate authority's CS.cfg configuration file.

    * The certificate authority now allows the size of nonces used in SCEP
    requests to be restricted by adding a new option, ca.scep.nonceSizeLimit=
    [number of bytes], to the certificate authority's CS.cfg configuration
    file. The limit is set to 16 bytes in the default CS.cfg configuration
    file.

    All users of Red Hat Certificate System 8 should upgrade to these updated
    packages, which resolve these issues and add these enhancements.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648886");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0838.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f36976d6");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0838");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL pki package based on the guidance in RHSA-2010:0838.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3868");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2004-2761");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-common-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pki-util-javadoc");
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
      {'reference':'pki-ca-8.0.7-1.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-common-8.0.6-2.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-common-javadoc-8.0.6-2.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-util-8.0.5-1.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pki-util-javadoc-8.0.5-1.el5pki', 'release':'5', 'el_string':'el5pki', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pki-ca / pki-common / pki-common-javadoc / pki-util / etc');
}
