#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1692. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79060);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2014-3513", "CVE-2014-3567");
  script_xref(name:"RHSA", value:"2014:1692");

  script_name(english:"RHEL 6 : openssl (RHSA-2014:1692)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for openssl.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:1692 advisory.

    OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL),
    Transport Layer Security (TLS), and Datagram Transport Layer Security
    (DTLS) protocols, as well as a full-strength, general purpose cryptography
    library.

    This update adds support for the TLS Fallback Signaling Cipher Suite Value
    (TLS_FALLBACK_SCSV), which can be used to prevent protocol downgrade
    attacks against applications which re-connect using a lower SSL/TLS
    protocol version when the initial connection indicating the highest
    supported protocol version fails.

    This can prevent a forceful downgrade of the communication to SSL 3.0.
    The SSL 3.0 protocol was found to be vulnerable to the padding oracle
    attack when using block cipher suites in cipher block chaining (CBC) mode.
    This issue is identified as CVE-2014-3566, and also known under the alias
    POODLE. This SSL 3.0 protocol flaw will not be addressed in a future
    update; it is recommended that users configure their applications to
    require at least TLS protocol version 1.0 for secure communication.

    For additional information about this flaw, see the Knowledgebase article
    at https://access.redhat.com/articles/1232123

    A memory leak flaw was found in the way OpenSSL parsed the DTLS Secure
    Real-time Transport Protocol (SRTP) extension data. A remote attacker could
    send multiple specially crafted handshake messages to exhaust all available
    memory of an SSL/TLS or DTLS server. (CVE-2014-3513)

    A memory leak flaw was found in the way an OpenSSL handled failed session
    ticket integrity checks. A remote attacker could exhaust all available
    memory of an SSL/TLS or DTLS server by sending a large number of invalid
    session tickets to that server. (CVE-2014-3567)

    All OpenSSL users are advised to upgrade to these updated packages, which
    contain backported patches to mitigate the CVE-2014-3566 issue and correct
    the CVE-2014-3513 and CVE-2014-3567 issues. For the update to take effect,
    all services linked to the OpenSSL library (such as httpd and other
    SSL-enabled services) must be restarted or the system rebooted.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_1692.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38218c94");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/1232123");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1692");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152961");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL openssl package based on the guidance in RHSA-2014:1692.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3567");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(401);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
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
      'content/dist/rhs/server/2.1/x86_64/debug',
      'content/dist/rhs/server/2.1/x86_64/os',
      'content/dist/rhs/server/2.1/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-1.0.1e-30.el6_6.2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openssl-devel-1.0.1e-30.el6_6.2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openssl-perl-1.0.1e-30.el6_6.2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openssl-static-1.0.1e-30.el6_6.2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-perl / openssl-static');
}
