#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0303. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(89069);
  script_version("2.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2015-0293",
    "CVE-2015-3197",
    "CVE-2016-0703",
    "CVE-2016-0704",
    "CVE-2016-0800"
  );
  script_xref(name:"RHSA", value:"2016:0303");

  script_name(english:"RHEL 6 : openssl (RHSA-2016:0303)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for openssl.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2016:0303 advisory.

    OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
    and Transport Layer Security (TLS v1) protocols, as well as a
    full-strength, general purpose cryptography library.

    A padding oracle flaw was found in the Secure Sockets Layer version 2.0
    (SSLv2) protocol. An attacker can potentially use this flaw to decrypt
    RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol
    version, allowing them to decrypt such connections. This cross-protocol
    attack is publicly referred to as DROWN. (CVE-2016-0800)

    Note: This issue was addressed by disabling the SSLv2 protocol by default
    when using the 'SSLv23' connection methods, and removing support for weak
    SSLv2 cipher suites. For more information, refer to the knowledge base
    article linked to in the References section.

    It was discovered that the SSLv2 servers using OpenSSL accepted SSLv2
    connection handshakes that indicated non-zero clear key length for
    non-export cipher suites. An attacker could use this flaw to decrypt
    recorded SSLv2 sessions with the server by using it as a decryption
    oracle.(CVE-2016-0703)

    It was discovered that the SSLv2 protocol implementation in OpenSSL did
    not properly implement the Bleichenbacher protection for export cipher
    suites. An attacker could use a SSLv2 server using OpenSSL as a
    Bleichenbacher oracle. (CVE-2016-0704)

    Note: The CVE-2016-0703 and CVE-2016-0704 issues could allow for more
    efficient exploitation of the CVE-2016-0800 issue via the DROWN attack.

    A denial of service flaw was found in the way OpenSSL handled SSLv2
    handshake messages. A remote attacker could use this flaw to cause a
    TLS/SSL server using OpenSSL to exit on a failed assertion if it had both
    the SSLv2 protocol and EXPORT-grade cipher suites enabled. (CVE-2015-0293)

    A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2
    ciphers that have been disabled on the server. This could result in weak
    SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to
    man-in-the-middle attacks. (CVE-2015-3197)

    Red Hat would like to thank the OpenSSL project for reporting these issues.
    Upstream acknowledges Nimrod Aviram and Sebastian Schinzel as the original
    reporters of CVE-2016-0800 and CVE-2015-3197; David Adrian (University of
    Michigan) and J. Alex Halderman (University of Michigan) as the original
    reporters of CVE-2016-0703 and CVE-2016-0704; and Sean Burford (Google) and
    Emilia Ksper (OpenSSL development team) as the original reporters of
    CVE-2015-0293.

    All openssl users are advised to upgrade to these updated packages, which
    contain backported patches to correct these issues. For the update to take
    effect, all services linked to the OpenSSL library must be restarted, or
    the system rebooted.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2016/rhsa-2016_0303.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23887498");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/2176731");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://openssl.org/news/secadv/20160128.txt");
  script_set_attribute(attribute:"see_also", value:"https://openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:0303");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1202404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1301846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1310593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1310811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1310814");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL openssl package based on the guidance in RHSA-2016:0303.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(617);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6.2','6.4','6.5'])) audit(AUDIT_OS_NOT, 'Red Hat 6.2 / 6.4 / 6.5', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.2/x86_64/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/os',
      'content/aus/rhel/server/6/6.2/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.2/x86_64/os',
      'content/aus/rhel/server/6/6.2/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-1.0.0-20.el6_2.8', 'sp':'2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-1.0.0-20.el6_2.8', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-1.0.0-20.el6_2.8', 'sp':'2', 'cpu':'i686', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-1.0.0-20.el6_2.8', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-perl-1.0.0-20.el6_2.8', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-static-1.0.0-20.el6_2.8', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.4/x86_64/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/os',
      'content/aus/rhel/server/6/6.4/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.4/x86_64/os',
      'content/aus/rhel/server/6/6.4/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-1.0.0-27.el6_4.5', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-1.0.0-27.el6_4.5', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-1.0.0-27.el6_4.5', 'sp':'4', 'cpu':'i686', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-1.0.0-27.el6_4.5', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-perl-1.0.0-27.el6_4.5', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-static-1.0.0-27.el6_4.5', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_4', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.5/x86_64/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/os',
      'content/aus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.5/x86_64/os',
      'content/aus/rhel/server/6/6.5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-1.0.1e-16.el6_5.16', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-1.0.1e-16.el6_5.16', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-1.0.1e-16.el6_5.16', 'sp':'5', 'cpu':'i686', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-1.0.1e-16.el6_5.16', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-perl-1.0.1e-16.el6_5.16', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-static-1.0.1e-16.el6_5.16', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-perl / openssl-static');
}
