#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1137. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91380);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2016-2108");
  script_xref(name:"RHSA", value:"2016:1137");

  script_name(english:"RHEL 5 : openssl (RHSA-2016:1137)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for openssl.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2016:1137 advisory.

    OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL) and Transport Layer Security (TLS)
    protocols, as well as a full-strength general-purpose cryptography library.

    Security Fix(es):

    * A flaw was found in the way OpenSSL encoded certain ASN.1 data structures. An attacker could use this
    flaw to create a specially crafted certificate which, when verified or re-encoded by OpenSSL, could cause
    it to crash, or execute arbitrary code using the permissions of the user running an application compiled
    against the OpenSSL library. (CVE-2016-2108)

    Red Hat would like to thank the OpenSSL project for reporting this issue. Upstream acknowledges Huzaifa
    Sidhpurwala (Red Hat), Hanno Bck, and David Benjamin (Google) as the original reporters.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2016/rhsa-2016_1137.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f412fe4");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:1137");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1331402");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL openssl package based on the guidance in RHSA-2016:1137.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2108");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/client/5/5Client/i386/debug',
      'content/dist/rhel/client/5/5Client/i386/os',
      'content/dist/rhel/client/5/5Client/i386/source/SRPMS',
      'content/dist/rhel/client/5/5Client/x86_64/debug',
      'content/dist/rhel/client/5/5Client/x86_64/os',
      'content/dist/rhel/client/5/5Client/x86_64/source/SRPMS',
      'content/dist/rhel/power/5/5Server/ppc/debug',
      'content/dist/rhel/power/5/5Server/ppc/os',
      'content/dist/rhel/power/5/5Server/ppc/source/SRPMS',
      'content/dist/rhel/server/5/5Server/i386/debug',
      'content/dist/rhel/server/5/5Server/i386/os',
      'content/dist/rhel/server/5/5Server/i386/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/debug',
      'content/dist/rhel/server/5/5Server/x86_64/os',
      'content/dist/rhel/server/5/5Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/5/5Server/s390x/debug',
      'content/dist/rhel/system-z/5/5Server/s390x/os',
      'content/dist/rhel/system-z/5/5Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/debug',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/debug',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/os',
      'content/dist/rhel/workstation/5/5Client/i386/desktop/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/os',
      'content/dist/rhel/workstation/5/5Client/i386/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/desktop/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/5/i386/debug',
      'content/fastrack/rhel/client/5/i386/os',
      'content/fastrack/rhel/client/5/i386/source/SRPMS',
      'content/fastrack/rhel/client/5/x86_64/debug',
      'content/fastrack/rhel/client/5/x86_64/os',
      'content/fastrack/rhel/client/5/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/5/ppc/debug',
      'content/fastrack/rhel/power/5/ppc/os',
      'content/fastrack/rhel/power/5/ppc/source/SRPMS',
      'content/fastrack/rhel/server/5/i386/debug',
      'content/fastrack/rhel/server/5/i386/os',
      'content/fastrack/rhel/server/5/i386/source/SRPMS',
      'content/fastrack/rhel/server/5/x86_64/debug',
      'content/fastrack/rhel/server/5/x86_64/os',
      'content/fastrack/rhel/server/5/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/5/s390x/debug',
      'content/fastrack/rhel/system-z/5/s390x/os',
      'content/fastrack/rhel/system-z/5/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/5/i386/debug',
      'content/fastrack/rhel/workstation/5/i386/desktop/debug',
      'content/fastrack/rhel/workstation/5/i386/desktop/os',
      'content/fastrack/rhel/workstation/5/i386/desktop/source/SRPMS',
      'content/fastrack/rhel/workstation/5/i386/os',
      'content/fastrack/rhel/workstation/5/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/5/x86_64/debug',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/debug',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/os',
      'content/fastrack/rhel/workstation/5/x86_64/desktop/source/SRPMS',
      'content/fastrack/rhel/workstation/5/x86_64/os',
      'content/fastrack/rhel/workstation/5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-0.9.8e-40.el5_11', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-0.9.8e-40.el5_11', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-0.9.8e-40.el5_11', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-0.9.8e-40.el5_11', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-0.9.8e-40.el5_11', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-0.9.8e-40.el5_11', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-0.9.8e-40.el5_11', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-0.9.8e-40.el5_11', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-0.9.8e-40.el5_11', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-0.9.8e-40.el5_11', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-0.9.8e-40.el5_11', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-0.9.8e-40.el5_11', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-devel-0.9.8e-40.el5_11', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-perl-0.9.8e-40.el5_11', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-perl-0.9.8e-40.el5_11', 'cpu':'ppc', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-perl-0.9.8e-40.el5_11', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'openssl-perl-0.9.8e-40.el5_11', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-perl');
}
