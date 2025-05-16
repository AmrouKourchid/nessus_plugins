#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:1789.
##

include('compat.inc');

if (description)
{
  script_id(193280);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id(
    "CVE-2023-4408",
    "CVE-2023-5517",
    "CVE-2023-5679",
    "CVE-2023-6516",
    "CVE-2023-50387",
    "CVE-2023-50868"
  );
  script_xref(name:"ALSA", value:"2024:1789");
  script_xref(name:"IAVA", value:"2024-A-0103-S");

  script_name(english:"AlmaLinux 9 : bind (ALSA-2024:1789)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:1789 advisory.

  - The DNS message parsing code in `named` includes a section whose computational complexity is overly high.
    It does not cause problems for typical DNS traffic, but crafted queries and responses may cause excessive
    CPU load on the affected `named` instance by exploiting this flaw. This issue affects both authoritative
    servers and recursive resolvers. This issue affects BIND 9 versions 9.0.0 through 9.16.45, 9.18.0 through
    9.18.21, 9.19.0 through 9.19.19, 9.9.3-S1 through 9.11.37-S1, 9.16.8-S1 through 9.16.45-S1, and 9.18.11-S1
    through 9.18.21-S1. (CVE-2023-4408)

  - Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote
    attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the
    KeyTrap issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the
    protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG
    records. (CVE-2023-50387)

  - The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC 9276 guidance is skipped)
    allows remote attackers to cause a denial of service (CPU consumption for SHA-1 computations) via DNSSEC
    responses in a random subdomain attack, aka the NSEC3 issue. The RFC 5155 specification implies that an
    algorithm must perform thousands of iterations of a hash function in certain situations. (CVE-2023-50868)

  - A flaw in query-handling code can cause `named` to exit prematurely with an assertion failure when: -
    `nxdomain-redirect <domain>;` is configured, and - the resolver receives a PTR query for an RFC 1918
    address that would normally result in an authoritative NXDOMAIN response. This issue affects BIND 9
    versions 9.12.0 through 9.16.45, 9.18.0 through 9.18.21, 9.19.0 through 9.19.19, 9.16.8-S1 through
    9.16.45-S1, and 9.18.11-S1 through 9.18.21-S1. (CVE-2023-5517)

  - A bad interaction between DNS64 and serve-stale may cause `named` to crash with an assertion failure
    during recursive resolution, when both of these features are enabled. This issue affects BIND 9 versions
    9.16.12 through 9.16.45, 9.18.0 through 9.18.21, 9.19.0 through 9.19.19, 9.16.12-S1 through 9.16.45-S1,
    and 9.18.11-S1 through 9.18.21-S1. (CVE-2023-5679)

  - To keep its cache database efficient, `named` running as a recursive resolver occasionally attempts to
    clean up the database. It uses several methods, including some that are asynchronous: a small chunk of
    memory pointing to the cache element that can be cleaned up is first allocated and then queued for later
    processing. It was discovered that if the resolver is continuously processing query patterns triggering
    this type of cache-database maintenance, `named` may not be able to handle the cleanup events in a timely
    manner. This in turn enables the list of queued cleanup events to grow infinitely large over time,
    allowing the configured `max-cache-size` limit to be significantly exceeded. This issue affects BIND 9
    versions 9.16.0 through 9.16.45 and 9.16.8-S1 through 9.16.45-S1. (CVE-2023-6516)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-1789.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400, 617);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-dnssec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-dnssec-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'bind-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-chroot-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-devel-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-dnssec-doc-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-dnssec-utils-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-doc-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-dyndb-ldap-11.9-8.el9_3.3.alma.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-dyndb-ldap-11.9-8.el9_3.3.alma.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bind-libs-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-license-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-utils-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'python3-bind-9.16.23-14.el9_3.4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-devel / bind-dnssec-doc / etc');
}
