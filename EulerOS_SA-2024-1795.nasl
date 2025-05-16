#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198318);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id(
    "CVE-2023-4408",
    "CVE-2023-5517",
    "CVE-2023-5679",
    "CVE-2023-6516",
    "CVE-2023-50387",
    "CVE-2023-50868"
  );
  script_xref(name:"IAVA", value:"2024-A-0103-S");

  script_name(english:"EulerOS 2.0 SP11 : bind (EulerOS-SA-2024-1795)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

    To keep its cache database efficient, `named` running as a recursive resolver occasionally attempts to
    clean up the database. It uses several methods, including some that are asynchronous: a small chunk of
    memory pointing to the cache element that can be cleaned up is first allocated and then queued for later
    processing. It was discovered that if the resolver is continuously processing query patterns triggering
    this type of cache-database maintenance, `named` may not be able to handle the cleanup events in a timely
    manner. This in turn enables the list of queued cleanup events to grow infinitely large over time,
    allowing the configured `max-cache-size` limit to be significantly exceeded.(CVE-2023-6516)

    A bad interaction between DNS64 and serve-stale may cause `named` to crash with an assertion failure
    during recursive resolution, when both of these features are enabled.(CVE-2023-5679)

    A flaw in query-handling code can cause `named` to exit prematurely with an assertion failure when: -
    `nxdomain-redirect domain;` is configured, and - the resolver receives a PTR query for an RFC 1918
    address that would normally result in an authoritative NXDOMAIN response. (CVE-2023-5517)

    The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC 9276 guidance is skipped)
    allows remote attackers to cause a denial of service (CPU consumption for SHA-1 computations) via DNSSEC
    responses in a random subdomain attack, aka the 'NSEC3' issue. The RFC 5155 specification implies that an
    algorithm must perform thousands of iterations of a hash function in certain situations.(CVE-2023-50868)

    Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote
    attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the
    'KeyTrap' issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the
    protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG
    records.(CVE-2023-50387)

    The DNS message parsing code in `named` includes a section whose computational complexity is overly high.
    It does not cause problems for typical DNS traffic, but crafted queries and responses may cause excessive
    CPU load on the affected `named` instance by exploiting this flaw. This issue affects both authoritative
    servers and recursive resolvers.(CVE-2023-4408)

Tenable has extracted the preceding description block directly from the EulerOS bind security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1795
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5b68a71");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-dnssec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-dnssec-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "bind-9.16.23-6.h21.eulerosv2r11",
  "bind-chroot-9.16.23-6.h21.eulerosv2r11",
  "bind-dnssec-doc-9.16.23-6.h21.eulerosv2r11",
  "bind-dnssec-utils-9.16.23-6.h21.eulerosv2r11",
  "bind-libs-9.16.23-6.h21.eulerosv2r11",
  "bind-license-9.16.23-6.h21.eulerosv2r11",
  "bind-pkcs11-9.16.23-6.h21.eulerosv2r11",
  "bind-pkcs11-libs-9.16.23-6.h21.eulerosv2r11",
  "bind-pkcs11-utils-9.16.23-6.h21.eulerosv2r11",
  "bind-utils-9.16.23-6.h21.eulerosv2r11",
  "python3-bind-9.16.23-6.h21.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
