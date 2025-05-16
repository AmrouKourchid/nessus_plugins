#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212639);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2011-2501",
    "CVE-2011-2690",
    "CVE-2011-2691",
    "CVE-2011-2692",
    "CVE-2011-3045",
    "CVE-2011-3048",
    "CVE-2012-3425",
    "CVE-2015-7981",
    "CVE-2015-8126",
    "CVE-2015-8472",
    "CVE-2015-8540",
    "CVE-2016-10087",
    "CVE-2017-12652"
  );

  script_name(english:"EulerOS 2.0 SP11 : unbound (EulerOS-SA-2024-2973)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the unbound packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    DISPUTE NOTE: this issue does not pose a security risk as it (according to analysis by the original
    software developer, NLnet Labs) falls within the expected functionality and security controls of the
    application. Red Hat has made a claim that there is a security risk within Red Hat products. NLnet Labs
    has no further information about the claim, and suggests that affected Red Hat customers refer to
    available Red Hat documentation or support channels. ORIGINAL DESCRIPTION: A heap-buffer-overflow flaw was
    found in the cfg_mark_ports function within Unbound's config_file.c, which can lead to memory corruption.
    This issue could allow an attacker with local access to provide specially crafted input, potentially
    causing the application to crash or allowing arbitrary code execution. This could result in a denial of
    service or unauthorized actions on the system.(CVE-2024-43168)

    NLnet Labs Unbound up to and including version 1.21.0 contains a vulnerability when handling replies with
    very large RRsets that it needs to perform name compression for. Malicious upstreams responses with very
    large RRsets can cause Unbound to spend a considerable time applying name compression to downstream
    replies. This can lead to degraded performance and eventually denial of service in well orchestrated
    attacks. The vulnerability can be exploited by a malicious actor querying Unbound for the specially
    crafted contents of a malicious zone with very large RRsets. Before Unbound replies to the query it will
    try to apply name compression which was an unbounded operation that could lock the CPU until the whole
    packet was complete. Unbound version 1.21.1 introduces a hard limit on the number of name compression
    calculations it is willing to do per packet. Packets that need more compression will result in semi-
    compressed packets or truncated packets, even on TCP for huge messages, to avoid locking the CPU for long.
    This change should not affect normal DNS traffic.(CVE-2024-8508)

    The DNS protocol in RFC 1035 and updates allows remote attackers to cause a denial of service (resource
    consumption) by arranging for DNS queries to be accumulated for seconds, such that responses are later
    sent in a pulsing burst (which can be considered traffic amplification in some cases), aka the 'DNSBomb'
    issue.(CVE-2024-33655)

Tenable has extracted the preceding description block directly from the EulerOS unbound security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2973
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88d12e7d");
  script_set_attribute(attribute:"solution", value:
"Update the affected unbound packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8540");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-12652");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "python3-unbound-1.13.2-3.h9.eulerosv2r11",
  "unbound-1.13.2-3.h9.eulerosv2r11",
  "unbound-libs-1.13.2-3.h9.eulerosv2r11"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unbound");
}
