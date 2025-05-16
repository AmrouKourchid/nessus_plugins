#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0011. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193540);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id(
    "CVE-2008-1447",
    "CVE-2009-2957",
    "CVE-2009-2958",
    "CVE-2013-0198",
    "CVE-2020-25684",
    "CVE-2020-25685",
    "CVE-2020-25686",
    "CVE-2023-28450"
  );
  script_xref(name:"IAVA", value:"2021-A-0041");
  script_xref(name:"CEA-ID", value:"CEA-2021-0003");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : dnsmasq Multiple Vulnerabilities (NS-SA-2024-0011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has dnsmasq packages installed that are affected
by multiple vulnerabilities:

  - The DNS protocol, as implemented in (1) BIND 8 and 9 before 9.5.0-P1, 9.4.2-P1, and 9.3.5-P1; (2)
    Microsoft DNS in Windows 2000 SP4, XP SP2 and SP3, and Server 2003 SP1 and SP2; and other implementations
    allow remote attackers to spoof DNS traffic via a birthday attack that uses in-bailiwick referrals to
    conduct cache poisoning against recursive resolvers, related to insufficient randomness of DNS transaction
    IDs and source ports, aka DNS Insufficient Socket Entropy Vulnerability or the Kaminsky bug.
    (CVE-2008-1447)

  - Heap-based buffer overflow in the tftp_request function in tftp.c in dnsmasq before 2.50, when --enable-
    tftp is used, might allow remote attackers to execute arbitrary code via a long filename in a TFTP packet,
    as demonstrated by a read (aka RRQ) request. (CVE-2009-2957)

  - The tftp_request function in tftp.c in dnsmasq before 2.50, when --enable-tftp is used, allows remote
    attackers to cause a denial of service (NULL pointer dereference and daemon crash) via a TFTP read (aka
    RRQ) request with a malformed blksize option. (CVE-2009-2958)

  - Dnsmasq before 2.66test2, when used with certain libvirt configurations, replies to queries from
    prohibited interfaces, which allows remote attackers to cause a denial of service (traffic amplification)
    via spoofed TCP based DNS queries. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2012-3411. (CVE-2013-0198)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in the forward.c:reply_query() if the reply destination address/port is used by the pending
    forwarded queries. However, it does not use the address/port to retrieve the exact forwarded query,
    substantially reducing the number of attempts an attacker on the network would have to perform to forge a
    reply and get it accepted by dnsmasq. This issue contrasts with RFC5452, which specifies a query's
    attributes that all must be used to match a reply. This flaw allows an attacker to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25685 or CVE-2020-25686, the attack complexity of a successful
    attack is reduced. The highest threat from this vulnerability is to data integrity. (CVE-2020-25684)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in forward.c:reply_query(), which is the forwarded query that matches the reply, by only using a
    weak hash of the query name. Due to the weak hash (CRC32 when dnsmasq is compiled without DNSSEC, SHA-1
    when it is) this flaw allows an off-path attacker to find several different domains all having the same
    hash, substantially reducing the number of attempts they would have to perform to forge a reply and get it
    accepted by dnsmasq. This is in contrast with RFC5452, which specifies that the query name is one of the
    attributes of a query that must be used to match a reply. This flaw could be abused to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25684 the attack complexity of a successful attack is reduced.
    The highest threat from this vulnerability is to data integrity. (CVE-2020-25685)

  - A flaw was found in dnsmasq before version 2.83. When receiving a query, dnsmasq does not check for an
    existing pending request for the same name and forwards a new request. By default, a maximum of 150
    pending queries can be sent to upstream servers, so there can be at most 150 queries for the same name.
    This flaw allows an off-path attacker on the network to substantially reduce the number of attempts that
    it would have to perform to forge a reply and have it accepted by dnsmasq. This issue is mentioned in the
    Birthday Attacks section of RFC5452. If chained with CVE-2020-25684, the attack complexity of a
    successful attack is reduced. The highest threat from this vulnerability is to data integrity.
    (CVE-2020-25686)

  - An issue was discovered in Dnsmasq before 2.90. The default maximum EDNS.0 UDP packet size was set to 4096
    but should be 1232 because of DNS Flag Day 2020. (CVE-2023-28450)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0011");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2008-1447");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-2957");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-2958");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-0198");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-25684");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-25685");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-25686");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-28450");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL dnsmasq packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2957");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2008-1447");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'dnsmasq-2.76-16.el7_9.1.cgslv5_4.0.2.gdcbca5c',
    'dnsmasq-debuginfo-2.76-16.el7_9.1.cgslv5_4.0.2.gdcbca5c',
    'dnsmasq-utils-2.76-16.el7_9.1.cgslv5_4.0.2.gdcbca5c'
  ],
  'CGSL MAIN 5.04': [
    'dnsmasq-2.76-16.el7_9.1.cgslv5_4.0.2.gdcbca5c',
    'dnsmasq-debuginfo-2.76-16.el7_9.1.cgslv5_4.0.2.gdcbca5c',
    'dnsmasq-utils-2.76-16.el7_9.1.cgslv5_4.0.2.gdcbca5c'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnsmasq');
}
