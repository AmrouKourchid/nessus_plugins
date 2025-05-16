#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0060. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206846);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2007-2926",
    "CVE-2007-6283",
    "CVE-2008-0122",
    "CVE-2008-1447",
    "CVE-2009-0025",
    "CVE-2009-0696",
    "CVE-2010-0213",
    "CVE-2011-1907",
    "CVE-2011-1910",
    "CVE-2011-4313",
    "CVE-2012-1667",
    "CVE-2013-2266",
    "CVE-2013-3919",
    "CVE-2014-0591",
    "CVE-2014-8500",
    "CVE-2015-5477",
    "CVE-2015-8704",
    "CVE-2015-8705",
    "CVE-2016-1285",
    "CVE-2016-1286",
    "CVE-2016-2088",
    "CVE-2017-3145",
    "CVE-2018-5738",
    "CVE-2018-5740",
    "CVE-2018-5744",
    "CVE-2022-2795",
    "CVE-2023-2828",
    "CVE-2023-3341"
  );
  script_xref(name:"IAVA", value:"2008-A-0045");
  script_xref(name:"IAVA", value:"2011-A-0158-S");
  script_xref(name:"IAVA", value:"2012-A-0106-S");
  script_xref(name:"IAVA", value:"2013-A-0069-S");
  script_xref(name:"IAVA", value:"2013-A-0116-S");
  script_xref(name:"IAVA", value:"2014-A-0086-S");
  script_xref(name:"IAVA", value:"2014-A-0196-S");
  script_xref(name:"IAVA", value:"2015-A-0181-S");
  script_xref(name:"IAVA", value:"2016-A-0032-S");
  script_xref(name:"IAVA", value:"2016-A-0074-S");
  script_xref(name:"IAVA", value:"2018-A-0024-S");
  script_xref(name:"IAVA", value:"2018-A-0255-S");
  script_xref(name:"IAVA", value:"2018-A-0303-S");
  script_xref(name:"IAVA", value:"2019-A-0069-S");
  script_xref(name:"IAVA", value:"2022-A-0387-S");
  script_xref(name:"IAVA", value:"2023-A-0320-S");
  script_xref(name:"IAVA", value:"2023-A-0500-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : bind Multiple Vulnerabilities (NS-SA-2024-0060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has bind packages installed that are affected by multiple
vulnerabilities:

  - ISC BIND 9 through 9.5.0a5 uses a weak random number generator during generation of DNS query ids when
    answering resolver questions or sending NOTIFY messages to slave name servers, which makes it easier for
    remote attackers to guess the next query id and perform DNS cache poisoning. (CVE-2007-2926)

  - Red Hat Enterprise Linux 5 and Fedora install the Bind /etc/rndc.key file with world-readable permissions,
    which allows local users to perform unauthorized named commands, such as causing a denial of service by
    stopping named. (CVE-2007-6283)

  - Off-by-one error in the inet_network function in libbind in ISC BIND 9.4.2 and earlier, as used in libc in
    FreeBSD 6.2 through 7.0-PRERELEASE, allows context-dependent attackers to cause a denial of service
    (crash) and possibly execute arbitrary code via crafted input that triggers memory corruption.
    (CVE-2008-0122)

  - The DNS protocol, as implemented in (1) BIND 8 and 9 before 9.5.0-P1, 9.4.2-P1, and 9.3.5-P1; (2)
    Microsoft DNS in Windows 2000 SP4, XP SP2 and SP3, and Server 2003 SP1 and SP2; and other implementations
    allow remote attackers to spoof DNS traffic via a birthday attack that uses in-bailiwick referrals to
    conduct cache poisoning against recursive resolvers, related to insufficient randomness of DNS transaction
    IDs and source ports, aka DNS Insufficient Socket Entropy Vulnerability or the Kaminsky bug.
    (CVE-2008-1447)

  - BIND 9.6.0, 9.5.1, 9.5.0, 9.4.3, and earlier does not properly check the return value from the OpenSSL
    DSA_verify function, which allows remote attackers to bypass validation of the certificate chain via a
    malformed SSL/TLS signature, a similar vulnerability to CVE-2008-5077. (CVE-2009-0025)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0060");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2007-2926");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2007-6283");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2008-0122");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2008-1447");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-0025");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-0696");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2010-0213");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2011-1907");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2011-1910");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2011-4313");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-1667");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-2266");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-3919");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-0591");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-8500");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-5477");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-8704");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-8705");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-1285");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-1286");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-2088");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-3145");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-5738");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-5740");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-5744");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2795");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2828");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3341");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0122");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-5738");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2022-2795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
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

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'bind-9.11.36-8.el8.cgslv6_2.2.g0e84ae1',
    'bind-export-libs-9.11.36-8.el8.cgslv6_2.2.g0e84ae1',
    'bind-libs-9.11.36-8.el8.cgslv6_2.2.g0e84ae1',
    'bind-libs-lite-9.11.36-8.el8.cgslv6_2.2.g0e84ae1',
    'bind-license-9.11.36-8.el8.cgslv6_2.2.g0e84ae1',
    'bind-utils-9.11.36-8.el8.cgslv6_2.2.g0e84ae1',
    'python3-bind-9.11.36-8.el8.cgslv6_2.2.g0e84ae1'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind');
}
