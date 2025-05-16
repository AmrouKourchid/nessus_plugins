#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0050. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206854);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2009-0037",
    "CVE-2011-2192",
    "CVE-2012-0036",
    "CVE-2013-0249",
    "CVE-2013-1944",
    "CVE-2013-2174",
    "CVE-2014-0015",
    "CVE-2014-0138",
    "CVE-2014-3613",
    "CVE-2014-3620",
    "CVE-2014-3707",
    "CVE-2014-8150",
    "CVE-2015-3143",
    "CVE-2015-3144",
    "CVE-2015-3145",
    "CVE-2015-3148",
    "CVE-2015-3153",
    "CVE-2015-3236",
    "CVE-2015-3237",
    "CVE-2016-0755",
    "CVE-2016-5419",
    "CVE-2016-5420",
    "CVE-2016-5421",
    "CVE-2016-7167",
    "CVE-2016-8615",
    "CVE-2016-8616",
    "CVE-2016-8617",
    "CVE-2016-8618",
    "CVE-2016-8619",
    "CVE-2016-8620",
    "CVE-2016-8621",
    "CVE-2016-8622",
    "CVE-2016-8623",
    "CVE-2016-8624",
    "CVE-2016-8625",
    "CVE-2016-9586",
    "CVE-2017-2629",
    "CVE-2017-7407",
    "CVE-2017-7468",
    "CVE-2017-8816",
    "CVE-2017-8817",
    "CVE-2017-8818",
    "CVE-2017-1000099",
    "CVE-2017-1000100",
    "CVE-2017-1000101",
    "CVE-2017-1000254",
    "CVE-2017-1000257",
    "CVE-2018-0500",
    "CVE-2018-16839",
    "CVE-2018-16840",
    "CVE-2018-16842",
    "CVE-2018-1000005",
    "CVE-2018-1000007",
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122",
    "CVE-2018-1000300",
    "CVE-2018-1000301",
    "CVE-2023-38546"
  );
  script_xref(name:"IAVA", value:"2023-A-0531-S");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"NewStart CGSL MAIN 6.02 : curl Multiple Vulnerabilities (NS-SA-2024-0050)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has curl packages installed that are affected by multiple
vulnerabilities:

  - The redirect implementation in curl and libcurl 5.11 through 7.19.3, when CURLOPT_FOLLOWLOCATION is
    enabled, accepts arbitrary Location values, which might allow remote HTTP servers to (1) trigger arbitrary
    requests to intranet servers, (2) read or overwrite arbitrary files via a redirect to a file: URL, or (3)
    execute arbitrary commands via a redirect to an scp: URL. (CVE-2009-0037)

  - The Curl_input_negotiate function in http_negotiate.c in libcurl 7.10.6 through 7.21.6, as used in curl
    and other products, always performs credential delegation during GSSAPI authentication, which allows
    remote servers to impersonate clients via GSSAPI requests. (CVE-2011-2192)

  - curl and libcurl 7.2x before 7.24.0 do not properly consider special characters during extraction of a
    pathname from a URL, which allows remote attackers to conduct data-injection attacks via a crafted URL, as
    demonstrated by a CRLF injection attack on the (1) IMAP, (2) POP3, or (3) SMTP protocol. (CVE-2012-0036)

  - Stack-based buffer overflow in the Curl_sasl_create_digest_md5_message function in lib/curl_sasl.c in curl
    and libcurl 7.26.0 through 7.28.1, when negotiating SASL DIGEST-MD5 authentication, allows remote
    attackers to cause a denial of service (crash) and possibly execute arbitrary code via a long string in
    the realm parameter in a (1) POP3, (2) SMTP or (3) IMAP message. (CVE-2013-0249)

  - The tailMatch function in cookie.c in cURL and libcurl before 7.30.0 does not properly match the path
    domain when sending cookies, which allows remote attackers to steal cookies via a matching suffix in the
    domain of a URL. (CVE-2013-1944)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0050");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-0037");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2011-2192");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-0036");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-0249");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-1944");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-2174");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-0015");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-0138");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-3613");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-3620");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-3707");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-8150");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-3143");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-3144");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-3145");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-3148");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-3153");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-3236");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-3237");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-0755");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-5419");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-5420");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-5421");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-7167");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8615");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8616");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8617");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8618");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8619");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8620");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8621");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8622");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8623");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8624");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-8625");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2016-9586");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-1000099");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-1000100");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-1000101");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-1000254");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-1000257");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-2629");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-7407");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-7468");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-8816");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-8817");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-8818");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-0500");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1000005");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1000007");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1000120");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1000121");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1000122");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1000300");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-1000301");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-16839");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-16840");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-16842");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-38546");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL curl packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3144");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16840");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libcurl-devel");
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
    'curl-7.61.1-30.0.2.el8.2.cgslv6_2.4.gc196023',
    'libcurl-7.61.1-30.0.2.el8.2.cgslv6_2.4.gc196023',
    'libcurl-devel-7.61.1-30.0.2.el8.2.cgslv6_2.4.gc196023'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'curl');
}
