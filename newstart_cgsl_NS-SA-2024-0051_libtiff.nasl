#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0051. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206852);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2006-2193",
    "CVE-2006-3460",
    "CVE-2006-3461",
    "CVE-2006-3462",
    "CVE-2006-3463",
    "CVE-2006-3464",
    "CVE-2006-3465",
    "CVE-2008-2327",
    "CVE-2009-2285",
    "CVE-2009-2347",
    "CVE-2009-5022",
    "CVE-2010-1411",
    "CVE-2010-2065",
    "CVE-2011-0192",
    "CVE-2011-1167",
    "CVE-2012-1173",
    "CVE-2012-2088",
    "CVE-2012-2113",
    "CVE-2012-3401",
    "CVE-2012-4447",
    "CVE-2012-4564",
    "CVE-2012-5581",
    "CVE-2013-1960",
    "CVE-2013-1961",
    "CVE-2013-4231",
    "CVE-2013-4232",
    "CVE-2013-4243",
    "CVE-2013-4244",
    "CVE-2014-9655",
    "CVE-2015-1547",
    "CVE-2017-9935",
    "CVE-2017-18013",
    "CVE-2018-5784",
    "CVE-2018-7456",
    "CVE-2018-8905",
    "CVE-2018-10963",
    "CVE-2018-17100",
    "CVE-2018-18557",
    "CVE-2018-18661",
    "CVE-2020-35521",
    "CVE-2020-35522",
    "CVE-2020-35523",
    "CVE-2020-35524",
    "CVE-2023-3316",
    "CVE-2023-3618",
    "CVE-2023-26965"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : libtiff Multiple Vulnerabilities (NS-SA-2024-0051)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has libtiff packages installed that are affected by multiple
vulnerabilities:

  - Buffer overflow in the t2p_write_pdf_string function in tiff2pdf in libtiff 3.8.2 and earlier allows
    attackers to cause a denial of service (crash) and possibly execute arbitrary code via a TIFF file with a
    DocumentName tag that contains UTF-8 characters, which triggers the overflow when a character is sign
    extended to an integer that produces more digits than expected in an sprintf call. (CVE-2006-2193)

  - Heap-based buffer overflow in the JPEG decoder in the TIFF library (libtiff) before 3.8.2 allows context-
    dependent attackers to cause a denial of service and possibly execute arbitrary code via an encoded JPEG
    stream that is longer than the scan line size (TiffScanLineSize). (CVE-2006-3460)

  - Heap-based buffer overflow in the PixarLog decoder in the TIFF library (libtiff) before 3.8.2 might allow
    context-dependent attackers to execute arbitrary code via unknown vectors. (CVE-2006-3461)

  - Heap-based buffer overflow in the NeXT RLE decoder in the TIFF library (libtiff) before 3.8.2 might allow
    context-dependent attackers to execute arbitrary code via unknown vectors involving decoding large RLE
    images. (CVE-2006-3462)

  - The EstimateStripByteCounts function in TIFF library (libtiff) before 3.8.2 uses a 16-bit unsigned short
    when iterating over an unsigned 32-bit value, which allows context-dependent attackers to cause a denial
    of service via a large td_nstrips value, which triggers an infinite loop. (CVE-2006-3463)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0051");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2006-2193");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2006-3460");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2006-3461");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2006-3462");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2006-3463");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2006-3464");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2006-3465");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2008-2327");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-2285");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-2347");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2009-5022");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2010-1411");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2010-2065");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2011-0192");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2011-1167");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-1173");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-2088");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-2113");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-3401");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-4447");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-4564");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2012-5581");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-1960");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-1961");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-4231");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-4232");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-4243");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2013-4244");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-9655");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2015-1547");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-18013");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2017-9935");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-10963");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-17100");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-18557");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-18661");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-5784");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-7456");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-8905");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-35521");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-35522");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-35523");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-35524");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-26965");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3316");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3618");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libtiff packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1961");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8905");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    'libtiff-4.0.9-20.el8.cgslv6_2.3.g203f6c2',
    'libtiff-devel-4.0.9-20.el8.cgslv6_2.3.g203f6c2'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff');
}
