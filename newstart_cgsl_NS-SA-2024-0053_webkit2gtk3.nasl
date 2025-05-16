#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0053. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206839);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2020-13558",
    "CVE-2020-27918",
    "CVE-2020-29623",
    "CVE-2021-1765",
    "CVE-2021-1788",
    "CVE-2021-1789",
    "CVE-2021-1799",
    "CVE-2021-1801",
    "CVE-2021-1844",
    "CVE-2021-1870",
    "CVE-2021-1871",
    "CVE-2021-21775",
    "CVE-2021-21779",
    "CVE-2021-21806",
    "CVE-2021-30663",
    "CVE-2021-30665",
    "CVE-2021-30682",
    "CVE-2021-30689",
    "CVE-2021-30720",
    "CVE-2021-30734",
    "CVE-2021-30744",
    "CVE-2021-30749",
    "CVE-2021-30758",
    "CVE-2021-30795",
    "CVE-2021-30797",
    "CVE-2021-30799",
    "CVE-2021-30809",
    "CVE-2021-30818",
    "CVE-2021-30823",
    "CVE-2021-30836",
    "CVE-2021-30846",
    "CVE-2021-30848",
    "CVE-2021-30849",
    "CVE-2021-30851",
    "CVE-2021-30858",
    "CVE-2021-30884",
    "CVE-2021-30887",
    "CVE-2021-30888",
    "CVE-2021-30889",
    "CVE-2021-30890",
    "CVE-2021-30897",
    "CVE-2021-30934",
    "CVE-2021-30936",
    "CVE-2021-30951",
    "CVE-2021-30952",
    "CVE-2021-30953",
    "CVE-2021-30954",
    "CVE-2021-30984",
    "CVE-2021-45481",
    "CVE-2021-45482",
    "CVE-2021-45483",
    "CVE-2022-22589",
    "CVE-2022-22590",
    "CVE-2022-22592",
    "CVE-2022-22594",
    "CVE-2022-22620",
    "CVE-2022-22637"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"NewStart CGSL MAIN 6.02 : webkit2gtk3 Multiple Vulnerabilities (NS-SA-2024-0053)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has webkit2gtk3 packages installed that are affected by
multiple vulnerabilities:

  - A use-after-free issue was found in the AudioSourceProviderGStreamer class of WebKitGTK and WPE WebKit in
    versions prior to 2.30.5. Processing maliciously crafted web content may lead to arbitrary code execution.
    The highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2020-13558)

  - A use-after-free issue was found in WebKitGTK and WPE WebKit in versions prior to 2.30.6. Processing
    maliciously crafted web content may lead to arbitrary code execution. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-27918)

  - A flaw was found in WebKitGTK and WPE WebKit in versions prior to 2.30.6. A user may be unable to fully
    delete the browsing history under some circumstances. The highest threat from this vulnerability is to
    data confidentiality. (CVE-2020-29623)

  - A flaw was found in WebKitGTK and WPE WebKit in versions prior to 2.30.6. Maliciously crafted web content
    may violate the iframe sandboxing policy. The highest threat from this vulnerability is to data integrity.
    (CVE-2021-1765, CVE-2021-1801)

  - A use-after-free issue was found in WebKitGTK and WPE WebKit in versions prior to 2.32.0. Processing
    maliciously crafted web content may lead to arbitrary code execution. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2021-1788)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0053");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-13558");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-27918");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-29623");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-1765");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-1788");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-1789");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-1799");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-1801");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-1844");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-1870");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-1871");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-21775");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-21779");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-21806");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30663");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30665");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30682");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30689");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30720");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30734");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30744");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30749");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30758");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30795");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30797");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30799");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30809");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30818");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30823");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30836");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30846");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30848");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30849");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30851");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30858");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30884");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30887");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30888");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30889");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30890");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30897");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30934");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30936");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30951");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30952");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30953");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30954");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-30984");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-45481");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-45482");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-45483");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22589");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22590");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22592");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22594");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22620");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-22637");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL webkit2gtk3 packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30954");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-jsc-devel");
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
    'webkit2gtk3-2.34.6-1.el8',
    'webkit2gtk3-devel-2.34.6-1.el8',
    'webkit2gtk3-jsc-2.34.6-1.el8',
    'webkit2gtk3-jsc-devel-2.34.6-1.el8'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkit2gtk3');
}
