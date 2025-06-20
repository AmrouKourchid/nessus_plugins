#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0158. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127438);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/07");

  script_cve_id(
    "CVE-2018-18511",
    "CVE-2019-5798",
    "CVE-2019-7317",
    "CVE-2019-9797",
    "CVE-2019-9800",
    "CVE-2019-9817",
    "CVE-2019-9819",
    "CVE-2019-9820",
    "CVE-2019-11691",
    "CVE-2019-11692",
    "CVE-2019-11693",
    "CVE-2019-11698"
  );
  script_bugtraq_id(107009);
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0158)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - png_image_free in png.c in libpng 1.6.36 has a use-
    after-free because png_image_free_function is called
    under png_safe_execute. (CVE-2019-7317)

  - If a crafted hyperlink is dragged and dropped to the
    bookmark bar or sidebar and the resulting bookmark is
    subsequently dragged and dropped into the web content
    area, an arbitrary query of a user's browser history can
    be run and transmitted to the content page via drop
    event data. This allows for the theft of browser history
    by a malicious site. This vulnerability affects
    Thunderbird < 60.7, Firefox < 67, and Firefox ESR <
    60.7. (CVE-2019-11698)

  - Lack of correct bounds checking in Skia in Google Chrome
    prior to 73.0.3683.75 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML
    page. (CVE-2019-5798)

  - Cross-origin images can be read from a canvas element in
    violation of the same-origin policy using the
    transferFromImageBitmap method. *Note: This only affects
    Firefox 65. Previous versions are unaffected.*. This
    vulnerability affects Firefox < 65.0.1. (CVE-2018-18511)

  - A use-after-free vulnerability can occur when working
    with XMLHttpRequest (XHR) in an event loop, causing the
    XHR main thread to be called after it has been freed.
    This results in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 60.7, Firefox < 67,
    and Firefox ESR < 60.7. (CVE-2019-11691)

  - A use-after-free vulnerability can occur when listeners
    are removed from the event listener manager while still
    in use, resulting in a potentially exploitable crash.
    This vulnerability affects Thunderbird < 60.7, Firefox <
    67, and Firefox ESR < 60.7. (CVE-2019-11692)

  - The bufferdata function in WebGL is vulnerable to a
    buffer overflow with specific graphics drivers on Linux.
    This could result in malicious content freezing a tab or
    triggering a potentially exploitable crash. *Note: this
    issue only occurs on Linux. Other operating systems are
    unaffected.*. This vulnerability affects Thunderbird <
    60.7, Firefox < 67, and Firefox ESR < 60.7.
    (CVE-2019-11693)

  - Cross-origin images can be read in violation of the
    same-origin policy by exporting an image after using
    createImageBitmap to read the image and then rendering
    the resulting bitmap image within a canvas element. This
    vulnerability affects Firefox < 66. (CVE-2019-9797)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 66, Firefox ESR 60.6, and
    Thunderbird 60.6. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    that some of these could be exploited to run arbitrary
    code. This vulnerability affects Thunderbird < 60.7,
    Firefox < 67, and Firefox ESR < 60.7. (CVE-2019-9800)

  - Images from a different domain can be read using a
    canvas object in some circumstances. This could be used
    to steal image data from a different site in violation
    of same-origin policy. This vulnerability affects
    Thunderbird < 60.7, Firefox < 67, and Firefox ESR <
    60.7. (CVE-2019-9817)

  - A vulnerability where a JavaScript compartment mismatch
    can occur while working with the fetch API, resulting in
    a potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7, Firefox < 67, and Firefox
    ESR < 60.7. (CVE-2019-9819)

  - A use-after-free vulnerability can occur in the chrome
    event handler when it is freed while still in use. This
    results in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 60.7, Firefox < 67,
    and Firefox ESR < 60.7. (CVE-2019-9820)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0158");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9820");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "thunderbird-60.7.0-1.el7.centos",
    "thunderbird-debuginfo-60.7.0-1.el7.centos"
  ],
  "CGSL MAIN 5.04": [
    "thunderbird-60.7.0-1.el7.centos",
    "thunderbird-debuginfo-60.7.0-1.el7.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
