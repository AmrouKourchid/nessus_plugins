#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212600);
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

  script_name(english:"EulerOS 2.0 SP12 : syslinux (EulerOS-SA-2024-2958)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the syslinux packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    Integer underflow in the png_check_keyword function in pngwutil.c in libpng 0.90 through 0.99, 1.0.x
    before 1.0.66, 1.1.x and 1.2.x before 1.2.56, 1.3.x and 1.4.x before 1.4.19, and 1.5.x before 1.5.26
    allows remote attackers to have unspecified impact via a space character as a keyword in a PNG image,
    which triggers an out-of-bounds read.(CVE-2015-8540)

    Buffer overflow in the png_set_PLTE function in libpng before 1.0.65, 1.1.x and 1.2.x before 1.2.55,
    1.3.x, 1.4.x before 1.4.18, 1.5.x before 1.5.25, and 1.6.x before 1.6.20 allows remote attackers to cause
    a denial of service (application crash) or possibly have unspecified other impact via a small bit-depth
    value in an IHDR (aka image header) chunk in a PNG image.  NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2015-8126.(CVE-2015-8472)

    Integer signedness error in the png_inflate function in pngrutil.c in libpng before 1.4.10beta01, as used
    in Google Chrome before 17.0.963.83 and other products, allows remote attackers to cause a denial of
    service (application crash) or possibly execute arbitrary code via a crafted PNG file, a different
    vulnerability than CVE-2011-3026.(CVE-2011-3045)

    The png_set_text_2 function in pngset.c in libpng 1.0.x before 1.0.59, 1.2.x before 1.2.49, 1.4.x before
    1.4.11, and 1.5.x before 1.5.10 allows remote attackers to cause a denial of service (crash) or execute
    arbitrary code via a crafted text chunk in a PNG image file, which triggers a memory allocation failure
    that is not properly handled, leading to a heap-based buffer overflow.(CVE-2011-3048)

    Multiple buffer overflows in the (1) png_set_PLTE and (2) png_get_PLTE functions in libpng before 1.0.64,
    1.1.x and 1.2.x before 1.2.54, 1.3.x and 1.4.x before 1.4.17, 1.5.x before 1.5.24, and 1.6.x before 1.6.19
    allow remote attackers to cause a denial of service (application crash) or possibly have unspecified other
    impact via a small bit-depth value in an IHDR (aka image header) chunk in a PNG image.(CVE-2015-8126)

    The png_format_buffer function in pngerror.c in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x
    before 1.4.8, and 1.5.x before 1.5.4 allows remote attackers to cause a denial of service (application
    crash) via a crafted PNG image that triggers an out-of-bounds read during the copying of error-message
    data.  NOTE: this vulnerability exists because of a CVE-2004-0421 regression. NOTE: this is called an off-
    by-one error by some sources.(CVE-2011-2501)

    The png_err function in pngerror.c in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8,
    and 1.5.x before 1.5.4 makes a function call using a NULL pointer argument instead of an empty-string
    argument, which allows remote attackers to cause a denial of service (application crash) via a crafted PNG
    image.(CVE-2011-2691)

    The png_handle_sCAL function in pngrutil.c in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x
    before 1.4.8, and 1.5.x before 1.5.4 does not properly handle invalid sCAL chunks, which allows remote
    attackers to cause a denial of service (memory corruption and application crash) or possibly have
    unspecified other impact via a crafted PNG image that triggers the reading of uninitialized
    memory.(CVE-2011-2692)

    Buffer overflow in libpng 1.0.x before 1.0.55, 1.2.x before 1.2.45, 1.4.x before 1.4.8, and 1.5.x before
    1.5.4, when used by an application that calls the png_rgb_to_gray function but not the png_set_expand
    function, allows remote attackers to overwrite memory with an arbitrary amount of data, and possibly have
    unspecified other impact, via a crafted PNG image.(CVE-2011-2690)

    The png_convert_to_rfc1123 function in png.c in libpng 1.0.x before 1.0.64, 1.2.x before 1.2.54, and 1.4.x
    before 1.4.17 allows remote attackers to obtain sensitive process memory information via crafted tIME
    chunk data in an image file, which triggers an out-of-bounds read.(CVE-2015-7981)

    The png_push_read_zTXt function in pngpread.c in libpng 1.0.x before 1.0.58, 1.2.x before 1.2.48, 1.4.x
    before 1.4.10, and 1.5.x before 1.5.10 allows remote attackers to cause a denial of service (out-of-bounds
    read) via a large avail_in field value in a PNG image.(CVE-2012-3425)

    The png_set_text_2 function in libpng 0.71 before 1.0.67, 1.2.x before 1.2.57, 1.4.x before 1.4.20, 1.5.x
    before 1.5.28, and 1.6.x before 1.6.27 allows context-dependent attackers to cause a NULL pointer
    dereference vectors involving loading a text chunk into a png structure, removing the text, and then
    adding another text chunk to the structure.(CVE-2016-10087)

    libpng before 1.6.32 does not properly check the length of chunks against the user limit.(CVE-2017-12652)

Tenable has extracted the preceding description block directly from the EulerOS syslinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2958
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ada5fcc4");
  script_set_attribute(attribute:"solution", value:
"Update the affected syslinux packages.");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:syslinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:syslinux-nonlinux");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(12)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "syslinux-6.04-13.h3.eulerosv2r12",
  "syslinux-nonlinux-6.04-13.h3.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"12", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "syslinux");
}
