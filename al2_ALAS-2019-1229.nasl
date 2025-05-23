#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1229.
#

include('compat.inc');

if (description)
{
  script_id(125901);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/16");

  script_cve_id(
    "CVE-2018-18511",
    "CVE-2019-11691",
    "CVE-2019-11692",
    "CVE-2019-11693",
    "CVE-2019-11698",
    "CVE-2019-5798",
    "CVE-2019-7317",
    "CVE-2019-9797",
    "CVE-2019-9800",
    "CVE-2019-9817",
    "CVE-2019-9819",
    "CVE-2019-9820"
  );
  script_xref(name:"ALAS", value:"2019-1229");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2019-1229)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Mozilla: Buffer overflow in WebGL bufferdata on Linux (CVE-2019-11693)

Mozilla: Use-after-free in XMLHttpRequest (CVE-2019-11691)

Cross-origin images can be read in violation of the same-origin policy
by exporting an image after using createImageBitmap to read the image
and then rendering the resulting bitmap image within a canvas element.
This vulnerability affects Firefox < 66. (CVE-2019-9797)

Mozilla: Memory safety bugs fixed in Firefox 67 and Firefox ESR 60.7
(CVE-2019-9800)

Mozilla: Use-after-free removing listeners in the event listener
manager (CVE-2019-11692)

Mozilla: Use-after-free of ChromeEventHandler by DocShell
(CVE-2019-9820)

Mozilla: Compartment mismatch with fetch API (CVE-2019-9819)

Lack of correct bounds checking in Skia in Google Chrome prior to
73.0.3683.75 allowed a remote attacker to perform an out of bounds
memory read via a crafted HTML page. (CVE-2019-5798)

Mozilla: Theft of user history data through drag and drop of
hyperlinks to and from bookmarks (CVE-2019-11698)

png_image_free in png.c in libpng 1.6.36 has a use-after-free because
png_image_free_function is called under png_safe_execute.
(CVE-2019-9817)

libpng: use-after-free in png_image_free in png.c (CVE-2019-7317)

Cross-origin images can be read from a canvas element in violation of
the same-origin policy using the transferFromImageBitmap method.
*Note: This only affects Firefox 65. Previous versions are
unaffected.*. This vulnerability affects Firefox < 65.0.1.
(CVE-2018-18511)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1229.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update thunderbird' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9820");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-60.7.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-60.7.0-1.amzn2.0.1", allowmaj:TRUE)) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
