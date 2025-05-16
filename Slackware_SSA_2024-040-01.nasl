#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2024-040-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190377);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/09");

  script_cve_id(
    "CVE-2018-7453",
    "CVE-2018-16369",
    "CVE-2022-36561",
    "CVE-2022-41844",
    "CVE-2023-2662",
    "CVE-2023-2663",
    "CVE-2023-2664",
    "CVE-2023-3044",
    "CVE-2023-3436"
  );

  script_name(english:"Slackware Linux 15.0 / current xpdf  Multiple Vulnerabilities (SSA:2024-040-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to xpdf.");
  script_set_attribute(attribute:"description", value:
"The version of xpdf installed on the remote host is prior to 4.05. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2024-040-01 advisory.

  - XRef::fetch in XRef.cc in Xpdf 4.00 allows remote attackers to cause a denial of service (stack
    consumption) via a crafted pdf file, related to AcroForm::scanField, as demonstrated by pdftohtml. NOTE:
    this might overlap CVE-2018-7453. (CVE-2018-16369)

  - Infinite recursion in AcroForm::scanField in AcroForm.cc in xpdf 4.00 allows attackers to launch denial of
    service via a specific pdf file due to lack of loop checking, as demonstrated by pdftohtml.
    (CVE-2018-7453)

  - XPDF v4.0.4 was discovered to contain a segmentation violation via the component /xpdf/AcroForm.cc:538.
    (CVE-2022-36561)

  - An issue was discovered in Xpdf 4.04. There is a crash in XRef::fetch(int, int, Object*, int) in
    xpdf/XRef.cc, a different vulnerability than CVE-2018-16369 and CVE-2019-16088. (CVE-2022-41844)

  - In Xpdf 4.04 (and earlier), a bad color space object in the input PDF file can cause a divide-by-zero.
    (CVE-2023-2662)

  - In Xpdf 4.04 (and earlier), a PDF object loop in the page label tree leads to infinite recursion and a
    stack overflow. (CVE-2023-2663)

  - In Xpdf 4.04 (and earlier), a PDF object loop in the embedded file tree leads to infinite recursion and a
    stack overflow. (CVE-2023-2664)

  - An excessively large PDF page size (found in fuzz testing, unlikely in normal PDF files) can result in a
    divide-by-zero in Xpdf's text extraction code. This is related to CVE-2022-30524, but the problem here is
    caused by a very large page size, rather than by a very large character coordinate. (CVE-2023-3044)

  - Xpdf 4.04 will deadlock on a PDF object stream whose Length field is itself in another object stream.
    (CVE-2023-3436)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.436503
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3a0029f");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected xpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7453");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2664");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '4.05', 'product' : 'xpdf', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '4.05', 'product' : 'xpdf', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '4.05', 'product' : 'xpdf', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '4.05', 'product' : 'xpdf', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach var constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
