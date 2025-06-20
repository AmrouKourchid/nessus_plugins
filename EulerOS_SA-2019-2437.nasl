#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131591);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/08");

  script_cve_id(
    "CVE-2014-1932",
    "CVE-2014-1933",
    "CVE-2014-3007",
    "CVE-2014-3589",
    "CVE-2014-9601",
    "CVE-2016-0740",
    "CVE-2016-0775",
    "CVE-2016-2533",
    "CVE-2016-9189",
    "CVE-2016-9190"
  );
  script_bugtraq_id(
    65511,
    65513,
    67150,
    69352
  );

  script_name(english:"EulerOS 2.0 SP2 : python-pillow (EulerOS-SA-2019-2437)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-pillow package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Pillow before 2.7.0 allows remote attackers to cause a
    denial of service via a compressed text chunk in a PNG
    image that has a large size when it is
    decompressed.(CVE-2014-9601)

  - The (1) load_djpeg function in JpegImagePlugin.py, (2)
    Ghostscript function in EpsImagePlugin.py, (3) load
    function in IptcImagePlugin.py, and (4) _copy function
    in Image.py in Python Image Library (PIL) 1.1.7 and
    earlier and Pillow before 2.3.1 do not properly create
    temporary files, which allow local users to overwrite
    arbitrary files and obtain sensitive information via a
    symlink attack on the temporary file.(CVE-2014-1932)

  - The (1) JpegImagePlugin.py and (2) EpsImagePlugin.py
    scripts in Python Image Library (PIL) 1.1.7 and earlier
    and Pillow before 2.3.1 uses the names of temporary
    files on the command line, which makes it easier for
    local users to conduct symlink attacks by listing the
    processes.(CVE-2014-1933)

  - Python Image Library (PIL) 1.1.7 and earlier and Pillow
    2.3 might allow remote attackers to execute arbitrary
    commands via shell metacharacters in unspecified
    vectors related to CVE-2014-1932, possibly
    JpegImagePlugin.py.(CVE-2014-3007)

  - PIL/IcnsImagePlugin.py in Python Imaging Library (PIL)
    and Pillow before 2.3.2 and 2.5.x before 2.5.2 allows
    remote attackers to cause a denial of service via a
    crafted block size.(CVE-2014-3589)

  - Buffer overflow in the ImagingLibTiffDecode function in
    libImaging/TiffDecode.c in Pillow before 3.1.1 allows
    remote attackers to overwrite memory via a crafted TIFF
    file.(CVE-2016-0740)

  - Buffer overflow in the ImagingFliDecode function in
    libImaging/FliDecode.c in Pillow before 3.1.1 allows
    remote attackers to cause a denial of service (crash)
    via a crafted FLI file.(CVE-2016-0775)

  - Buffer overflow in the ImagingPcdDecode function in
    PcdDecode.c in Pillow before 3.1.1 and Python Imaging
    Library (PIL) 1.1.7 and earlier allows remote attackers
    to cause a denial of service (crash) via a crafted
    PhotoCD file.(CVE-2016-2533)

  - Pillow before 3.3.2 allows context-dependent attackers
    to obtain sensitive information by using the 'crafted
    image file' approach, related to an 'Integer Overflow'
    issue affecting the Image.core.map_buffer in map.c
    component.(CVE-2016-9189)

  - Pillow before 3.3.2 allows context-dependent attackers
    to execute arbitrary code by using the 'crafted image
    file' approach, related to an 'Insecure Sign Extension'
    issue affecting the ImagingNew in Storage.c
    component.(CVE-2016-9190)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2437
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a3bdf53");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pillow packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3007");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-9190");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-pillow");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["python-pillow-2.0.0-19.gitd1c6db8.h3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pillow");
}
