#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140883);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/19");

  script_cve_id(
    "CVE-2018-21247",
    "CVE-2019-20788",
    "CVE-2019-20839",
    "CVE-2020-14397",
    "CVE-2020-14398",
    "CVE-2020-14399",
    "CVE-2020-14400",
    "CVE-2020-14401",
    "CVE-2020-14402",
    "CVE-2020-14403",
    "CVE-2020-14404",
    "CVE-2020-14405"
  );

  script_name(english:"EulerOS 2.0 SP3 : libvncserver (EulerOS-SA-2020-2116)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libvncserver package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - LibVNCServer makes writing a VNC server (or more
    correctly, a program exporting a frame-buffer via the
    Remote Frame Buffer protocol) easy. It hides the
    programmer from the tedious task of managing clients
    and compression schemata.Security Fix(es):An issue was
    discovered in LibVNCServer before 0.9.13. There is an
    information leak (of uninitialized memory contents) in
    the libvncclient/rfbproto.c ConnectToRFBRepeater
    function.(CVE-2018-21247)libvncclient/sockets.c in
    LibVNCServer before 0.9.13 has a buffer overflow via a
    long socket filename.(CVE-2019-20839)An issue was
    discovered in LibVNCServer before 0.9.13.
    libvncserver/rfbregion.c has a NULL pointer
    dereference.(CVE-2020-14397)An issue was discovered in
    LibVNCServer before 0.9.13. An improperly closed TCP
    connection causes an infinite loop in
    libvncclient/sockets.c.(CVE-2020-14398)An issue was
    discovered in LibVNCServer before 0.9.13. Byte-aligned
    data is accessed through uint32_t pointers in
    libvncclient/rfbproto.c. NOTE: there is reportedly 'no
    trust boundary crossed.'(CVE-2020-14399)An issue was
    discovered in LibVNCServer before 0.9.13. Byte-aligned
    data is accessed through uint16_t pointers in
    libvncserver/translate.c. NOTE: Third parties do not
    consider this to be a vulnerability as there is no
    known path of exploitation or cross of a trust
    boundary.(CVE-2020-14400)An issue was discovered in
    LibVNCServer before 0.9.13. libvncserver/scale.c has a
    pixel_value integer overflow.(CVE-2020-14401)An issue
    was discovered in LibVNCServer before 0.9.13.
    libvncserver/corre.c allows out-of-bounds access via
    encodings.(CVE-2020-14402)An issue was discovered in
    LibVNCServer before 0.9.13. libvncserver/hextile.c
    allows out-of-bounds access via
    encodings.(CVE-2020-14403)An issue was discovered in
    LibVNCServer before 0.9.13. libvncserver/rre.c allows
    out-of-bounds access via encodings.(CVE-2020-14404)An
    issue was discovered in LibVNCServer before 0.9.13.
    libvncclient/rfbproto.c does not limit TextChat
    size.(CVE-2020-14405)libvncclient/cursor.c in
    LibVNCServer through 0.9.12 has a HandleCursorShape
    integer overflow and heap-based buffer overflow via a
    large height or width value. (CVE-2019-20788)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2116
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95cb084f");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvncserver packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvncserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libvncserver-0.9.9-12.h12"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvncserver");
}
