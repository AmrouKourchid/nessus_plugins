#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134477);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/22");

  script_cve_id(
    "CVE-2008-3521",
    "CVE-2016-8884",
    "CVE-2016-8887",
    "CVE-2016-9393",
    "CVE-2016-9397",
    "CVE-2016-9398",
    "CVE-2016-10250",
    "CVE-2017-6850",
    "CVE-2017-6852",
    "CVE-2017-13747",
    "CVE-2017-13752",
    "CVE-2017-1000050"
  );
  script_bugtraq_id(31470);

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : jasper (EulerOS-SA-2020-1188)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the jasper package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Runtime libraries for jasper. Security Fix(es):Race
    condition in the jas_stream_tmpfile function in
    libjasper/base/jas_stream.c in JasPer 1.900.1 allows
    local users to cause a denial of service (program exit)
    by creating the appropriate tmp.XXXXXXXXXX temporary
    file, which causes Jasper to exit. NOTE: this was
    originally reported as a symlink issue, but this was
    incorrect. NOTE: some vendors dispute the severity of
    this issue, but it satisfies CVE's requirements for
    inclusion.(CVE-2008-3521)Heap-based buffer overflow in
    the jpc_dec_decodepkt function in jpc_t2dec.c in JasPer
    2.0.10 allows remote attackers to have unspecified
    impact via a crafted image.(CVE-2017-6852)The
    jp2_colr_destroy function in jp2_cod.c in JasPer before
    1.900.13 allows remote attackers to cause a denial of
    service (NULL pointer dereference) by leveraging
    incorrect cleanup of JP2 box data on error. NOTE: this
    vulnerability exists because of an incomplete fix for
    CVE-2016-8887.(CVE-2016-10250)The jp2_cdef_destroy
    function in jp2_cod.c in JasPer before 2.0.13 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference) via a crafted
    image.(CVE-2017-6850)The jp2_colr_destroy function in
    libjasper/jp2/jp2_cod.c in JasPer before 1.900.10
    allows remote attackers to cause a denial of service
    (NULL pointer dereference).(CVE-2016-8887)The
    jpc_floorlog2 function in jpc_math.c in JasPer before
    1.900.17 allows remote attackers to cause a denial of
    service (assertion failure) via unspecified
    vectors.(CVE-2016-9398)JasPer 2.0.12 is vulnerable to a
    NULL pointer exception in the function jp2_encode which
    failed to check to see if the image contained at least
    one component resulting in a
    denial-of-service.(CVE-2017-1000050)The jpc_pi_nextrpcl
    function in jpc_t2cod.c in JasPer before 1.900.17
    allows remote attackers to cause a denial of service
    (assertion failure) via a crafted
    file.(CVE-2016-9393)The bmp_getdata function in
    libjasper/bmp/bmp_dec.c in JasPer 1.900.5 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference) by calling the imginfo command with a
    crafted BMP image. NOTE: this vulnerability exists
    because of an incomplete fix for
    CVE-2016-8690.(CVE-2016-8884)There is a reachable
    assertion abort in the function jpc_dequantize() in
    jpc/jpc_dec.c in JasPer 2.0.12 that will lead to a
    remote denial of service attack.(CVE-2017-13752)The
    jpc_dequantize function in jpc_dec.c in JasPer 1.900.13
    allows remote attackers to cause a denial of service
    (assertion failure) via unspecified
    vectors.(CVE-2016-9397)There is a reachable assertion
    abort in the function jpc_floorlog2() in jpc/jpc_math.c
    in JasPer 2.0.12 that will lead to a remote denial of
    service attack.(CVE-2017-13747)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1188
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c800e748");
  script_set_attribute(attribute:"solution", value:
"Update the affected jasper packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3521");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-6852");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["jasper-libs-1.900.1-33.h7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper");
}
