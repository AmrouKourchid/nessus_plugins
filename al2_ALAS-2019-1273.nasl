#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1273.
#

include('compat.inc');

if (description)
{
  script_id(128287);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/01");

  script_cve_id(
    "CVE-2017-5731",
    "CVE-2017-5732",
    "CVE-2017-5733",
    "CVE-2017-5734",
    "CVE-2017-5735",
    "CVE-2018-12178",
    "CVE-2018-12180",
    "CVE-2018-12181",
    "CVE-2018-3613",
    "CVE-2018-3630"
  );
  script_xref(name:"ALAS", value:"2019-1273");

  script_name(english:"Amazon Linux 2 : edk2 (ALAS-2019-1273)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Logic error in FV parsing in MdeModulePkg\Core\Pei\FwVol\FwVol.c
(CVE-2018-3630)

Logic issue in variable service module for EDK
II/UDK2018/UDK2017/UDK2015 may allow an authenticated user to
potentially enable escalation of privilege, information disclosure
and/or denial of service via local access. (CVE-2017-5734)

A missing check leads to an out-of-bounds read and write flaw in
NetworkPkg/DnsDxe as shipped in edk2, when it parses DNS responses. A
remote attacker who controls the DNS server used by the vulnerable
firmware may use this flaw to make the system crash. (CVE-2018-3613)

improper DNS packet size check (CVE-2018-12178)

Privilege escalation via heap-based buffer overflow in Decode()
function (CVE-2017-5735)

Privilege escalation via heap-based buffer overflow in MakeTable()
function (CVE-2017-5733)

Privilege escalation via processing of malformed files in
TianoCompress.c (CVE-2017-5731)

Privilege escalation via processing of malformed files in
BaseUefiDecompressLib.c (CVE-2017-5732)

A stack-based buffer overflow was discovered in edk2 when the HII
database contains a Bitmap that claims to be 4-bit or 8-bit per pixel,
but the palette contains more than 16(2^4) or 256(2^8) colors.
(CVE-2018-12181)

Buffer overflow in BlockIo service for EDK II may allow an
unauthenticated user to potentially enable escalation of privilege,
information disclosure and/or denial of service via network access.
(CVE-2018-12180)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1273.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update edk2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3630");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-12178");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools-python");
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
if (rpm_check(release:"AL2", reference:"edk2-aarch64-20190308stable-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"edk2-debuginfo-20190308stable-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"edk2-ovmf-20190308stable-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"edk2-tools-20190308stable-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"edk2-tools-doc-20190308stable-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"edk2-tools-python-20190308stable-1.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "edk2-aarch64 / edk2-debuginfo / edk2-ovmf / edk2-tools / etc");
}
