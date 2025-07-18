#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146755);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/19");

  script_cve_id(
    "CVE-2019-15691",
    "CVE-2019-15692",
    "CVE-2019-15693",
    "CVE-2019-15694",
    "CVE-2019-15695",
    "CVE-2020-26117"
  );

  script_name(english:"EulerOS 2.0 SP2 : tigervnc (EulerOS-SA-2021-1369)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tigervnc packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - TigerVNC version prior to 1.10.1 is vulnerable to stack
    use-after-return, which occurs due to incorrect usage
    of stack memory in ZRLEDecoder. If decoding routine
    would throw an exception, ZRLEDecoder may try to access
    stack variable, which has been already freed during the
    process of stack unwinding. Exploitation of this
    vulnerability could potentially result into remote code
    execution. This attack appear to be exploitable via
    network connectivity.(CVE-2019-15691)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap
    buffer overflow. Vulnerability could be triggered from
    CopyRectDecoder due to incorrect value checks.
    Exploitation of this vulnerability could potentially
    result into remote code execution. This attack appear
    to be exploitable via network
    connectivity.(CVE-2019-15692)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap
    buffer overflow, which occurs in
    TightDecoder::FilterGradient. Exploitation of this
    vulnerability could potentially result into remote code
    execution. This attack appear to be exploitable via
    network connectivity.(CVE-2019-15693)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap
    buffer overflow, which could be triggered from
    DecodeManager::decodeRect. Vulnerability occurs due to
    the signdness error in processing MemOutStream.
    Exploitation of this vulnerability could potentially
    result into remote code execution. This attack appear
    to be exploitable via network
    connectivity.(CVE-2019-15694)

  - TigerVNC version prior to 1.10.1 is vulnerable to stack
    buffer overflow, which could be triggered from
    CMsgReader::readSetCursor. This vulnerability occurs
    due to insufficient sanitization of PixelFormat. Since
    remote attacker can choose offset from start of the
    buffer to start writing his values, exploitation of
    this vulnerability could potentially result into remote
    code execution. This attack appear to be exploitable
    via network connectivity.(CVE-2019-15695)

  - In rfb/CSecurityTLS.cxx and rfb/CSecurityTLS.java in
    TigerVNC before 1.11.0, viewers mishandle TLS
    certificate exceptions. They store the certificates as
    authorities, meaning that the owner of a certificate
    could impersonate any server after a client had added
    an exception.(CVE-2020-26117)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1369
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17235e9b");
  script_set_attribute(attribute:"solution", value:
"Update the affected tigervnc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15695");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-26117");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["tigervnc-1.8.0-1.h2",
        "tigervnc-icons-1.8.0-1.h2",
        "tigervnc-license-1.8.0-1.h2",
        "tigervnc-server-1.8.0-1.h2",
        "tigervnc-server-minimal-1.8.0-1.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tigervnc");
}
