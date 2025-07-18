#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191797);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id(
    "CVE-2023-40547",
    "CVE-2023-40548",
    "CVE-2023-40549",
    "CVE-2023-40550",
    "CVE-2023-40551"
  );

  script_name(english:"EulerOS 2.0 SP11 : shim (EulerOS-SA-2024-1227)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the shim packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - A remote code execution vulnerability was found in Shim. The Shim boot support trusts attacker-controlled
    values when parsing an HTTP response. This flaw allows an attacker to craft a specific malicious HTTP
    request, leading to a completely controlled out-of-bounds write primitive and complete system compromise.
    This flaw is only exploitable during the early boot phase, an attacker needs to perform a Man-in-the-
    Middle or compromise the boot server to be able to exploit this vulnerability successfully.
    (CVE-2023-40547)

  - A buffer overflow was found in Shim in the 32-bit system. The overflow happens due to an addition
    operation involving a user-controlled value parsed from the PE binary being used by Shim. This value is
    further used for memory allocation operations, leading to a heap-based buffer overflow. This flaw causes
    memory corruption and can lead to a crash or data integrity issues during the boot phase. (CVE-2023-40548)

  - An out-of-bounds read flaw was found in Shim due to the lack of proper boundary verification during the
    load of a PE binary. This flaw allows an attacker to load a crafted PE binary, triggering the issue and
    crashing Shim, resulting in a denial of service. (CVE-2023-40549)

  - An out-of-bounds read flaw was found in Shim when it tried to validate the SBAT information. This issue
    may expose sensitive data during the system's boot phase. (CVE-2023-40550)

  - A flaw was found in the MZ binary format in Shim. An out-of-bounds read may occur, leading to a crash or
    possible exposure of sensitive data during the system's boot phase. (CVE-2023-40551)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1227
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?580df3c3");
  script_set_attribute(attribute:"solution", value:
"Update the affected shim packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:shim-aa64-storage");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "shim-15.4-2.h24.eulerosv2r11",
  "shim-aa64-storage-15.4-2.h24.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "shim");
}
