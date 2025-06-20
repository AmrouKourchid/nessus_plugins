#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198314);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2024-0727");

  script_name(english:"EulerOS 2.0 SP11 : linux-sgx (EulerOS-SA-2024-1804)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the linux-sgx packages installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

    A remote code execution vulnerability was found in Shim. The Shim boot support trusts attacker-controlled
    values when parsing an HTTP response. This flaw allows an attacker to craft a specific malicious HTTP
    request, leading to a completely controlled out-of-bounds write primitive and complete system
    compromise.(CVE-2024-0727)

Tenable has extracted the preceding description block directly from the EulerOS linux-sgx security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1804
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?539559a3");
  script_set_attribute(attribute:"solution", value:
"Update the affected linux-sgx packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-ae-le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-aesm-launch-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-enclave-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-launch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsgx-urts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sgx-aesm-service");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libsgx-ae-le-2.15.1-1.h18.eulerosv2r11",
  "libsgx-aesm-launch-plugin-2.15.1-1.h18.eulerosv2r11",
  "libsgx-enclave-common-2.15.1-1.h18.eulerosv2r11",
  "libsgx-launch-2.15.1-1.h18.eulerosv2r11",
  "libsgx-urts-2.15.1-1.h18.eulerosv2r11",
  "sgx-aesm-service-2.15.1-1.h18.eulerosv2r11"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-sgx");
}
