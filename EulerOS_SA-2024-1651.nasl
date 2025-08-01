#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197246);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id("CVE-2023-4692", "CVE-2023-4693");

  script_name(english:"EulerOS Virtualization 3.0.6.6 : grub2 (EulerOS-SA-2024-1651)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the grub2 packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - An out-of-bounds write flaw was found in grub2's NTFS filesystem driver. This issue may allow an attacker
    to present a specially crafted NTFS filesystem image, leading to grub's heap metadata corruption. In some
    circumstances, the attack may also corrupt the UEFI firmware heap metadata. As a result, arbitrary code
    execution and secure boot protection bypass may be achieved. (CVE-2023-4692)

  - An out-of-bounds read flaw was found on grub2's NTFS filesystem driver. This issue may allow a physically
    present attacker to present a specially crafted NTFS file system image to read arbitrary memory locations.
    A successful attack allows sensitive data cached in memory or EFI variable values to be leaked, presenting
    a high Confidentiality risk. (CVE-2023-4693)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1651
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?393eccc5");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4692");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "grub2-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-common-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-efi-ia32-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-efi-ia32-cdboot-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-efi-x64-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-efi-x64-cdboot-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-efi-x64-modules-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-pc-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-pc-modules-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-tools-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-tools-extra-2.02-0.65.2.h29.eulerosv2r7",
  "grub2-tools-minimal-2.02-0.65.2.h29.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2");
}
