#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0139. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154470);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2020-10713",
    "CVE-2020-14308",
    "CVE-2020-14309",
    "CVE-2020-14310",
    "CVE-2020-14311",
    "CVE-2020-15705",
    "CVE-2020-15706",
    "CVE-2020-15707"
  );
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : grub2 Multiple Vulnerabilities (NS-SA-2021-0139)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has grub2 packages installed that are affected by
multiple vulnerabilities:

  - A flaw was found in grub2, prior to version 2.06. An attacker may use the GRUB 2 flaw to hijack and tamper
    the GRUB verification process. This flaw also allows the bypass of Secure Boot protections. In order to
    load an untrusted or modified kernel, an attacker would first need to establish access to the system such
    as gaining physical access, obtain the ability to alter a pxe-boot network, or have remote access to a
    networked system with root access. With this access, an attacker could then craft a string to cause a
    buffer overflow by injecting a malicious payload that leads to arbitrary code execution within GRUB. The
    highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2020-10713)

  - In grub2 versions before 2.06 the grub memory allocator doesn't check for possible arithmetic overflows on
    the requested allocation size. This leads the function to return invalid memory allocations which can be
    further used to cause possible integrity, confidentiality and availability impacts during the boot
    process. (CVE-2020-14308)

  - There's an issue with grub2 in all versions before 2.06 when handling squashfs filesystems containing a
    symbolic link with name length of UINT32 bytes in size. The name size leads to an arithmetic overflow
    leading to a zero-size allocation further causing a heap-based buffer overflow with attacker controlled
    data. (CVE-2020-14309)

  - There is an issue on grub2 before version 2.06 at function read_section_as_string(). It expects a font
    name to be at max UINT32_MAX - 1 length in bytes but it doesn't verify it before proceed with buffer
    allocation to read the value from the font value. An attacker may leverage that by crafting a malicious
    font file which has a name with UINT32_MAX, leading to read_section_as_string() to an arithmetic overflow,
    zero-sized allocation and further heap-based buffer overflow. (CVE-2020-14310)

  - There is an issue with grub2 before version 2.06 while handling symlink on ext filesystems. A filesystem
    containing a symbolic link with an inode size of UINT32_MAX causes an arithmetic overflow leading to a
    zero-sized memory allocation with subsequent heap-based buffer overflow. (CVE-2020-14311)

  - GRUB2 fails to validate kernel signature when booted directly without shim, allowing secure boot to be
    bypassed. This only affects systems where the kernel signing certificate has been imported directly into
    the secure boot database and the GRUB image is booted directly without the use of shim. This issue affects
    GRUB2 version 2.04 and prior versions. (CVE-2020-15705)

  - GRUB2 contains a race condition in grub_script_function_create() leading to a use-after-free vulnerability
    which can be triggered by redefining a function whilst the same function is already executing, leading to
    arbitrary code execution and secure boot restriction bypass. This issue affects GRUB2 version 2.04 and
    prior versions. (CVE-2020-15706)

  - Integer overflows were discovered in the functions grub_cmd_initrd and grub_initrd_init in the efilinux
    component of GRUB2, as shipped in Debian, Red Hat, and Ubuntu (the functionality is not included in GRUB2
    upstream), leading to a heap-based buffer overflow. These could be triggered by an extremely large number
    of arguments to the initrd command on 32-bit architectures, or a crafted filesystem with very large files
    on any architecture. An attacker could use this to execute arbitrary code and bypass UEFI Secure Boot
    restrictions. This issue affects GRUB2 version 2.04 and prior versions. (CVE-2020-15707)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0139");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-10713");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14308");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14309");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14310");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14311");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15705");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15706");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15707");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL grub2 packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14309");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10713");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-i386-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-i386-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'grub2-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-common-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-debuginfo-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-efi-ia32-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-efi-ia32-cdboot-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-efi-ia32-modules-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-efi-x64-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-efi-x64-cdboot-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-efi-x64-modules-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-i386-modules-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-lang-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-pc-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-pc-modules-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-tools-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-tools-extra-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite',
    'grub2-tools-minimal-2.02-0.86.el7.centos.cgslv5_5.0.6.g4a36c9e.lite'
  ],
  'CGSL MAIN 5.05': [
    'grub2-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-common-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-debuginfo-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-efi-ia32-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-efi-ia32-cdboot-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-efi-ia32-modules-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-efi-x64-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-efi-x64-cdboot-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-efi-x64-modules-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-i386-modules-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-pc-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-pc-modules-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-tools-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-tools-extra-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8',
    'grub2-tools-minimal-2.02-0.86.el7.centos.cgslv5_5.0.7.g62910b8'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2');
}
