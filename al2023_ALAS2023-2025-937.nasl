#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2025-937.
##

include('compat.inc');

if (description)
{
  script_id(234335);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2024-45774",
    "CVE-2024-45775",
    "CVE-2024-45776",
    "CVE-2024-45777",
    "CVE-2024-45778",
    "CVE-2024-45779",
    "CVE-2024-45780",
    "CVE-2024-45781",
    "CVE-2024-45782",
    "CVE-2024-45783",
    "CVE-2025-0622",
    "CVE-2025-0624",
    "CVE-2025-0677",
    "CVE-2025-0678",
    "CVE-2025-0684",
    "CVE-2025-0685",
    "CVE-2025-0686",
    "CVE-2025-0689",
    "CVE-2025-0690",
    "CVE-2025-1118",
    "CVE-2025-1125"
  );

  script_name(english:"Amazon Linux 2023 : grub2-common, grub2-efi-aa64, grub2-efi-aa64-cdboot (ALAS2023-2025-937)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2025-937 advisory.

    A flaw was found in grub2. A specially crafted JPEG file can cause the JPEG parser of grub2 to incorrectly
    check the bounds of its internal buffers, resulting in an out-of-bounds write. The possibility of
    overwriting sensitive information to bypass secure boot protections is not discarded. (CVE-2024-45774)

    A flaw was found in grub2 where the grub_extcmd_dispatcher() function calls grub_arg_list_alloc() to
    allocate memory for the grub's argument list. However, it fails to check in case the memory allocation
    fails. Once the allocation fails, a NULL point will be processed by the parse_option() function, leading
    grub to crash or, in some rare scenarios, corrupt the IVT data. (CVE-2024-45775)

    When reading the language .mo file in grub_mofile_open(), grub2 fails to verify an integer overflow when
    allocating its internal buffer. A crafted .mo file may lead the buffer size calculation to overflow,
    leading to out-of-bound reads and writes. This flaw allows an attacker to leak sensitive data or overwrite
    critical data, possibly circumventing secure boot protections. (CVE-2024-45776)

    A flaw was found in grub2. The calculation of the translation buffer when reading a language .mo file in
    grub_gettext_getstr_from_position() may overflow, leading to a Out-of-bound write. This issue can be
    leveraged by an attacker to overwrite grub2's sensitive heap data, eventually leading to the circumvention
    of secure boot protections. (CVE-2024-45777)

    grub2: fs/bfs: Integer overflow in the BFS parser. (CVE-2024-45778)

    grub2: fs/bfs: Integer overflow leads to Heap OOB Read in the BFS parser (CVE-2024-45779)

    grub2: fs/tar: Integer Overflow causes Heap OOB Write (CVE-2024-45780)

    A flaw was found in grub2. When reading a symbolic link's name from a UFS filesystem, grub2 fails to
    validate the string length taken as an input. The lack of validation may lead to a heap out-of-bounds
    write, causing data integrity issues and eventually allowing an attacker to circumvent secure boot
    protections. (CVE-2024-45781)

    grub2: fs/hfs: strcpy() using the volume name (fs/hfs.c:382) (CVE-2024-45782)

    A flaw was found in grub2. When failing to mount an HFS+ grub, the hfsplus filesystem driver doesn't
    properly set an ERRNO value. This issue may lead to a NULL pointer access. (CVE-2024-45783)

    A flaw was found in command/gpg. In some scenarios, hooks created by loaded modules are not removed when
    the related module is unloaded. This flaw allows an attacker to force grub2 to call the hooks once the
    module that registered it was unloaded, leading to a use-after-free vulnerability. If correctly exploited,
    this vulnerability may result in arbitrary code execution, eventually allowing the attacker to bypass
    secure boot protections. (CVE-2025-0622)

    A flaw was found in grub2. During the network boot process, when trying to search for the configuration
    file, grub copies data from a user controlled environment variable into an internal buffer using the
    grub_strcpy() function. During this step, it fails to consider the environment variable length when
    allocating the internal buffer, resulting in an out-of-bounds write. If correctly exploited, this issue
    may result in remote code execution through the same network segment grub is searching for the boot
    information, which can be used to by-pass secure boot protections. (CVE-2025-0624)

    A flaw was found in grub2. When performing a symlink lookup, the grub's UFS module checks the inode's data
    size to allocate the internal buffer to read the file content, however, it fails to check if the symlink
    data size has overflown. When this occurs, grub_malloc() may be called with a smaller value than needed.
    When further reading the data from the disk into the buffer, the grub_ufs_lookup_symlink() function will
    write past the end of the allocated size. An attack can leverage this by crafting a malicious filesystem,
    and as a result, it will corrupt data stored in the heap, allowing for arbitrary code execution used to
    by-pass secure boot mechanisms. (CVE-2025-0677)

    grub2: squash4: Integer overflow may lead to heap based out-of-bounds write when reading data
    (CVE-2025-0678)

    grub2: reiserfs: Integer overflow when handling symlinks may lead to heap based out-of-bounds write when
    reading data (CVE-2025-0684)

    grub2: jfs: Integer overflow when handling symlinks may lead to heap based out-of-bounds write when
    reading data (CVE-2025-0685)

    grub2: romfs: Integer overflow when handling symlinks may lead to heap based out-of-bounds write when
    reading dat (CVE-2025-0686)

    grub2: udf: Heap based buffer overflow in grub_udf_read_block() may lead to arbitrary code execution
    (CVE-2025-0689)

    The read command is used to read the keyboard input from the user, while reads it keeps the input length
    in a 32-bit integer value which is further used to reallocate the line buffer to accept the next
    character. During this process, with a line big enough it's possible to make this variable to overflow
    leading to a out-of-bounds write in the heap based buffer. This flaw may be leveraged to corrupt grub's
    internal critical data and secure boot bypass is not discarded as consequence. (CVE-2025-0690)

    A flaw was found in grub2. Grub's dump command is not blocked when grub is in lockdown mode, which allows
    the user to read any memory information, and an attacker may leverage this in order to extract signatures,
    salts, and other sensitive information from the memory. (CVE-2025-1118)

    grub2: fs/hfs: Integer overflow may lead to heap based out-of-bounds write (CVE-2025-1125)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2025-937.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45774.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45775.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45776.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45777.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45778.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45779.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45780.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45781.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45782.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45783.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0622.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0624.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0677.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0678.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0684.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0685.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0686.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0689.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0690.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1118.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1125.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update grub2 --releasever 2023.7.20250414' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0678");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-efi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'grub2-common-2.06-61.amzn2023.0.16', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debugsource-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debugsource-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-cdboot-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-ec2-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-modules-2.06-61.amzn2023.0.16', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-cdboot-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-ec2-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-modules-2.06-61.amzn2023.0.16', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-modules-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-modules-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-pc-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-pc-modules-2.06-61.amzn2023.0.16', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-efi-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-efi-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-debuginfo-2.06-61.amzn2023.0.16', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2-common / grub2-debuginfo / grub2-debugsource / etc");
}
