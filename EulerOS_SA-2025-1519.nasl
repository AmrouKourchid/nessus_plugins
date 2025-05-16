#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235753);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id(
    "CVE-2024-45777",
    "CVE-2024-45778",
    "CVE-2024-45779",
    "CVE-2024-45780",
    "CVE-2024-45782",
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

  script_name(english:"EulerOS 2.0 SP10 : grub2 (EulerOS-SA-2025-1519)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the grub2 packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

    A stack overflow flaw was found when reading a BFS file system. A crafted BFS filesystem may lead to an
    uncontrolled loop, causing grub2 to crash.(CVE-2024-45778)

    A flaw was found in grub2. When reading data from a jfs filesystem, grub's jfs filesystem module uses
    user-controlled parameters from the filesystem geometry to determine the internal buffer size, however, it
    improperly checks for integer overflows. A maliciouly crafted filesystem may lead some of those buffer
    size calculations to overflow, causing it to perform a grub_malloc() operation with a smaller size than
    expected. As a result, the grub_jfs_lookup_symlink() function will write past the internal buffer length
    during grub_jfs_read_file(). This issue can be leveraged to corrupt grub's internal critical data and may
    result in arbitrary code execution, by-passing secure boot protections.(CVE-2025-0685)

    When reading data from a hfs filesystem, grub's hfs filesystem module uses user-controlled parameters from
    the filesystem metadata to calculate the internal buffers size, however it misses to properly check for
    integer overflows. A maliciouly crafted filesystem may lead some of those buffer size calculation to
    overflow, causing it to perform a grub_malloc() operation with a smaller size than expected. As a result
    the hfsplus_open_compressed_real() function will write past of the internal buffer length. This flaw may
    be leveraged to corrupt grub's internal critical data and may result in arbitrary code execution by-
    passing secure boot protections.(CVE-2025-1125)

    A flaw was found in grub2. When performing a symlink lookup, the grub's UFS module checks the inode's data
    size to allocate the internal buffer to read the file content, however, it fails to check if the symlink
    data size has overflown. When this occurs, grub_malloc() may be called with a smaller value than needed.
    When further reading the data from the disk into the buffer, the grub_ufs_lookup_symlink() function will
    write past the end of the allocated size. An attack can leverage this by crafting a malicious filesystem,
    and as a result, it will corrupt data stored in the heap, allowing for arbitrary code execution used to
    by-pass secure boot mechanisms.(CVE-2025-0677)

    When reading data from disk, the grub's UDF filesystem module utilizes the user controlled data length
    metadata to allocate its internal buffers. In certain scenarios, while iterating through disk sectors, it
    assumes the read size from the disk is always smaller than the allocated buffer size which is not
    guaranteed. A crafted filesystem image may lead to a heap-based buffer overflow resulting in critical data
    to be corrupted, resulting in the risk of arbitrary code execution by-passing secure boot
    protections.(CVE-2025-0689)

    A flaw was found in grub2. When performing a symlink lookup from a romfs filesystem, grub's romfs
    filesystem module uses user-controlled parameters from the filesystem geometry to determine the internal
    buffer size, however, it improperly checks for integer overflows. A maliciously crafted filesystem may
    lead some of those buffer size calculations to overflow, causing it to perform a grub_malloc() operation
    with a smaller size than expected. As a result, the grub_romfs_read_symlink() may cause out-of-bounds
    writes when the calling grub_disk_read() function. This issue may be leveraged to corrupt grub's internal
    critical data and can result in arbitrary code execution by-passing secure boot
    protections.(CVE-2025-0686)

    A flaw was found in grub2. During the network boot process, when trying to search for the configuration
    file, grub copies data from a user controlled environment variable into an internal buffer using the
    grub_strcpy() function. During this step, it fails to consider the environment variable length when
    allocating the internal buffer, resulting in an out-of-bounds write. If correctly exploited, this issue
    may result in remote code execution through the same network segment grub is searching for the boot
    information, which can be used to by-pass secure boot protections.(CVE-2025-0624)

    A flaw was found in grub2. When reading data from a squash4 filesystem, grub's squash4 fs module uses
    user-controlled parameters from the filesystem geometry to determine the internal buffer size, however, it
    improperly checks for integer overflows. A maliciously crafted filesystem may lead some of those buffer
    size calculations to overflow, causing it to perform a grub_malloc() operation with a smaller size than
    expected. As a result, the direct_read() will perform a heap based out-of-bounds write during data
    reading. This flaw may be leveraged to corrupt grub's internal critical data and may result in arbitrary
    code execution, by-passing secure boot protections.(CVE-2025-0678)

    The read command is used to read the keyboard input from the user, while reads it keeps the input length
    in a 32-bit integer value which is further used to reallocate the line buffer to accept the next
    character. During this process, with a line big enough it's possible to make this variable to overflow
    leading to a out-of-bounds write in the heap based buffer. This flaw may be leveraged to corrupt grub's
    internal critical data and secure boot bypass is not discarded as consequence.(CVE-2025-0690)

    A flaw was found in grub2. When reading tar files, grub2 allocates an internal buffer for the file name.
    However, it fails to properly verify the allocation against possible integer overflows. It's possible to
    cause the allocation length to overflow with a crafted tar file, leading to a heap out-of-bounds write.
    This flaw eventually allows an attacker to circumvent secure boot protections.(CVE-2024-45780)

    A flaw was found in the HFS filesystem. When reading an HFS volume's name at grub_fs_mount(), the HFS
    filesystem driver performs a strcpy() using the user-provided volume name as input without properly
    validating the volume name's length. This issue may read to a heap-based out-of-bounds writer, impacting
    grub's sensitive data integrity and eventually leading to a secure boot protection bypass.(CVE-2024-45782)

    An integer overflow flaw was found in the BFS file system driver in grub2. When reading a file with an
    indirect extent map, grub2 fails to validate the number of extent entries to be read. A crafted or
    corrupted BFS filesystem may cause an integer overflow during the file reading, leading to a heap of
    bounds read. As a consequence, sensitive data may be leaked, or grub2 will crash.(CVE-2024-45779)

    A flaw was found in grub2. When performing a symlink lookup from a reiserfs filesystem, grub's reiserfs fs
    module uses user-controlled parameters from the filesystem geometry to determine the internal buffer size,
    however, it improperly checks for integer overflows. A maliciouly crafted filesystem may lead some of
    those buffer size calculations to overflow, causing it to perform a grub_malloc() operation with a smaller
    size than expected. As a result, the grub_reiserfs_read_symlink() will call grub_reiserfs_read_real() with
    a overflown length parameter, leading to a heap based out-of-bounds write during data reading. This flaw
    may be leveraged to corrupt grub's internal critical data and can result in arbitrary code execution, by-
    passing secure boot protections.(CVE-2025-0684)

    A flaw was found in grub2. The calculation of the translation buffer when reading a language .mo file in
    grub_gettext_getstr_from_position() may overflow, leading to a Out-of-bound write. This issue can be
    leveraged by an attacker to overwrite grub2's sensitive heap data, eventually leading to the circumvention
    of secure boot protections.(CVE-2024-45777)

    A flaw was found in grub2. Grub's dump command is not blocked when grub is in lockdown mode, which allows
    the user to read any memory information, and an attacker may leverage this in order to extract signatures,
    salts, and other sensitive information from the memory.(CVE-2025-1118)

Tenable has extracted the preceding description block directly from the EulerOS grub2 security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1519
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64db4ee8");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0678");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "grub2-common-2.04-16.h50.eulerosv2r10",
  "grub2-efi-aa64-2.04-16.h50.eulerosv2r10",
  "grub2-efi-aa64-modules-2.04-16.h50.eulerosv2r10",
  "grub2-tools-2.04-16.h50.eulerosv2r10",
  "grub2-tools-extra-2.04-16.h50.eulerosv2r10",
  "grub2-tools-minimal-2.04-16.h50.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
