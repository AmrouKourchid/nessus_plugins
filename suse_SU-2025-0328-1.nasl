#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0328-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214890);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id(
    "CVE-2018-14679",
    "CVE-2023-20197",
    "CVE-2024-20380",
    "CVE-2024-20505",
    "CVE-2024-20506",
    "CVE-2025-20128"
  );
  script_xref(name:"IAVB", value:"2023-B-0062-S");
  script_xref(name:"IAVB", value:"2024-B-0134");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0328-1");

  script_name(english:"SUSE SLES12 Security Update : clamav (SUSE-SU-2025:0328-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:0328-1 advisory.

    New version 1.4.2:

      * CVE-2025-20128, bsc#1236307: Fixed a possible buffer overflow
        read bug in the OLE2 file parser that could cause a
        denial-of-service (DoS) condition.

    - Start clamonacc with --fdpass to avoid errors due to
      clamd not being able to access user files. (bsc#1232242)

    - New version 1.4.1:

      * https://blog.clamav.net/2024/09/clamav-141-132-107-and-010312-security.html

    - New version 1.4.0:

      * Added support for extracting ALZ archives.
      * Added support for extracting LHA/LZH archives.
      * Added the ability to disable image fuzzy hashing, if needed.
        For context, image fuzzy hashing is a detection mechanism
        useful for identifying malware by matching images included with
        the malware or phishing email/document.
      * https://blog.clamav.net/2024/08/clamav-140-feature-release-and-clamav.html

    - New version 1.3.2:

      * CVE-2024-20506: Changed the logging module to disable following
        symlinks on Linux and Unix systems so as to prevent an attacker
        with existing access to the 'clamd' or 'freshclam' services from
        using a symlink to corrupt system files.
      * CVE-2024-20505: Fixed a possible out-of-bounds read bug in the PDF
        file parser that could cause a denial-of-service condition.
      * Removed unused Python modules from freshclam tests including
        deprecated 'cgi' module that is expected to cause test failures in
        Python 3.13.
      * Fix unit test caused by expiring signing certificate.
      * Fixed a build issue on Windows with newer versions of Rust. Also
        upgraded GitHub Actions imports to fix CI failures.
      * Fixed an unaligned pointer dereference issue on select architectures.
      * Fixes to Jenkins CI pipeline.


    - New Version: 1.3.1:

      * CVE-2024-20380: Fixed a possible crash in the HTML file parser
        that could cause a denial-of-service (DoS) condition.
      * Updated select Rust dependencies to the latest versions.
      * Fixed a bug causing some text to be truncated when converting
        from UTF-16.
      * Fixed assorted complaints identified by Coverity static
        analysis.
      * Fixed a bug causing CVDs downloaded by the DatabaseCustomURL
      * Added the new 'valhalla' database name to the list of optional
        databases in preparation for future work.

    - New version: 1.3.0:

      * Added support for extracting and scanning attachments found in
        Microsoft OneNote section files. OneNote parsing will be
        enabled by default, but may be optionally disabled.
      * Added file type recognition for compiled Python ('.pyc') files.
      * Improved support for decrypting PDFs with empty passwords.
      * Fixed a warning when scanning some HTML files.
      * ClamOnAcc: Fixed an infinite loop when a watched directory
        does not exist.
      * ClamOnAcc: Fixed an infinite loop when a file has been deleted
        before a scan.

    - New version: 1.2.0:

      * Added support for extracting Universal Disk Format (UDF)
        partitions.
      * Added an option to customize the size of ClamAV's clean file
        cache.
      * Raised the MaxScanSize limit so the total amount of data
        scanned when scanning a file or archive may exceed 4 gigabytes.
      * Added ability for Freshclam to use a client certificate PEM
        file and a private key PEM file for authentication to a private
        mirror.
      * Fix an issue extracting files from ISO9660 partitions where the
        files are listed in the plain ISO tree and there also exists an
        empty Joliet tree.
      * PID and socket are now located under /run/clamav/clamd.pid and
        /run/clamav/clamd.sock .
      * bsc#1211594: Fixed an issue where ClamAV does not abort the
        signature load process after partially loading an invalid
        signature.

    - New version 1.1.0:

      * https://blog.clamav.net/2023/05/clamav-110-released.html
      * Added the ability to extract images embedded in HTML CSS
        <style> blocks.
      * Updated to Sigtool so that the '--vba' option will extract VBA
        code from Microsoft Office documents the same way that
        libclamav extracts VBA.
      * Added a new option --fail-if-cvd-older-than=days to clamscan
        and clamd, and FailIfCvdOlderThan to clamd.conf
      * Added a new function 'cl_cvdgetage()' to the libclamav API.
      * Added a new function 'cl_engine_set_clcb_vba()' to the
        libclamav API.
    - bsc#1180296: Integrate clamonacc as a service.
    - New version 1.0.1 LTS (including changes in 0.104 and 0.105):
      * As of ClamAV 0.104, CMake is required to build ClamAV.
      * As of ClamAV 0.105, Rust is now required to compile ClamAV.
      * Increased the default limits for file and scan size:
        * MaxScanSize: 100M to 400M
        * MaxFileSize: 25M to 100M
        * StreamMaxLength: 25M to 100M
        * PCREMaxFileSize: 25M to 100M
        * MaxEmbeddedPE: 10M to 40M
        * MaxHTMLNormalize: 10M to 40M
        * MaxScriptNormalize: 5M to 20M
        * MaxHTMLNoTags: 2M to 8M
      * Added image fuzzy hash subsignatures for logical signatures.
      * Support for decrypting read-only OLE2-based XLS files that are
        encrypted with the default password.
      * Overhauled the implementation of the all-match feature.
      * Added a new callback to the public API for inspecting file
        content during a scan at each layer of archive extraction.
      * Added a new function to the public API for unpacking CVD
        signature archives.
      * The option to build with an external TomsFastMath library has
        been removed. ClamAV requires non-default build options for
        TomsFastMath to support bigger floating point numbers.
      * For a full list of changes see the release announcements:
        * https://blog.clamav.net/2022/11/clamav-100-lts-released.html
        * https://blog.clamav.net/2022/05/clamav-01050-01043-01036-released.html
        * https://blog.clamav.net/2021/09/clamav-01040-released.html
    - Build clamd with systemd support.

    * CVE-2023-20197: Fixed a possible denial of service vulnerability in
      the HFS+ file parser. (bsc#1214342)
    * CVE-2018-14679: Fixed that an issue was discovered in mspack/chmd.c
      in libmspack before 0.7alpha. There isan off-by-one error in the CHM
      PMGI/PMGL chunk number validity checks, which could lead to denial of
      service (uninitialized da (bsc#1103032)

    - Package huge .html documentation in a separate subpackage.

    - Update to 0.103.7 (bsc#1202986)

      - Zip parser: tolerate 2-byte overlap in file entries
      - Fix bug with logical signature Intermediates feature
      - Update to UnRAR v6.1.7
      - Patch UnRAR: allow skipping files in solid archives
      - Patch UnRAR: limit dict winsize to 1GB

    - Use a split-provides for clamav-milter instead of recommending it.
    - Package clamav-milter in a subpackage
    - Remove virus signatures upon uninstall
    - Check for database existence before starting clamd
    - Restart clamd when it exits
    - Don't daemonize freshclam, but use a systemd timer instead to
      trigger updates

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1102840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1103032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236307");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020256.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0c790e7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-20197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20380");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-20128");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14679");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-20506");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libclamav12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libclammspack0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreshclam3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'clamav-1.4.2-3.36.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'clamav-devel-1.4.2-3.36.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'clamav-docs-html-1.4.2-3.36.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'clamav-milter-1.4.2-3.36.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'libclamav12-1.4.2-3.36.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'libclammspack0-1.4.2-3.36.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'libfreshclam3-1.4.2-3.36.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'clamav-1.4.2-3.36.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'clamav-devel-1.4.2-3.36.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'clamav-docs-html-1.4.2-3.36.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'clamav-milter-1.4.2-3.36.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libclamav12-1.4.2-3.36.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libclammspack0-1.4.2-3.36.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libfreshclam3-1.4.2-3.36.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clamav / clamav-devel / clamav-docs-html / clamav-milter / etc');
}
