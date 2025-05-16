#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0518-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(190658);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/11");

  script_cve_id("CVE-2023-6129", "CVE-2023-6237", "CVE-2024-0727");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0518-1");
  script_xref(name:"IAVA", value:"2024-A-0121-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : openssl-3 (SUSE-SU-2024:0518-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / SLES_SAP15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:0518-1 advisory.

  - Issue summary: The POLY1305 MAC (message authentication code) implementation contains a bug that might
    corrupt the internal state of applications running on PowerPC CPU based platforms if the CPU provides
    vector instructions. Impact summary: If an attacker can influence whether the POLY1305 MAC algorithm is
    used, the application state might be corrupted with various application dependent consequences. The
    POLY1305 MAC (message authentication code) implementation in OpenSSL for PowerPC CPUs restores the
    contents of vector registers in a different order than they are saved. Thus the contents of some of these
    vector registers are corrupted when returning to the caller. The vulnerable code is used only on newer
    PowerPC processors supporting the PowerISA 2.07 instructions. The consequences of this kind of internal
    application state corruption can be various - from no consequences, if the calling application does not
    depend on the contents of non-volatile XMM registers at all, to the worst consequences, where the attacker
    could get complete control of the application process. However unless the compiler uses the vector
    registers for storing pointers, the most likely consequence, if any, would be an incorrect result of some
    application dependent calculations or a crash leading to a denial of service. The POLY1305 MAC algorithm
    is most frequently used as part of the CHACHA20-POLY1305 AEAD (authenticated encryption with associated
    data) algorithm. The most common usage of this AEAD cipher is with TLS protocol versions 1.2 and 1.3. If
    this cipher is enabled on the server a malicious client can influence whether this AEAD cipher is used.
    This implies that TLS server applications using OpenSSL can be potentially impacted. However we are
    currently not aware of any concrete application that would be affected by this issue therefore we consider
    this a Low severity security issue. (CVE-2023-6129)

  - Issue summary: Checking excessively long invalid RSA public keys may take a long time. Impact summary:
    Applications that use the function EVP_PKEY_public_check() to check RSA public keys may experience long
    delays. Where the key that is being checked has been obtained from an untrusted source this may lead to a
    Denial of Service. When function EVP_PKEY_public_check() is called on RSA public keys, a computation is
    done to confirm that the RSA modulus, n, is composite. For valid RSA keys, n is a product of two or more
    large primes and this computation completes quickly. However, if n is an overly large prime, then this
    computation would take a long time. An application that calls EVP_PKEY_public_check() and supplies an RSA
    key obtained from an untrusted source could be vulnerable to a Denial of Service attack. The function
    EVP_PKEY_public_check() is not called from other OpenSSL functions however it is called from the OpenSSL
    pkey command line application. For that reason that application is also vulnerable if used with the
    '-pubin' and '-check' options on untrusted data. The OpenSSL SSL/TLS implementation is not affected by
    this issue. The OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue. Found by OSS-Fuzz. Fix
    developed by Tomas Mraz. Fixed in OpenSSL 3.0.13 (Affected since 3.0.0). (CVE-2023-6237)

  - Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a
    potential Denial of Service attack Impact summary: Applications loading files in the PKCS12 format from
    untrusted sources might terminate abruptly. A file in PKCS12 format can contain certificates and keys and
    may come from an untrusted source. The PKCS12 specification allows certain fields to be NULL, but OpenSSL
    does not correctly check for this case. This can lead to a NULL pointer dereference that results in
    OpenSSL crashing. If an application processes PKCS12 files from an untrusted source using the OpenSSL APIs
    then that application will be vulnerable to this issue. OpenSSL APIs that are vulnerable to this are:
    PKCS12_parse(), PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes() and
    PKCS12_newpass(). We have also fixed a similar issue in SMIME_write_PKCS7(). However since this function
    is related to writing data we do not consider it security significant. The FIPS modules in 3.2, 3.1 and
    3.0 are not affected by this issue. (CVE-2024-0727)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219243");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-February/017939.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c24fdcd8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0727");
  script_set_attribute(attribute:"solution", value:
"Update the affected libopenssl-3-devel, libopenssl3 and / or openssl-3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libopenssl-3-devel-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libopenssl3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'openssl-3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libopenssl-3-devel-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libopenssl-3-devel-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'libopenssl3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libopenssl3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'openssl-3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'openssl-3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'libopenssl-3-devel-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libopenssl-3-devel-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libopenssl3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libopenssl3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'openssl-3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'openssl-3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libopenssl-3-devel-3.0.8-150400.4.49.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'libopenssl3-3.0.8-150400.4.49.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'openssl-3-3.0.8-150400.4.49.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'libopenssl-3-devel-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sled-release-15.4']},
    {'reference':'libopenssl3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sled-release-15.4']},
    {'reference':'openssl-3-3.0.8-150400.4.49.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sled-release-15.4']},
    {'reference':'libopenssl-3-devel-3.0.8-150400.4.49.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libopenssl3-3.0.8-150400.4.49.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'openssl-3-3.0.8-150400.4.49.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenssl-3-devel / libopenssl3 / openssl-3');
}
