#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2327-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151727);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id(
    "CVE-2020-7774",
    "CVE-2021-3449",
    "CVE-2021-3450",
    "CVE-2021-22918",
    "CVE-2021-23362",
    "CVE-2021-27290"
  );
  script_xref(name:"IAVA", value:"2021-A-0149-S");
  script_xref(name:"IAVA", value:"2021-A-0195");
  script_xref(name:"IAVA", value:"2021-A-0192-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"IAVA", value:"2021-A-0193-S");

  script_name(english:"openSUSE 15 Security Update : nodejs12 (openSUSE-SU-2021:2327-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2327-1 advisory.

  - This affects the package y18n before 3.2.2, 4.0.1 and 5.0.5. PoC by po6ix: const y18n = require('y18n')();
    y18n.setLocale('__proto__'); y18n.updateLocale({polluted: true}); console.log(polluted); // true
    (CVE-2020-7774)

  - Node.js before 16.4.1, 14.17.2, 12.22.2 is vulnerable to an out-of-bounds read when uv__idna_toascii() is
    used to convert strings to ASCII. The pointer p is read and increased without checking whether it is
    beyond pe, with the latter holding a pointer to the end of the buffer. This can lead to information
    disclosures or crashes. This function can be triggered via uv_getaddrinfo(). (CVE-2021-22918)

  - The package hosted-git-info before 3.0.8 are vulnerable to Regular Expression Denial of Service (ReDoS)
    via regular expression shortcutMatch in the fromUrl function in index.js. The affected regular expression
    exhibits polynomial worst-case time complexity. (CVE-2021-23362)

  - ssri 5.2.2-8.0.0, fixed in 8.0.1, processes SRIs using a regular expression which is vulnerable to a
    denial of service. Malicious SRIs could take an extremely long time to process, leading to denial of
    service. This issue only affects consumers using the strict option. (CVE-2021-27290)

  - An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a
    client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was
    present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL
    pointer dereference will result, leading to a crash and a denial of service attack. A server is only
    vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS
    clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of
    these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in
    OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j). (CVE-2021-3449)

  - The X509_V_FLAG_X509_STRICT flag enables additional security checks of the certificates present in a
    certificate chain. It is not set by default. Starting from OpenSSL version 1.1.1h a check to disallow
    certificates in the chain that have explicitly encoded elliptic curve parameters was added as an
    additional strict check. An error in the implementation of this check meant that the result of a previous
    check to confirm that certificates in the chain are valid CA certificates was overwritten. This
    effectively bypasses the check that non-CA certificates must not be able to issue other certificates. If a
    purpose has been configured then there is a subsequent opportunity for checks that the certificate is a
    valid CA. All of the named purpose values implemented in libcrypto perform this check. Therefore, where
    a purpose is set the certificate chain will still be rejected even when the strict flag has been used. A
    purpose is set by default in libssl client and server certificate verification routines, but it can be
    overridden or removed by an application. In order to be affected, an application must explicitly set the
    X509_V_FLAG_X509_STRICT verification flag and either not set a purpose for the certificate verification
    or, in the case of TLS client or server applications, override the default purpose. OpenSSL versions
    1.1.1h and newer are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k.
    OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1h-1.1.1j).
    (CVE-2021-3450)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187977");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OFQOZ4RLN343RY5DDFVA2KWFMZHZD2KS/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e8736d8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3449");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3450");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs12, nodejs12-devel and / or npm12 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7774");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'nodejs12-12.22.2-4.16.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs12-devel-12.22.2-4.16.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm12-12.22.2-4.16.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs12 / nodejs12-devel / npm12');
}
