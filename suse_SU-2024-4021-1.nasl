#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4021-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212577);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2024-0397",
    "CVE-2024-3651",
    "CVE-2024-4032",
    "CVE-2024-5569",
    "CVE-2024-6345",
    "CVE-2024-6923",
    "CVE-2024-7592",
    "CVE-2024-8088",
    "CVE-2024-37891"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4021-1");

  script_name(english:"SUSE SLES15 Security Update : SUSE Manager Salt Bundle (SUSE-SU-2024:4021-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:4021-1 advisory.

    venv-salt-minion:

    - Security fixes on Python 3.11 interpreter:

      * CVE-2024-7592: Fixed quadratic complexity in parsing -quoted cookie values with backslashes
        (bsc#1229873, bsc#1230059)
      * CVE-2024-8088: Prevent malformed payload to cause infinite loops in zipfile.Path (bsc#1229704,
    bsc#1230058)
      * CVE-2024-6923: Prevent email header injection due to unquoted newlines (bsc#1228780)
      * CVE-2024-4032: Rearranging definition of private global IP addresses (bsc#1226448)
      * CVE-2024-0397: ssl.SSLContext.cert_store_stats() and ssl.SSLContext.get_ca_certs() now correctly lock
    access to the
        certificate store, when the ssl.SSLContext is shared across multiple threads (bsc#1226447)

    - Security fixes on Python dependencies:

      * CVE-2024-5569: zipp: Fixed a Denial of Service (DoS) vulnerability in the jaraco/zipp library
    (bsc#1227547, bsc#1229996)
      * CVE-2024-6345: setuptools: Sanitize any VCS URL used for download (bsc#1228105, bsc#1229995)
      * CVE-2024-3651: idna: Fix a potential DoS via resource consumption via specially crafted inputs to
    idna.encode()
        (bsc#1222842, bsc#1229994)
      * CVE-2024-37891: urllib3: Added the ``Proxy-Authorization`` header to the list of headers to strip from
    requests
        when redirecting to a different host (bsc#1226469, bsc#1229654)

    - Other bugs fixed:

      * Added passlib Python module to the bundle
      * Allow NamedLoaderContexts to be returned from loader
      * Avoid crash on wrong output of systemctl version (bsc#1229539)
      * Avoid explicit reading of /etc/salt/minion (bsc#1220357)
      * Enable post_start_cleanup.sh to work in a transaction
      * Fixed cloud Minion configuration for multiple Masters (bsc#1229109)
      * Fixed failing x509 tests with OpenSSL < 1.1
      * Fixed the SELinux context for Salt Minion service (bsc#1219041)
      * Fixed too frequent systemd service restart in test_system test
      * Fixed zyppnotify plugin after latest zypp/libzypp upgrades (bsc#1231697, bsc#1231045)
      * Improved error handling with different OpenSSL versions
      * Increase warn_until_date date for code we still support
      * Prevent using SyncWrapper with no reason
      * Reverted the change making reactor less blocking (bsc#1230322)
      * Use --cachedir for extension_modules in salt-call (bsc#1226141)
      * Use Pygit2 id instead of deprecated oid in gitfs

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231697");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019830.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9512c6b5");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-4032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-5569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-7592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8088");
  script_set_attribute(attribute:"solution", value:
"Update the affected venv-salt-minion package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/S:N/AU:N/R:U/RE:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7592");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-8088");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:venv-salt-minion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'venv-salt-minion-3006.0-150000.3.67.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'venv-salt-minion');
}
