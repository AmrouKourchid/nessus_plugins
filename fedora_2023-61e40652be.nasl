#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-61e40652be
#

include('compat.inc');

if (description)
{
  script_id(178701);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2023-30581",
    "CVE-2023-30585",
    "CVE-2023-30588",
    "CVE-2023-30589",
    "CVE-2023-30590"
  );
  script_xref(name:"FEDORA", value:"2023-61e40652be");

  script_name(english:"Fedora 37 : nodejs16 (2023-61e40652be)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-61e40652be advisory.

    ## 2023-06-20, Version 16.20.1 'Gallium' (LTS), @RafaelGSS

    This is a security release.

    ### Notable Changes

    The following CVEs are fixed in this release:

    * [CVE-2023-30581](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30581): `mainModule.__proto__`
    Bypass Experimental Policy Mechanism (High)
    * [CVE-2023-30585](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30585): Privilege escalation
    via Malicious Registry Key manipulation during Node.js installer repair process (Medium)
    * [CVE-2023-30588](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30588): Process interuption due
    to invalid Public Key information in x509 certificates (Medium)
    * [CVE-2023-30589](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30589): HTTP Request Smuggling
    via Empty headers separated by CR (Medium)
    * [CVE-2023-30590](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30590): DiffieHellman does not
    generate keys after setting a private key (Medium)
    * OpenSSL Security Releases
      * [OpenSSL security advisory 28th March](https://www.openssl.org/news/secadv/20230328.txt).
      * [OpenSSL security advisory 20th April](https://www.openssl.org/news/secadv/20230420.txt).
      * [OpenSSL security advisory 30th May](https://www.openssl.org/news/secadv/20230530.txt)
    * c-ares vulnerabilities:
      * [GHSA-9g78-jv2r-p7vc](https://github.com/c-ares/c-ares/security/advisories/GHSA-9g78-jv2r-p7vc)
      * [GHSA-8r8p-23f3-64c2](https://github.com/c-ares/c-ares/security/advisories/GHSA-8r8p-23f3-64c2)
      * [GHSA-54xr-f67r-4pc4](https://github.com/c-ares/c-ares/security/advisories/GHSA-54xr-f67r-4pc4)
      * [GHSA-x6mf-cxr9-8q6v](https://github.com/c-ares/c-ares/security/advisories/GHSA-x6mf-cxr9-8q6v)

    More detailed information on each of the vulnerabilities can be found in [June 2023 Security
    Releases](https://nodejs.org/en/blog/vulnerability/june-2023-security-releases/) blog post.

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-61e40652be");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:nodejs16 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30590");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'nodejs16-16.20.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs16');
}
