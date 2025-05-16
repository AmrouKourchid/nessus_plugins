#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-21310568fa
#

include('compat.inc');

if (description)
{
  script_id(190678);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2023-4408",
    "CVE-2023-5517",
    "CVE-2023-5679",
    "CVE-2023-6516",
    "CVE-2023-50387",
    "CVE-2023-50868"
  );
  script_xref(name:"FEDORA", value:"2024-21310568fa");
  script_xref(name:"IAVA", value:"2024-A-0103-S");

  script_name(english:"Fedora 39 : bind / bind-dyndb-ldap (2024-21310568fa)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2024-21310568fa advisory.

    # Security Fixes

    -    Validating DNS messages containing a lot of DNSSEC signatures could cause excessive CPU load, leading
    to a denial-of-service condition. This has been fixed.
    ([CVE-2023-50387](https://kb.isc.org/docs/cve-2023-50387))

        ISC would like to thank Elias Heftrig, Haya Schulmann, Niklas Vogel, and Michael Waidner from the
    German National Research Center for Applied Cybersecurity ATHENE for bringing this vulnerability to our
    attention. [GL #4424]

    -    Parsing DNS messages with many different names could cause excessive CPU load. This has been fixed.
    ([CVE-2023-4408](https://kb.isc.org/docs/cve-2023-4408))

        ISC would like to thank Shoham Danino from Reichman University, Anat Bremler-Barr from Tel-Aviv
    University, Yehuda Afek from Tel-Aviv University, and Yuval Shavitt from Tel-Aviv University for bringing
    this vulnerability to our attention. [GL #4234]

    -    Specific queries could cause named to crash with an assertion failure when nxdomain-redirect was
    enabled. This has been fixed. ([CVE-2023-5517](https://kb.isc.org/docs/cve-2023-5517)) [GL #4281]

    -    A bad interaction between DNS64 and serve-stale could cause named to crash with an assertion failure,
    when both of these features were enabled. This has been fixed.
    ([CVE-2023-5679](https://kb.isc.org/docs/cve-2023-5679)) [GL #4334]

    -  Under certain circumstances, the DNS-over-TLS client code incorrectly attempted to process more than
    one DNS message at a time, which could cause named to crash with an assertion failure. This has been
    fixed. [GL #4487]

    - Full [Release notes](https://downloads.isc.org/isc/bind9/9.18.24/doc/arm/html/notes.html#notes-for-
    bind-9-18-24)

    ## Related blog post

    - [BIND 9 Security Release and Multi-Vendor Vulnerability Handling, CVE-2023-50387 and
    CVE-2023-50868](https://www.isc.org/blogs/2024-bind-security-release/)



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-21310568fa");
  script_set_attribute(attribute:"solution", value:
"Update the affected 32:bind and / or bind-dyndb-ldap packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-dyndb-ldap");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'bind-9.18.24-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-dyndb-ldap-11.10-24.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-dyndb-ldap');
}
