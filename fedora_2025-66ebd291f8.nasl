#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-66ebd291f8
#

include('compat.inc');

if (description)
{
  script_id(216345);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/15");

  script_cve_id("CVE-2025-23419");
  script_xref(name:"IAVA", value:"2025-A-0086");
  script_xref(name:"FEDORA", value:"2025-66ebd291f8");

  script_name(english:"Fedora 41 : nginx / nginx-mod-fancyindex / nginx-mod-modsecurity / etc (2025-66ebd291f8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 41 host has packages installed that are affected by a vulnerability as referenced in the
FEDORA-2025-66ebd291f8 advisory.


    Changes with nginx 1.26.3                                        05 Feb 2025

        *) Security: insufficient check in virtual servers handling with TLSv1.3
           SNI allowed to reuse SSL sessions in a different virtual server, to
           bypass client SSL certificates verification (CVE-2025-23419).

        *) Bugfix: in the ngx_http_mp4_module.
           Thanks to Nils Bars.

        *) Workaround: gzip filter failed to use preallocated memory alerts
           appeared in logs when using zlib-ng.

        *) Bugfix: nginx could not build libatomic library using the library
           sources if the --with-libatomic=DIR option was used.

        *) Bugfix: nginx now ignores QUIC version negotiation packets from
           clients.

        *) Bugfix: nginx could not be built on Solaris 10 and earlier with the
           ngx_http_v3_module.

        *) Bugfixes in HTTP/3.

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-66ebd291f8");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23419");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nginx-mod-fancyindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nginx-mod-modsecurity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nginx-mod-naxsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nginx-mod-vts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^41([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 41', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'nginx-1.26.3-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'nginx-mod-fancyindex-0.5.2-10.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nginx-mod-modsecurity-1.0.3-16.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nginx-mod-naxsi-1.6-9.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nginx-mod-vts-0.2.3-3.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nginx / nginx-mod-fancyindex / nginx-mod-modsecurity / etc');
}
