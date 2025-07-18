#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:10787.
##

include('compat.inc');

if (description)
{
  script_id(212100);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/12");

  script_cve_id("CVE-2024-10976", "CVE-2024-10978", "CVE-2024-10979");
  script_xref(name:"ALSA", value:"2024:10787");
  script_xref(name:"RHSA", value:"2024:10787");

  script_name(english:"AlmaLinux 9 : postgresql:15 (ALSA-2024:10787)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:10787 advisory.

    * postgresql: PostgreSQL SET ROLE, SET SESSION AUTHORIZATION reset to wrong user ID (CVE-2024-10978)
      * postgresql: PostgreSQL PL/Perl environment variable changes execute arbitrary code (CVE-2024-10979)
      * postgresql: PostgreSQL row security below e.g. subqueries disregards user ID changes (CVE-2024-10976)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-10787.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:10787");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10979");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(1250, 15, 266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pg_repack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:pgaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgres-decoderbufs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-private-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-test-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:postgresql-upgrade-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'pg_repack-1.4.8-2.module_el9.5.0+120+4533eb20', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pg_repack-1.4.8-2.module_el9.5.0+120+4533eb20', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pg_repack-1.4.8-2.module_el9.5.0+120+4533eb20', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pg_repack-1.4.8-2.module_el9.5.0+120+4533eb20', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pgaudit-1.7.0-1.module_el9.3.0+52+21733919', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pgaudit-1.7.0-1.module_el9.3.0+52+21733919', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pgaudit-1.7.0-1.module_el9.3.0+52+21733919', 'cpu':'s390x', 'release':'9', 'el_string':'el9.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'pgaudit-1.7.0-1.module_el9.3.0+52+21733919', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgres-decoderbufs-1.9.7-1.Final.module_el9.3.0+52+21733919', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgres-decoderbufs-1.9.7-1.Final.module_el9.3.0+52+21733919', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgres-decoderbufs-1.9.7-1.Final.module_el9.3.0+52+21733919', 'cpu':'s390x', 'release':'9', 'el_string':'el9.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgres-decoderbufs-1.9.7-1.Final.module_el9.3.0+52+21733919', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-contrib-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-contrib-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-contrib-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-contrib-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-docs-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-docs-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-docs-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-docs-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-plperl-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-plperl-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-plperl-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-plperl-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-plpython3-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-plpython3-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-plpython3-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-plpython3-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-pltcl-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-pltcl-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-pltcl-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-pltcl-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-private-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-private-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-private-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-private-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-private-libs-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-private-libs-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-private-libs-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-private-libs-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-server-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-server-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-server-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-server-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-server-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-server-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-server-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-server-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-static-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-static-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-static-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-static-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-test-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-test-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-test-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-test-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-test-rpm-macros-15.10-1.module_el9.5.0+126+03d48c9f', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-upgrade-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-upgrade-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-upgrade-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-upgrade-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-upgrade-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'aarch64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-upgrade-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-upgrade-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'s390x', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'postgresql-upgrade-devel-15.10-1.module_el9.5.0+126+03d48c9f', 'cpu':'x86_64', 'release':'9', 'el_string':'el9.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pg_repack / pgaudit / postgres-decoderbufs / postgresql / etc');
}
