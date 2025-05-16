#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0067-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216569);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id(
    "CVE-2022-3676",
    "CVE-2022-21618",
    "CVE-2022-21619",
    "CVE-2022-21624",
    "CVE-2022-21626",
    "CVE-2022-21628",
    "CVE-2022-39399",
    "CVE-2023-2597",
    "CVE-2023-5676",
    "CVE-2023-21835",
    "CVE-2023-21843",
    "CVE-2023-21930",
    "CVE-2023-21937",
    "CVE-2023-21938",
    "CVE-2023-21939",
    "CVE-2023-21954",
    "CVE-2023-21967",
    "CVE-2023-21968",
    "CVE-2023-22006",
    "CVE-2023-22025",
    "CVE-2023-22036",
    "CVE-2023-22041",
    "CVE-2023-22044",
    "CVE-2023-22045",
    "CVE-2023-22049",
    "CVE-2023-22081",
    "CVE-2023-25193",
    "CVE-2024-20918",
    "CVE-2024-20919",
    "CVE-2024-20921",
    "CVE-2024-20932",
    "CVE-2024-20945",
    "CVE-2024-20952",
    "CVE-2024-21011",
    "CVE-2024-21012",
    "CVE-2024-21068",
    "CVE-2024-21094",
    "CVE-2024-21131",
    "CVE-2024-21138",
    "CVE-2024-21140",
    "CVE-2024-21145",
    "CVE-2024-21147",
    "CVE-2024-21208",
    "CVE-2024-21210",
    "CVE-2024-21217",
    "CVE-2024-21235",
    "CVE-2025-21502"
  );

  script_name(english:"openSUSE 15 Security Update : java-17-openj9 (openSUSE-SU-2025:0067-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0067-1 advisory.

    - Update to OpenJDK 17.0.14 with OpenJ9 0.49.0 virtual machine
    - Including Oracle October 2024 and January 2025 CPU changes
      * CVE-2024-21208 (boo#1231702), CVE-2024-21210 (boo#1231711),
        CVE-2024-21217 (boo#1231716), CVE-2024-21235 (boo#1231719),
        CVE-2025-21502 (boo#1236278)
      * OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.49/

    - Update to OpenJDK 17.0.12 with OpenJ9 0.46.0 virtual machine
    - Including Oracle July 2024 CPU changes
      * CVE-2024-21131 (boo#1228046), CVE-2024-21138 (boo#1228047),
        CVE-2024-21140 (boo#1228048), CVE-2024-21147 (boo#1228052),
        CVE-2024-21145 (boo#1228051)
      * OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.46/

    - Update to OpenJDK 17.0.11 with OpenJ9 0.44.0 virtual machine
    - Including Oracle April 2024 CPU changes
      * CVE-2024-21012 (boo#1222987), CVE-2024-21094 (boo#1222986),
        CVE-2024-21011 (boo#1222979), CVE-2024-21068 (boo#1222983)
      * OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.44/

    - Update to OpenJDK 17.0.10 with OpenJ9 0.43.0 virtual machine
    - Including Oracle January 2024 CPU changes
      * CVE-2024-20918 (boo#1218907), CVE-2024-20919 (boo#1218903),
        CVE-2024-20921 (boo#1218905), CVE-2024-20932 (boo#1218908),
        CVE-2024-20945 (boo#1218909), CVE-2024-20952 (boo#1218911)
      * OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.43/

    - Update to OpenJDK 17.0.9 with OpenJ9 0.41.0 virtual machine
    - Including Oracle October 2023 CPU changes
      * CVE-2023-22081, boo#1216374
      * CVE-2023-22025, boo#1216339
    - Including Openj9 0.41.0 fixes of CVE-2023-5676, boo#1217214
      * For other OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.41

    - Update to OpenJDK 17.0.8.1 with OpenJ9 0.40.0 virtual machine
      * JDK-8313765: Invalid CEN header (invalid zip64 extra data
        field size)

    - Update to OpenJDK 17.0.8 with OpenJ9 0.40.0 virtual machine
    - Including Oracle July 2023 CPU changes
      * CVE-2023-22006 (boo#1213473), CVE-2023-22036 (boo#1213474),
        CVE-2023-22041 (boo#1213475), CVE-2023-22044 (boo#1213479),
        CVE-2023-22045 (boo#1213481), CVE-2023-22049 (boo#1213482),
        CVE-2023-25193 (boo#1207922)
      * OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.40

    - Update to OpenJDK 17.0.7 with OpenJ9 0.38.0 virtual machine
    - Including Oracle April 2023 CPU changes
      * CVE-2023-21930 (boo#1210628), CVE-2023-21937 (boo#1210631),
        CVE-2023-21938 (boo#1210632), CVE-2023-21939 (boo#1210634),
        CVE-2023-21954 (boo#1210635), CVE-2023-21967 (boo#1210636),
        CVE-2023-21968 (boo#1210637)
      * OpenJ9 specific vulnerability: CVE-2023-2597 (boo#1211615)
      * OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.38

    - Update to OpenJDK 17.0.6 with OpenJ9 0.36.0 virtual machine
      * including Oracle January 2023 CPU changes
        - CVE-2023-21835, boo#1207246
        - CVE-2023-21843, boo#1207248
      * OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.36

    - Update to OpenJDK 17.0.5 with OpenJ9 0.35.0 virtual machine
      * Including Oracle October 2022 CPU changes
        CVE-2022-21618 (boo#1204468), CVE-2022-21619 (boo#1204473),
        CVE-2022-21626 (boo#1204471), CVE-2022-21624 (boo#1204475),
        CVE-2022-21628 (boo#1204472), CVE-2022-39399 (boo#1204480)
      * Fixes OpenJ9 vulnerability boo#1204703, CVE-2022-3676
      * OpenJ9 changes, see
        https://www.eclipse.org/openj9/docs/version0.35

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236804");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XA5CCGSPUXUTQHDG25O5DM4G37BLRUMN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c86f7d16");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21624");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-21628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-21968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-20952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21094");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21140");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21502");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-17-openj9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-17-openj9-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-17-openj9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-17-openj9-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-17-openj9-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-17-openj9-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-17-openj9-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'java-17-openj9-17.0.14.0-bp156.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-17-openj9-demo-17.0.14.0-bp156.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-17-openj9-devel-17.0.14.0-bp156.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-17-openj9-headless-17.0.14.0-bp156.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-17-openj9-javadoc-17.0.14.0-bp156.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-17-openj9-jmods-17.0.14.0-bp156.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-17-openj9-src-17.0.14.0-bp156.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-17-openj9 / java-17-openj9-demo / java-17-openj9-devel / etc');
}
