#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-d0ed59bee7
#

include('compat.inc');

if (description)
{
  script_id(211024);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-21618",
    "CVE-2022-21619",
    "CVE-2022-21624",
    "CVE-2022-21628",
    "CVE-2022-39399"
  );
  script_xref(name:"FEDORA", value:"2022-d0ed59bee7");

  script_name(english:"Fedora 37 : java-latest-openjdk (2022-d0ed59bee7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-d0ed59bee7 advisory.

    # New in release OpenJDK 19.0.1 (2022-10-18)

    * [Full release notes](https://builds.shipilev.net/backports-monitor/release-notes-19.0.1.html)
    * This update depends on
    [FEDORA-2022-d0fc6f0dd4](https://bodhi.fedoraproject.org/updates/FEDORA-2022-d0fc6f0dd4)

    ## CVEs Fixed
      - CVE-2022-21618
      - CVE-2022-21619
      - CVE-2022-21624
      - CVE-2022-21628
      - CVE-2022-39399

    ## Security Fixes
      - JDK-8282252: Improve BigInteger/Decimal validation
      - JDK-8285662: Better permission resolution
      - JDK-8286077: Wider MultiByte conversions
      - JDK-8286511: Improve macro allocation
      - JDK-8286519: Better memory handling
      - JDK-8286526: Improve NTLM support
      - JDK-8286910: Improve JNDI lookups
      - JDK-8286918: Better HttpServer service
      - JDK-8287446: Enhance icon presentations
      - JDK-8288508: Enhance ECDSA usage
      - JDK-8289366: Improve HTTP/2 client usage
      - JDK-8289853: Update HarfBuzz to 4.4.1
      - JDK-8290334: Update FreeType to 2.12.1

    ## Major Changes

    ### [JDK-8292654](https://bugs.openjdk.org/browse/JDK-8292654): G1 Remembered set memory footprint
    regression after [JDK-8286115](https://bugs.openjdk.org/browse/JDK-8286115)
    JDK-8286115 changed ergonomic sizing of a component of the remembered sets in G1. This change causes
    increased native memory usage of the Hotspot VM for applications that create large remembered sets with
    the G1 collector.

    In an internal benchmark total GC component native memory usage rose by almost 10% (from 1.2GB to 1.3GB).

    This issue can be worked around by passing double the value of `G1RemSetArrayOfCardsEntries` as printed by
    running the application with `-XX:+PrintFlagsFinal -XX:+UnlockExperimentalVMOptions` to your application.

    E.g. pass `-XX:+UnlockExperimentalVMOptions -XX:G1RemSetArrayOfCardsEntries=128` if a previous run showed
    a value of `64` for `G1RemSetArrayOfCardsEntries` in the output of `-XX:+PrintFlagsFinal`.

    ## [JDK-8292579](https://bugs.openjdk.org/browse/JDK-8292579): Update Timezone Data to 2022c

    This version includes changes from 2022b that merged multiple regions that have the same timestamp data
    post-1970 into a single time zone database.  All time zone IDs remain the same but the merged time zones
    will point to a shared zone database.

    As a result, pre-1970 data may not be compatible with earlier JDK versions.  The affected zones are
    ```Antarctica/Vostok, Asia/Brunei, Asia/Kuala_Lumpur, Atlantic/Reykjavik, Europe/Amsterdam,
    Europe/Copenhagen, Europe/Luxembourg, Europe/Monaco, Europe/Oslo, Europe/Stockholm, Indian/Christmas,
    Indian/Cocos, Indian/Kerguelen, Indian/Mahe,  Indian/Reunion, Pacific/Chuuk, Pacific/Funafuti,
    Pacific/Majuro, Pacific/Pohnpei, Pacific/Wake, Pacific/Wallis, Arctic/Longyearbyen, Atlantic/Jan_Mayen,
    Iceland, Pacific/Ponape, Pacific/Truk, and Pacific/Yap```.

    For more details, refer to the announcement of [2022b](https://mm.icann.org/pipermail/tz-
    announce/2022-August/000071.html)


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-d0ed59bee7");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:java-latest-openjdk package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21618");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-latest-openjdk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'java-latest-openjdk-19.0.1.0.10-2.rolling.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-latest-openjdk');
}
