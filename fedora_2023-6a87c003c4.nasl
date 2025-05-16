#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-6a87c003c4
#

include('compat.inc');

if (description)
{
  script_id(180438);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2023-0809", "CVE-2023-3592", "CVE-2023-28366");
  script_xref(name:"FEDORA", value:"2023-6a87c003c4");

  script_name(english:"Fedora 38 : libwebsockets / mosquitto (2023-6a87c003c4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-6a87c003c4 advisory.

    2.0.17

    Broker:

    * Fix `max_queued_messages 0` stopping clients from receiving messages
    * Fix `max_inflight_messages` not being set correctly.

    Apps:

    * Fix `mosquitto_passwd -U` backup file creation.


    2.0.16

    Security:

    * CVE-2023-28366: Fix memory leak in broker when clients send multiple QoS 2 messages with the same
    message ID, but then never respond to the PUBREC commands.
    * CVE-2023-0809: Fix excessive memory being allocated based on malicious initial packets that are not
    CONNECT packets.
    * CVE-2023-3592: Fix memory leak when clients send v5 CONNECT packets with a will message that contains
    invalid property types.
    * Broker will now reject Will messages that attempt to publish to $CONTROL/.
    * Broker now validates usernames provided in a TLS certificate or TLS-PSK identity are valid UTF-8.
    * Fix potential crash when loading invalid persistence file.
    * Library will no longer allow single level wildcard certificates, e.g. *.com

    Broker:

    * Fix $SYS messages being expired after 60 seconds and hence unchanged values disappearing.
    * Fix some retained topic memory not being cleared immediately after used.
    * Fix error handling related to the `bind_interface` option.
    * Fix std* files not being redirected when daemonising, when built with assertions removed.
    * Fix default settings incorrectly allowing TLS v1.1.
    * Use line buffered mode for stdout. Closes #2354.
    * Fix bridges with non-matching cleansession/local_cleansession being expired on start after restoring
    from persistence.
    * Fix connections being limited to 2048 on Windows. The limit is now 8192, where supported.
    * Broker will log warnings if sensitive files are world readable/writable, or if the owner/group is not
    the same as the user/group the broker is running as. In future versions the broker will refuse to open
    these files.
    * mosquitto_memcmp_const is now more constant time.
    * Only register with DLT if DLT logging is enabled.
    * Fix any possible case where a json string might be incorrectly loaded. This could have caused a crash if
    a textname or textdescription field of a role was not a string, when loading the dynsec config from file
    only.
    * Dynsec plugin will not allow duplicate clients/groups/roles when loading config from file, which matches
    the behaviour for when creating them.
    * Fix heap overflow when reading corrupt config with log_dest file.

    Client library:

    * Use CLOCK_BOOTTIME when available, to keep track of time. This solves the problem of the client OS
    sleeping and the client hence not being able to calculate the actual time for keepalive purposes.
    * Fix default settings incorrectly allowing TLS v1.1.
    * Fix high CPU use on slow TLS connect.

    Clients:

    * Fix incorrect topic-alias property value in mosquitto_sub json output.
    * Fix confusing message on TLS certificate verification.

    Apps:

    * mosquitto_passwd uses mkstemp() for backup files.
    * `mosquitto_ctrl dynsec init` will refuse to overwrite an existing file, without a race-condition.


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-6a87c003c4");
  script_set_attribute(attribute:"solution", value:
"Update the affected libwebsockets and / or mosquitto packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3592");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mosquitto");
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
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'libwebsockets-4.3.2-5.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mosquitto-2.0.17-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwebsockets / mosquitto');
}
