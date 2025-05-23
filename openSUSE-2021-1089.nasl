#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1089-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152064);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/06");

  script_cve_id("CVE-2020-29663", "CVE-2021-32739", "CVE-2021-32743");

  script_name(english:"openSUSE 15 Security Update : icinga2 (openSUSE-SU-2021:1089-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1089-1 advisory.

  - Icinga 2 v2.8.0 through v2.11.7 and v2.12.2 has an issue where revoked certificates due for renewal will
    automatically be renewed, ignoring the CRL. This issue is fixed in Icinga 2 v2.11.8 and v2.12.3.
    (CVE-2020-29663)

  - Icinga is a monitoring system which checks the availability of network resources, notifies users of
    outages, and generates performance data for reporting. From version 2.4.0 through version 2.12.4, a
    vulnerability exists that may allow privilege escalation for authenticated API users. With a read-ony
    user's credentials, an attacker can view most attributes of all config objects including `ticket_salt` of
    `ApiListener`. This salt is enough to compute a ticket for every possible common name (CN). A ticket, the
    master node's certificate, and a self-signed certificate are enough to successfully request the desired
    certificate from Icinga. That certificate may in turn be used to steal an endpoint or API user's identity.
    Versions 2.12.5 and 2.11.10 both contain a fix the vulnerability. As a workaround, one may either specify
    queryable types explicitly or filter out ApiListener objects. (CVE-2021-32739)

  - Icinga is a monitoring system which checks the availability of network resources, notifies users of
    outages, and generates performance data for reporting. In versions prior to 2.11.10 and from version
    2.12.0 through version 2.12.4, some of the Icinga 2 features that require credentials for external
    services expose those credentials through the API to authenticated API users with read permissions for the
    corresponding object types. IdoMysqlConnection and IdoPgsqlConnection (every released version) exposes the
    password of the user used to connect to the database. IcingaDB (added in 2.12.0) exposes the password used
    to connect to the Redis server. ElasticsearchWriter (added in 2.8.0)exposes the password used to connect
    to the Elasticsearch server. An attacker who obtains these credentials can impersonate Icinga to these
    services and add, modify and delete information there. If credentials with more permissions are in use,
    this increases the impact accordingly. Starting with the 2.11.10 and 2.12.5 releases, these passwords are
    no longer exposed via the API. As a workaround, API user permissions can be restricted to not allow
    querying of any affected objects, either by explicitly listing only the required object types for object
    query permissions, or by applying a filter rule. (CVE-2021-32743)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AG46DROWC4ZEVBNIZC5IYVVFYH4FMFCS/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61082e9e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32743");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32743");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29663");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-ido-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-ido-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nano-icinga2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-icinga2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
if (release !~ "^(SUSE15\.2|SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2 / 15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'icinga2-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-bin-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-bin-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-bin-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-bin-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-common-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-common-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-common-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-common-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-ido-mysql-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-ido-mysql-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-ido-mysql-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-ido-mysql-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-ido-pgsql-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-ido-pgsql-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-ido-pgsql-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icinga2-ido-pgsql-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nano-icinga2-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nano-icinga2-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nano-icinga2-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nano-icinga2-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-icinga2-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-icinga2-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-icinga2-2.12.5-bp153.2.5.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-icinga2-2.12.5-bp153.2.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'icinga2 / icinga2-bin / icinga2-common / icinga2-ido-mysql / etc');
}
