#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2023-5.0-0046. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204343);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/13");

  script_cve_id(
    "CVE-2022-45886",
    "CVE-2022-45919",
    "CVE-2022-48425",
    "CVE-2023-1192",
    "CVE-2023-2124",
    "CVE-2023-3117",
    "CVE-2023-3212",
    "CVE-2023-3269",
    "CVE-2023-3389",
    "CVE-2023-3390",
    "CVE-2023-35788",
    "CVE-2023-38427",
    "CVE-2023-38430",
    "CVE-2023-38431",
    "CVE-2023-38432"
  );

  script_name(english:"Photon OS 5.0: Linux PHSA-2023-5.0-0046");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-5.0-46.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38427");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-35788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item('Host/PhotonOS/release');
if (isnull(_release) || _release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (_release !~ "^VMware Photon (?:Linux|OS) 5\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 5.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', reference:'linux-api-headers-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-devel-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-docs-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-gpu-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-sound-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-devel-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-docs-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-python3-perf-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-devel-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-docs-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-secure-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-secure-devel-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-secure-docs-6.1.37-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-tools-6.1.37-1.ph5')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux');
}
