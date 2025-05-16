#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2024-5.0-0345. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205572);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/16");

  script_cve_id(
    "CVE-2023-52760",
    "CVE-2024-41007",
    "CVE-2024-41012",
    "CVE-2024-41020",
    "CVE-2024-41022",
    "CVE-2024-41027",
    "CVE-2024-41035",
    "CVE-2024-41038",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41048",
    "CVE-2024-41049",
    "CVE-2024-41050",
    "CVE-2024-41055",
    "CVE-2024-41058",
    "CVE-2024-41060",
    "CVE-2024-41062",
    "CVE-2024-41063",
    "CVE-2024-41069",
    "CVE-2024-41072",
    "CVE-2024-41073",
    "CVE-2024-41076",
    "CVE-2024-41078",
    "CVE-2024-41079",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-42101",
    "CVE-2024-42102",
    "CVE-2024-42103",
    "CVE-2024-42104",
    "CVE-2024-42105",
    "CVE-2024-42106",
    "CVE-2024-42109",
    "CVE-2024-42119",
    "CVE-2024-42120",
    "CVE-2024-42126",
    "CVE-2024-42131",
    "CVE-2024-42136",
    "CVE-2024-42142",
    "CVE-2024-42145",
    "CVE-2024-42148",
    "CVE-2024-42152",
    "CVE-2024-42153",
    "CVE-2024-42154",
    "CVE-2024-42157",
    "CVE-2024-42159",
    "CVE-2024-42161",
    "CVE-2024-42223",
    "CVE-2024-42224",
    "CVE-2024-42225",
    "CVE-2024-42226",
    "CVE-2024-42229",
    "CVE-2024-42230",
    "CVE-2024-42232",
    "CVE-2024-42236",
    "CVE-2024-42240",
    "CVE-2024-42245",
    "CVE-2024-42246",
    "CVE-2024-42247"
  );

  script_name(english:"Photon OS 5.0: Linux PHSA-2024-5.0-0345");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-5.0-345.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42225");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-42159");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-devel-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-docs-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-gpu-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-i40e-2.22.18-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-i40e-docs-2.22.18-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-iavf-4.9.5-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-iavf-docs-4.9.5-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-ice-1.13.7-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-ice-docs-1.13.7-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-sound-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-devel-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-docs-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-i40e-2.22.18-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-i40e-docs-2.22.18-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-iavf-4.9.5-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-iavf-docs-4.9.5-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-ice-1.13.7-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-ice-docs-1.13.7-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-python3-perf-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-devel-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-docs-6.1.102-1.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.22', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.22.18-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.23', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.23.17-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.25', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.25.7-2.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.22', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.22.18-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.23', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.23.17-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.25', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.25.7-2.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.11.1-2.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.5', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.5.3-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.8', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.8.2-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.9.5-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.11.1-2.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.5', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.5.3-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.8', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.8.2-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.9.5-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.11.14-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.12', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.12.7-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.13', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.13.7-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.14', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.14.9-2.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.9.11-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.11.14-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.12', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.12.7-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.13', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.13.7-4.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.14', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.14.9-2.0601102001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.9.11-4.0601102001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-stalld-ebpf-plugin-6.1.102-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-tools-6.1.102-1.ph5')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux');
}
