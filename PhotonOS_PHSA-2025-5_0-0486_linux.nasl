#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2025-5.0-0486. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232764);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2024-42122",
    "CVE-2024-57977",
    "CVE-2024-57979",
    "CVE-2024-57981",
    "CVE-2024-57986",
    "CVE-2024-57996",
    "CVE-2024-58005",
    "CVE-2024-58009",
    "CVE-2024-58013",
    "CVE-2024-58017",
    "CVE-2024-58052",
    "CVE-2024-58068",
    "CVE-2024-58072",
    "CVE-2024-58077",
    "CVE-2024-58079",
    "CVE-2024-58083",
    "CVE-2025-21712",
    "CVE-2025-21716",
    "CVE-2025-21719",
    "CVE-2025-21725",
    "CVE-2025-21726",
    "CVE-2025-21727",
    "CVE-2025-21728",
    "CVE-2025-21731",
    "CVE-2025-21738",
    "CVE-2025-21745",
    "CVE-2025-21753",
    "CVE-2025-21758",
    "CVE-2025-21760",
    "CVE-2025-21761",
    "CVE-2025-21762",
    "CVE-2025-21763",
    "CVE-2025-21764",
    "CVE-2025-21765",
    "CVE-2025-21766",
    "CVE-2025-21767",
    "CVE-2025-21776",
    "CVE-2025-21779",
    "CVE-2025-21780",
    "CVE-2025-21790",
    "CVE-2025-21791",
    "CVE-2025-21795",
    "CVE-2025-21796",
    "CVE-2025-21806",
    "CVE-2025-21814",
    "CVE-2025-21819",
    "CVE-2025-21826",
    "CVE-2025-21829",
    "CVE-2025-21832"
  );

  script_name(english:"Photon OS 5.0: Linux PHSA-2025-5.0-0486");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-5.0-486.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21791");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-devel-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-docs-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-gpu-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-i40e-2.22.18-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-i40e-docs-2.22.18-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-iavf-4.9.5-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-iavf-docs-4.9.5-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-ice-1.13.7-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-ice-docs-1.13.7-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-sound-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-devel-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-docs-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-i40e-2.22.18-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-i40e-docs-2.22.18-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-iavf-4.9.5-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-iavf-docs-4.9.5-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-ice-1.13.7-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-ice-docs-1.13.7-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-python3-perf-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-devel-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-docs-6.1.130-1.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.22', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.22.18-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.23', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.23.17-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.25', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.25.7-3.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.22', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.22.18-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.23', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.23.17-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.25', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.25.7-3.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.11.1-3.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.5', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.5.3-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.8', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.8.2-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.9.5-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.11.1-3.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.5', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.5.3-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.8', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.8.2-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.9.5-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.11.14-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.12', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.12.7-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.13', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.13.7-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.14', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.14.9-3.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.9.11-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.11.14-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.12', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.12.7-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.13', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.13.7-5.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.14', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.14.9-3.0601130001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.9.11-5.0601130001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-stalld-ebpf-plugin-6.1.130-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-tools-6.1.130-1.ph5')) flag++;

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
