#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2025-5.0-0449. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214382);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id(
    "CVE-2024-38553",
    "CVE-2024-39282",
    "CVE-2024-44950",
    "CVE-2024-47408",
    "CVE-2024-49571",
    "CVE-2024-49974",
    "CVE-2024-52332",
    "CVE-2024-53680",
    "CVE-2024-55881",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56558",
    "CVE-2024-56570",
    "CVE-2024-56582",
    "CVE-2024-56584",
    "CVE-2024-56587",
    "CVE-2024-56590",
    "CVE-2024-56594",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56603",
    "CVE-2024-56604",
    "CVE-2024-56605",
    "CVE-2024-56606",
    "CVE-2024-56615",
    "CVE-2024-56616",
    "CVE-2024-56622",
    "CVE-2024-56623",
    "CVE-2024-56625",
    "CVE-2024-56628",
    "CVE-2024-56633",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56643",
    "CVE-2024-56644",
    "CVE-2024-56658",
    "CVE-2024-56659",
    "CVE-2024-56662",
    "CVE-2024-56663",
    "CVE-2024-56665",
    "CVE-2024-56672",
    "CVE-2024-56675",
    "CVE-2024-56677",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56693",
    "CVE-2024-56694",
    "CVE-2024-56701",
    "CVE-2024-56704",
    "CVE-2024-56709",
    "CVE-2024-56720",
    "CVE-2024-56739",
    "CVE-2024-56745",
    "CVE-2024-56751",
    "CVE-2024-56756",
    "CVE-2024-56759",
    "CVE-2024-56762",
    "CVE-2024-56763",
    "CVE-2024-56770",
    "CVE-2024-56774",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-57798",
    "CVE-2024-57807",
    "CVE-2024-57841",
    "CVE-2024-57876",
    "CVE-2025-23125"
  );

  script_name(english:"Photon OS 5.0: Linux PHSA-2025-5.0-0449");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-5.0-449.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/18");

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

if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-devel-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-docs-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-gpu-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-i40e-2.22.18-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-i40e-docs-2.22.18-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-iavf-4.9.5-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-iavf-docs-4.9.5-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-ice-1.13.7-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-intel-ice-docs-1.13.7-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-drivers-sound-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-devel-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-docs-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-i40e-2.22.18-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-i40e-docs-2.22.18-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-iavf-4.9.5-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-iavf-docs-4.9.5-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-ice-1.13.7-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-esx-drivers-intel-ice-docs-1.13.7-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-python3-perf-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-devel-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-docs-6.1.124-1.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.22', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.22.18-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.23', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.23.17-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.25', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.25.7-3.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.22', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.22.18-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.23', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.23.17-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-docs-2.25', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-docs-2.25.7-3.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.11.1-3.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.5', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.5.3-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.8', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.8.2-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.9.5-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.11.1-3.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.5', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.5.3-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.8', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.8.2-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-docs-4.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-docs-4.9.5-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.11.14-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.12', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.12.7-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.13', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.13.7-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.14', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.14.9-3.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.9.11-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.11', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.11.14-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.12', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.12.7-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.13', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.13.7-5.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.14', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.14.9-3.0601124001.ph5')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-docs-1.9', release:'PhotonOS-5.0') && rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-docs-1.9.11-5.0601124001.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-rt-stalld-ebpf-plugin-6.1.124-1.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'linux-tools-6.1.124-1.ph5')) flag++;

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
