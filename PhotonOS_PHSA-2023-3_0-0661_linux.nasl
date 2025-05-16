#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2023-3.0-0661. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(203933);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2023-42754");

  script_name(english:"Photon OS 3.0: Linux PHSA-2023-3.0-0661");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-3.0-661.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42754");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:3.0");
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
if (_release !~ "^VMware Photon (?:Linux|OS) 3\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 3.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-aws-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-aws-devel-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-aws-docs-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-aws-drivers-gpu-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-aws-hmacgen-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-aws-oprofile-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-aws-sound-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-devel-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-docs-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-drivers-gpu-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-drivers-intel-sgx-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-drivers-sound-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-esx-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-esx-devel-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-esx-docs-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-esx-hmacgen-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-hmacgen-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-oprofile-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-python3-perf-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-devel-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-docs-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.15', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.15.9-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.16', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.16.11-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.22', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.22.18-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-i40e-2.23', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-i40e-2.23.17-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.2', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.2.7-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.4', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.4.2-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.5', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.5.3-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.8', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.8.2-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-iavf-4.9', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-iavf-4.9.1-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.11', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.11.14-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.12', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.12.6-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.6', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.6.4-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.8', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.8.3-4.19.295-3.ph3')) flag++;
if (rpm_exists(rpm:'linux-rt-drivers-intel-ice-1.9', release:'PhotonOS-3.0') && rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-rt-drivers-intel-ice-1.9.11-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-secure-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-secure-devel-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-secure-docs-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-secure-hmacgen-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-secure-lkcm-4.19.295-3.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'linux-tools-4.19.295-3.ph3')) flag++;

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
