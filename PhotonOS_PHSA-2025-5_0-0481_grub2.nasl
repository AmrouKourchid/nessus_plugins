#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2025-5.0-0481. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233411);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2024-45774",
    "CVE-2024-45775",
    "CVE-2024-45776",
    "CVE-2024-45777",
    "CVE-2024-45778",
    "CVE-2024-45779",
    "CVE-2024-45780",
    "CVE-2024-45781",
    "CVE-2024-45782",
    "CVE-2024-45783",
    "CVE-2024-56737",
    "CVE-2025-0622",
    "CVE-2025-0624",
    "CVE-2025-0677",
    "CVE-2025-0678",
    "CVE-2025-0684",
    "CVE-2025-0685",
    "CVE-2025-0686",
    "CVE-2025-0689",
    "CVE-2025-0690",
    "CVE-2025-1118",
    "CVE-2025-1125"
  );
  script_xref(name:"IAVA", value:"2024-A-0207");

  script_name(english:"Photon OS 5.0: Grub2 PHSA-2025-5.0-0481");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the grub2 package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-5.0-481.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0678");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:grub2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'grub2-2.06-21.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'grub2-efi-2.06-21.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'grub2-efi-image-2.06-21.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'grub2-emu-2.06-21.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'grub2-lang-2.06-21.ph5')) flag++;
if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'grub2-pc-2.06-21.ph5')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2');
}
