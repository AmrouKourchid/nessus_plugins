#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-SUSE-RU-2025:0272-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214746);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/29");

  script_cve_id("CVE-2020-6923");
  script_xref(name:"SuSE", value:"SUSE-RU-2025:0272-1");

  script_name(english:"SUSE SLES15 : Recommended update for hplip (SUSE-SU-SUSE-RU-2025:0272-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by a vulnerability as referenced
in the SUSE-SU-SUSE-RU-2025:0272-1 advisory.

    This update for hplip fixes the following issues:

    Update to hplip 3.24.4 (jsc#PED-5846)

    - Added support for new printers:
      * HP OfficeJet 8120 All-in-One series
      * HP OfficeJet Pro 8120 All-in-One series
      * HP OfficeJet 8130 All-in-One series
      * HP OfficeJet Pro 8130 All-in-One series
      * HP OfficeJet Pro 9720 Series
      * HP OfficeJet Pro 9730 Series
      * HP OfficeJet Pro 9130b series
      * HP OfficeJet Pro 9120b series
      * HP OfficeJet Pro 9110b series
      * HP Color LaserJet Enterprise Flow MFP X58045z
      * HP Color LaserJet Enterprise Flow MFP X58045zs
      * HP Color LaserJet Enterprise MFP X58045dn
      * HP Color LaserJet Enterprise MFP X58045
      * HP LaserJet Pro P1106 plus
      * HP LaserJet Pro P1108 plus
      * HP LaserJet Tank MFP 1602a
      * HP LaserJet Tank MFP 1602w
      * HP LaserJet Tank MFP 1604w
      * HP LaserJet Tank MFP 2602dn
      * HP LaserJet Tank MFP 2602sdn
      * HP LaserJet Tank MFP 2602sdw
      * HP LaserJet Tank MFP 2602dw
      * HP LaserJet Tank MFP 2604dw
      * HP LaserJet Tank MFP 2604sdw
      * HP LaserJet Tank MFP 2603dw
      * HP LaserJet Tank MFP 2603sdw
      * HP LaserJet Tank MFP 2605sdw
      * HP LaserJet Tank MFP 2606dn
      * HP LaserJet Tank MFP 2606sdn
      * HP LaserJet Tank MFP 2606sdw
      * HP LaserJet Tank MFP 2606dw
      * HP LaserJet Tank MFP 2606dc
      * HP LaserJet Tank MFP 1005
      * HP LaserJet Tank MFP 1005w
      * HP LaserJet Tank MFP 1005nw
      * HP LaserJet Tank 1502a
      * HP LaserJet Tank 1502w
      * HP LaserJet Tank 1504w
      * HP LaserJet Tank 2502dw
      * HP LaserJet Tank 2502dn
      * HP LaserJet Tank 2504dw
      * HP LaserJet Tank 2503dw
      * HP LaserJet Tank 2506dw
      * HP LaserJet Tank 2506d
      * HP LaserJet Tank 2506dn
      * HP LaserJet Tank 1020
      * HP LaserJet Tank 1020w
      * HP LaserJet Tank 1020nw
      * HP LaserJet Pro 4001ne
      * HP LaserJet Pro 4001n
      * HP LaserJet Pro 4001dne
      * HP LaserJet Pro 4001dn
      * HP LaserJet Pro 4001dwe
      * HP LaserJet Pro 4001dw
      * HP LaserJet Pro 4001d
      * HP LaserJet Pro 4001de
      * HP LaserJet Pro 4002ne
      * HP LaserJet Pro 4002n
      * HP LaserJet Pro 4002dne
      * HP LaserJet Pro 4002dn
      * HP LaserJet Pro 4002dwe
      * HP LaserJet Pro 4002dw
      * HP LaserJet Pro 4002d
      * HP LaserJet Pro 4002de
      * HP LaserJet Pro 4003dn
      * HP LaserJet Pro 4003dw
      * HP LaserJet Pro 4003n
      * HP LaserJet Pro 4003d
      * HP LaserJet Pro 4004d
      * HP LaserJet Pro 4004dn
      * HP LaserJet Pro 4004dw
      * HP LaserJet Pro MFP 4101dwe
      * HP LaserJet Pro MFP 4101dw
      * HP LaserJet Pro MFP 4101fdn
      * HP LaserJet Pro MFP 4101fdne
      * HP LaserJet Pro MFP 4101fdw
      * HP LaserJet Pro MFP 4101fdwe
      * HP LaserJet Pro MFP 4102dwe
      * HP LaserJet Pro MFP 4102dw
      * HP LaserJet Pro MFP 4102fdn
      * HP LaserJet Pro MFP 4102fdw
      * HP LaserJet Pro MFP 4102fdwe
      * HP LaserJet Pro MFP 4102fdne
      * HP LaserJet Pro MFP 4102fnw
      * HP LaserJet Pro MFP 4102fnwe
      * HP LaserJet Pro MFP 4103dw
      * HP LaserJet Pro MFP 4103dn
      * HP LaserJet Pro MFP 4103fdn
      * HP LaserJet Pro MFP 4103fdw
      * HP LaserJet Pro MFP 4104dw
      * HP LaserJet Pro MFP 4104fdw
      * HP LaserJet Pro MFP 4104fdn
      * HP ScanJet Pro 3600 f1
      * HP ScanJet Pro N4600 fnw1
      * HP ScanJet Pro 2600 f1
      * HP ScanJet Enterprise Flow N6600 fnw1
      * HP Color LaserJet Managed MFP E785dn
      * HP Color LaserJet Managed MFP E78523dn
      * HP Color LaserJet Managed MFP E78528dn
      * HP Color LaserJet Managed MFP E786dn
      * HP Color LaserJet Managed MFP E786 Core Printer
      * HP Color LaserJet Managed MFP E78625dn
      * HP Color LaserJet  Managed FlowMFP E786z
      * HP Color LaserJet Managed Flow MFP E78625z
      * HP Color LaserJet Managed MFP E78630dn
      * HP Color LaserJet Managed Flow MFP E78630z
      * HP Color LaserJet Managed MFP E78635dn
      * HP Color LaserJet Managed Flow MFP E78635z
      * HP LaserJet Managed MFP E731dn
      * HP LaserJet Managed MFP E731 Core Printer
      * HP LaserJet Managed MFP E73130dn
      * HP LaserJet Managed Flow MFP E731z
      * HP LaserJet Managed Flow MFP E73130z
      * HP LaserJet Managed MFP E73135dn
      * HP LaserJet Managed Flow MFP E73135z
      * HP LaserJet Managed MFP E73140dn
      * HP LaserJet Managed Flow MFP E73140z
      * HP Color LaserJet Managed MFP E877dn
      * HP Color LaserJet Managed MFP E877 Core Printer
      * HP Color LaserJet Managed MFP E87740dn
      * HP Color LaserJet Managed Flow MFP E877z
      * HP Color LaserJet Managed Flow MFP E87740z
      * HP Color LaserJet Managed MFP E87750dn
      * HP Color LaserJet Managed Flow MFP E87750z
      * HP Color LaserJet Managed MFP E87760dn
      * HP Color LaserJet Managed Flow MFP E87760z
      * HP Color LaserJet Managed MFP E87770dn
      * HP Color LaserJet Managed Flow MFP E87770z
      * HP LaserJet Managed MFP E826dn
      * HP LaserJet Managed MFP E826 Core Printer
      * HP LaserJet Managed MFP E82650dn
      * HP LaserJet Managed Flow MFP E826z
      * HP LaserJet Managed Flow MFP E82650z
      * HP LaserJet Managed MFP E82660dn
      * HP LaserJet Managed Flow MFP E82660z
      * HP LaserJet Managed MFP E82670dn
      * HP LaserJet Managed Flow MFP E82670z
      * HP LaserJet Managed MFP E730dn
      * HP LaserJet Managed MFP E73025dn
      * HP LaserJet Managed MFP E73030dn
      * HP LaserJet Pro MFP 3101fdwe
      * HP LaserJet Pro MFP 3101fdw
      * HP LaserJet Pro MFP 3102fdwe
      * HP LaserJet Pro MFP 3102fdw
      * HP LaserJet Pro MFP 3103fdw
      * HP LaserJet Pro MFP 3104fdw
      * HP LaserJet Pro MFP 3101fdne
      * HP LaserJet Pro MFP 3101fdn
      * HP LaserJet Pro MFP 3102fdne
      * HP LaserJet Pro MFP 3102fdn
      * HP LaserJet Pro MFP 3103fdn
      * HP LaserJet Pro MFP 3104fdn
      * HP LaserJet Pro 3001dwe
      * HP LaserJet Pro 3001dw
      * HP LaserJet Pro 3002dwe
      * HP LaserJet Pro 3002dw
      * HP LaserJet Pro 3003dw
      * HP LaserJet Pro 3004dw
      * HP LaserJet Pro 3001dne
      * HP LaserJet Pro 3001dn
      * HP LaserJet Pro 3002dne
      * HP LaserJet Pro 3002dn
      * HP LaserJet Pro 3003dn
      * HP LaserJet Pro 3004dn
      * HP Smart Tank 520_540 series
      * HP Smart Tank 580-590 series
      * HP Smart Tank 5100 series
      * HP Smart Tank 210-220 series
      * HP Color LaserJet Enterprise 6700dn
      * HP Color LaserJet Enterprise 6700
      * HP Color LaserJet Enterprise 6701dn
      * HP Color LaserJet Enterprise 6701
      * HP Color LaserJet Enterprise X654dn
      * HP Color LaserJet Enterprise X65455dn
      * HP Color LaserJet Enterprise X654
      * HP Color LaserJet Enterprise X65465dn
      * HP Color LaserJet Enterprise X654 65 PPM
      * HP Color LaserJet Enterprise X654 55 to 65ppm License
      * HP Color LaserJet Enterprise X654 Down License
      * HP Color LaserJet Enterprise MFP 6800dn
      * HP Color LaserJet Enterprise Flow MFP 6800zf
      * HP Color LaserJet Enterprise Flow MFP 6800zfsw
      * HP Color LaserJet Enterprise Flow MFP 6800zfw+
      * HP Color LaserJet Enterprise MFP 6800
      * HP Color LaserJet Enterprise MFP 6801
      * HP Color LaserJet Enterprise MFP 6801 zfsw
      * HP Color LaserJet Enterprise Flow MFP 6801zfw+
      * HP Color LaserJet Enterprise MFP X677 55 to 65ppm License
      * HP Color LaserJet Enterprise MFP X677 65ppm
      * HP Color LaserJet Enterprise MFP X677s
      * HP Color LaserJet Enterprise Flow MFP X677z
      * HP Color LaserJet Enterprise MFP X67765dn
      * HP Color LaserJet Enterprise Flow MFP X67765zs
      * HP Color LaserJet Enterprise Flow MFP X67765z+
      * HP Color LaserJet Enterprise MFP X677
      * HP Color LaserJet Enterprise MFP X67755dn
      * HP Color LaserJet Enterprise Flow MFP X67755zs
      * HP Color LaserJet Enterprise Flow MFP X67755z+
      * HP Color LaserJet Enterprise MFP X677dn
      * HP Color LaserJet Enterprise Flow MFP X677zs
      * HP Color LaserJet Enterprise Flow MFP X677z+
      * HP Color LaserJet Enterprise 5700dn
      * HP Color LaserJet Enterprise 5700
      * HP Color LaserJet Enterprise X55745dn
      * HP Color LaserJet Enterprise X55745
      * HP Color LaserJet Enterprise MFP 5800dn
      * HP Color LaserJet Enterprise MFP 5800f
      * HP Color LaserJet Enterprise Flow MFP 5800zf
      * HP Color LaserJet Enterprise MFP 5800
      * HP Color LaserJet Enterprise MFP X57945
      * HP Color LaserJet Enterprise Flow MFP X57945zs
      * HP Color LaserJet Enterprise MFP X57945dn
      * HP Color LaserJet Enterprise Flow MFP X57945z
      * HP Color LaserJet Pro MFP 4301fdne
      * HP Color LaserJet Pro MFP 4301fdwe
      * HP Color LaserJet Pro MFP 4301cdwe
      * HP Color LaserJet Pro MFP 4301cfdne
      * HP Color LaserJet Pro MFP 4301cfdwe
      * HP Color LaserJet Pro MFP 4302dwe
      * HP Color LaserJet Pro MFP 4302fdne
      * HP Color LaserJet Pro MFP 4302fdwe
      * HP Color LaserJet Pro MFP 4302cdwe
      * HP Color LaserJet Pro MFP 4302fdn
      * HP Color LaserJet Pro MFP 4302fdw
      * HP Color LaserJet Pro MFP 4303dw
      * HP Color LaserJet Pro MFP 4303fdn
      * HP Color LaserJet Pro MFP 4303fdw
      * HP Color LaserJet Pro MFP 4303cdw
      * HP Color LaserJet Pro MFP 4303cfdn
      * HP Color LaserJet Pro MFP 4303cfdw
      * HP Color LaserJet Pro 4201dne
      * HP Color LaserJet Pro 4201dwe
      * HP Color LaserJet Pro 4201cdne
      * HP Color LaserJet Pro 4201cdwe
      * HP Color LaserJet Pro 4202dne
      * HP Color LaserJet Pro 4202dwe
      * HP Color LaserJet Pro 4202dn
      * HP Color LaserJet Pro 4202dw
      * HP Color LaserJet Pro 4203dn
      * HP Color LaserJet Pro 4203dw
      * HP Color LaserJet Pro 4203cdn
      * HP Color LaserJet Pro 4203cdw
      * HP DeskJet 2800 All-in-One Printer series
      * HP DeskJet 2800e All-in-One Printer series
      * HP DeskJet Ink Advantage 2800 All-in-One Printer series
      * HP DeskJet 4200 All-in-One Printer series
      * HP DeskJet 4200e All-in-One Printer series
      * HP DeskJet Ink Advantage 4200 All-in-One Printer series
      * HP DeskJet Ink Advantage Ultra 4900 All-in-One Printer series
      * HP OfficeJet Pro 9130b series
      * HP OfficeJet Pro 9120b series
      * HP OfficeJet Pro 9110b series
      * HP Color LaserJet Enterprise Flow MFP X58045z
      * HP Color LaserJet Enterprise Flow MFP X58045zs
      * HP Color LaserJet Enterprise MFP X58045dn
      * HP Color LaserJet Enterprise MFP X58045
      * HP LaserJet Pro P1106 plus
      * HP LaserJet Pro P1108 plus
      * HP OfficeJet 8120 All-in-One series
      * HP OfficeJet Pro 8120 All-in-One series
      * HP OfficeJet 8130 All-in-One series
      * HP OfficeJet Pro 8130 All-in-One series
      * HP OfficeJet Pro 9720 Series
      * HP OfficeJet Pro 9730 Series

    - Bug fixes:
      * hpmud: sanitize printer serial number (bsc#1209401, lp#2012262)

    - hppsfilter: booklet printing: change insecure fixed /tmp file paths (bsc#1214399)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234745");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-January/038220.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-6923");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6923");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip-hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hplip-udev-rules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'hplip-3.24.4-150400.3.17.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'hplip-devel-3.24.4-150400.3.17.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'hplip-hpijs-3.24.4-150400.3.17.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'hplip-sane-3.24.4-150400.3.17.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'hplip-udev-rules-3.24.4-150400.3.17.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hplip / hplip-devel / hplip-hpijs / hplip-sane / hplip-udev-rules');
}
