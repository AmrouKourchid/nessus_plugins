#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0284-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(189885);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/01");

  script_cve_id(
    "CVE-2023-49933",
    "CVE-2023-49935",
    "CVE-2023-49936",
    "CVE-2023-49937",
    "CVE-2023-49938"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0284-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : slurm (SUSE-SU-2024:0284-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:0284-1 advisory.

  - An issue was discovered in SchedMD Slurm 22.05.x, 23.02.x, and 23.11.x. There is Improper Enforcement of
    Message Integrity During Transmission in a Communication Channel. This allows attackers to modify RPC
    traffic in a way that bypasses message hash checks. The fixed versions are 22.05.11, 23.02.7, and 23.11.1.
    (CVE-2023-49933)

  - An issue was discovered in SchedMD Slurm 23.02.x and 23.11.x. There is Incorrect Access Control because of
    a slurmd Message Integrity Bypass. An attacker can reuse root-level authentication tokens during
    interaction with the slurmd process. This bypasses the RPC message hashes that protect against undesired
    MUNGE credential reuse. The fixed versions are 23.02.7 and 23.11.1. (CVE-2023-49935)

  - An issue was discovered in SchedMD Slurm 22.05.x, 23.02.x, and 23.11.x. A NULL pointer dereference leads
    to denial of service. The fixed versions are 22.05.11, 23.02.7, and 23.11.1. (CVE-2023-49936)

  - An issue was discovered in SchedMD Slurm 22.05.x, 23.02.x, and 23.11.x. Because of a double free,
    attackers can cause a denial of service or possibly execute arbitrary code. The fixed versions are
    22.05.11, 23.02.7, and 23.11.1. (CVE-2023-49937)

  - An issue was discovered in SchedMD Slurm 22.05.x and 23.02.x. There is Incorrect Access Control: an
    attacker can modified their extended group list that is used with the sbcast subsystem, and open files
    with an unauthorized set of extended groups. The fixed versions are 22.05.11 and 23.02.7. (CVE-2023-49938)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218053");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-January/017828.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0d4600a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49938");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49937");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnss_slurm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libslurm39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-config-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-cray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-plugin-ext-sensors-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:slurm-webdoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libnss_slurm2-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libnss_slurm2-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libpmi0-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libpmi0-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libslurm39-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libslurm39-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'perl-slurm-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'perl-slurm-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-auth-none-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-auth-none-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-config-23.02.7-150500.5.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-config-man-23.02.7-150500.5.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-cray-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-cray-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-devel-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-devel-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-doc-23.02.7-150500.5.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-lua-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-lua-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-munge-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-munge-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-node-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-node-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-pam_slurm-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-pam_slurm-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-plugin-ext-sensors-rrd-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-plugin-ext-sensors-rrd-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-plugins-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-plugins-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-rest-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-rest-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-slurmdbd-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-slurmdbd-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-sql-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-sql-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-sview-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-sview-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-torque-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-torque-23.02.7-150500.5.15.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'slurm-webdoc-23.02.7-150500.5.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libnss_slurm2-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libpmi0-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libslurm39-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'perl-slurm-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-auth-none-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-config-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-config-man-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-cray-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-devel-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-doc-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-hdf5-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-lua-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-munge-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-node-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-openlava-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-pam_slurm-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-plugin-ext-sensors-rrd-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-plugins-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-rest-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-seff-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-sjstat-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-slurmdbd-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-sql-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-sview-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-testsuite-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-torque-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'slurm-webdoc-23.02.7-150500.5.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss_slurm2 / libpmi0 / libslurm39 / perl-slurm / slurm / etc');
}
