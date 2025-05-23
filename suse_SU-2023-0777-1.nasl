#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0777-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(172647);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id("CVE-2021-37501");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0777-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : hdf5 (SUSE-SU-2023:0777-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 host has packages installed that are affected by a
vulnerability as referenced in the SUSE-SU-2023:0777-1 advisory.

  - Buffer Overflow vulnerability in HDFGroup hdf5-h5dump 1.12.0 through 1.13.0 allows attackers to cause a
    denial of service via h5tools_str_sprint in /hdf5/tools/lib/h5tools_str.c. (CVE-2021-37501)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37501");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-March/014077.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad480c79");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37501");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5-hpc-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mpich-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mpich-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mvapich2-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-mvapich2-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi3-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi3-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi4-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-gnu-openmpi4-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_8-hpc-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-103");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'hdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-hpc-examples-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-hpc-examples-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-103-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-103-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl100-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl100-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'hdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-hpc-examples-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5-hpc-examples-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mpich-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-mvapich2-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi3-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-devel-static-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-gnu-openmpi4-hpc-module-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-hpc-examples-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'hdf5_1_10_8-hpc-examples-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-103-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-103-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl100-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl100-1.10.8-150400.3.6.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_cpp_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mpich-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-mvapich2-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi3-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']},
    {'reference':'libhdf5hl_fortran_1_10_8-gnu-openmpi4-hpc-1.10.8-150400.3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-hpc-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hdf5-gnu-hpc / hdf5-gnu-hpc-devel / hdf5-gnu-mpich-hpc / etc');
}
