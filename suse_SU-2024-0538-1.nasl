#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0538-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(190848);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/24");

  script_cve_id(
    "CVE-2016-4332",
    "CVE-2018-11202",
    "CVE-2019-8396",
    "CVE-2020-10812",
    "CVE-2021-37501"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0538-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : hdf5 (SUSE-SU-2024:0538-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:0538-1 advisory.

  - The library's failure to check if certain message types support a particular flag, the HDF5 1.8.16 library
    will cast the structure to an alternative structure and then assign to fields that aren't supported by the
    message type and the library will write outside the bounds of the heap buffer. This can lead to code
    execution under the context of the library. (CVE-2016-4332)

  - A NULL pointer dereference was discovered in H5S_hyper_make_spans in H5Shyper.c in the HDF HDF5 1.10.2
    library. It could allow a remote denial of service attack. (CVE-2018-11202)

  - A buffer overflow in H5O__layout_encode in H5Olayout.c in the HDF HDF5 through 1.10.4 library allows
    attackers to cause a denial of service via a crafted HDF5 file. This issue was triggered while repacking
    an HDF5 file, aka Invalid write of size 2. (CVE-2019-8396)

  - An issue was discovered in HDF5 through 1.12.0. A NULL pointer dereference exists in the function
    H5F_get_nrefs() located in H5Fquery.c. It allows an attacker to cause Denial of Service. (CVE-2020-10812)

  - Buffer Overflow vulnerability in HDFGroup hdf5-h5dump 1.12.0 through 1.13.0 allows attackers to cause a
    denial of service via h5tools_str_sprint in /hdf5/tools/lib/h5tools_str.c. (CVE-2021-37501)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1011205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1093641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1125882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207973");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-February/017975.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd665b69");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-4332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37501");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4332");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/21");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-mpich-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-mpich-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-mvapich2-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-mvapich2-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-openmpi3-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-openmpi3-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-openmpi4-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-gnu-openmpi4-hpc-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hdf5_1_10_11-hpc-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_11-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_11-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_11-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_11-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_1_10_11-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_11-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_11-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_11-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_11-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_cpp_1_10_11-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_11-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_11-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_11-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_11-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_fortran_1_10_11-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_11-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_11-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_11-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_11-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_1_10_11-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_11-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5_hl_fortran-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_11-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_11-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc");
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
    {'reference':'hdf5-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5-hpc-examples-1.10.11-150400.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5', 'sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-static-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-module-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-hpc-examples-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5_1_10_11-hpc-examples-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-hpc-release-15.5']},
    {'reference':'hdf5-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5-hpc-examples-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-static-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-module-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-static-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-module-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-static-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-module-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-static-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-module-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-static-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-module-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-hpc-examples-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'hdf5_1_10_11-hpc-examples-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150400.3.12.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']}
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
      severity   : SECURITY_WARNING,
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
