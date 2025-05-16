#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3144-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(206700);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id(
    "CVE-2016-4332",
    "CVE-2017-17507",
    "CVE-2018-11202",
    "CVE-2018-11205",
    "CVE-2019-8396",
    "CVE-2020-10812",
    "CVE-2021-37501",
    "CVE-2024-29158",
    "CVE-2024-29161",
    "CVE-2024-29166",
    "CVE-2024-32608",
    "CVE-2024-32610",
    "CVE-2024-32614",
    "CVE-2024-32619",
    "CVE-2024-32620",
    "CVE-2024-33873",
    "CVE-2024-33874",
    "CVE-2024-33875"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3144-1");

  script_name(english:"SUSE SLES15 Security Update : hdf5, netcdf, trilinos  (SUSE-SU-2024:3144-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:3144-1 advisory.

    hdf5 was updated from version 1.10.8 to 1.10.11:

    - Security issues fixed:

      * CVE-2019-8396: Fixed problems with malformed HDF5 files where content does not match expected size.
    (bsc#1125882)
      * CVE-2018-11202: Fixed that a malformed file could result in chunk index memory leaks. (bsc#1093641)
      * CVE-2016-4332: Fixed an assertion in a previous fix for this issue (bsc#1011205).
      * CVE-2020-10812: Fixed a segfault on file close in h5debug which fails with a core dump on a file that
    has an illegal
        file size in its cache image.Fixes HDFFV-11052, (bsc#1167400).
      * CVE-2021-37501: Fixed buffer overflow in hdf5-h5dump (bsc#1207973)
      * Other security issues fixed (bsc#1224158):

        +  CVE-2024-29158, CVE-2024-29161, CVE-2024-29166, CVE-2024-32608,
        +  CVE-2024-32610, CVE-2024-32614, CVE-2024-32619, CVE-2024-32620,
        +  CVE-2024-33873, CVE-2024-33874, CVE-2024-33875
        +  Additionally, these fixes resolve crashes triggered by the
           reproducers for CVE-2017-17507, CVE-2018-11205. These crashes
           appear to be unrelated to the original problems

    - Other issues fixed:

      * Remove timestamp/buildhost/kernel version from libhdf5.settings (bsc#1209548)
      * Changed the error handling for a not found path in the find plugin process.
      * Fixed a file space allocation bug in the parallel library for chunked datasets.
      * Fixed an assertion failure in Parallel HDF5 when a file can't be created due to an invalid library
    version bounds
        setting.
      * Fixed memory leaks that could occur when reading a dataset from a malformed file.
      * Fixed a bug in H5Ocopy that could generate invalid HDF5 files
      * Fixed potential heap buffer overflow in decoding of link info message.
      * Fixed potential buffer overrun issues in some object header decode routines.
      * Fixed a heap buffer overflow that occurs when reading from a dataset with a compact layout within a
    malformed HDF5
        file.
      * Fixed memory leak when running h5dump with proof of vulnerability file.
      * Added option --no-compact-subset to h5diff
      * Several improvements to parallel compression feature, including:

        + Improved support for collective I/O (for both writes and reads).
        + Reduction of copying of application data buffers passed to H5Dwrite.
        + Addition of support for incremental file space allocation for filtered datasets created in parallel.
        + Addition of support for HDF5's 'don't filter partial edge chunks' flag
        + Addition of proper support for HDF5 fill values with the feature.
        + Addition of 'H5_HAVE_PARALLEL_FILTERED_WRITES' macro toH5pubconf.h so HDF5 applications can
    determine at
          compile-time whether the feature is available.
        + Addition of simple examples

      * h5repack added an optional verbose value for reporting R/W timing.
      * Fixed a metadata cache bug when resizing a pinned/protected cache entry.
      * Fixed a problem with the H5_VERS_RELEASE check in the H5check_version function.
      * Unified handling of collective metadata reads to correctly fix old bugs.
      * Fixed several potential MPI deadlocks in library failure conditions.
      * Fixed an issue with collective metadata reads being permanently disabled after a dataset chunk lookup
    operation.

    netcdf was updated to fix:

    - rebuild against new hdf5 library version.

    trilinos was updated to fix:

    - Rebuild against new hdf5 library version.
    - Fix dependency in module file for MPI version of Trilinos to depend on the correct version of netcdf
    (bsc#1210049).
      This prevents the error message:
      'Lmod has detected the following error: These module(s) or
       extension(s) exist but cannot be loaded as requested: 'trilinos'

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1011205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1093641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1125882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1133222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224158");
  # https://lists.suse.com/pipermail/sle-updates/2024-September/036796.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f8a3994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-4332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-17507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-8396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-29158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-29161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-29166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-33873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-33874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-33875");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4332");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-32608");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-mpich-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-mvapich2-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-openmpi3-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios-gnu-openmpi4-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-mpich-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-mvapich2-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-openmpi3-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:adios_1_13_1-gnu-openmpi4-hpc-devel-static");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_7_4-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_7_4-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_7_4-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_7_4-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetcdf_4_7_4-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpetsc-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpetsc-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpetsc-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpetsc-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpetsc_3_14_5-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpetsc_3_14_5-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpetsc_3_14_5-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpetsc_3_14_5-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtrilinos-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtrilinos-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtrilinos-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtrilinos-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtrilinos_13_2_0-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtrilinos_13_2_0-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtrilinos_13_2_0-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtrilinos_13_2_0-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-mpich-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-mpich-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-mvapich2-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-mvapich2-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-openmpi3-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-openmpi3-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-openmpi4-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netcdf_4_7_4-gnu-openmpi4-hpc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc_3_14_5-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc_3_14_5-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc_3_14_5-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:petsc_3_14_5-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos-hpc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos_13_2_0-gnu-mpich-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos_13_2_0-gnu-mvapich2-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos_13_2_0-gnu-openmpi3-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos_13_2_0-gnu-openmpi4-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:trilinos_13_2_0-hpc-doc");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'adios-gnu-mpich-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-mpich-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-mpich-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-mvapich2-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-mvapich2-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-mvapich2-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-openmpi3-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-openmpi3-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-openmpi3-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-openmpi4-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-openmpi4-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios-gnu-openmpi4-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mpich-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mpich-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mpich-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mpich-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mpich-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mpich-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mvapich2-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mvapich2-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mvapich2-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mvapich2-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mvapich2-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-mvapich2-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi3-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi3-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi3-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi3-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi3-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi3-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi4-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi4-hpc-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi4-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi4-hpc-devel-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi4-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'adios_1_13_1-gnu-openmpi4-hpc-devel-static-1.13.1-150300.12.4.2', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-mpich-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-mvapich2-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-openmpi3-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-gnu-openmpi4-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5-hpc-examples-1.10.11-150300.4.16.15', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mpich-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-mvapich2-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi3-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-devel-static-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-gnu-openmpi4-hpc-module-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-hpc-examples-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'hdf5_1_10_11-hpc-examples-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_cpp_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5_hl_fortran-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mpich-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-mvapich2-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi3-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libhdf5hl_fortran_1_10_11-gnu-openmpi4-hpc-1.10.11-150300.4.16.15', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-mpich-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-mpich-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-mvapich2-hpc-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-mvapich2-hpc-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-openmpi3-hpc-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-openmpi3-hpc-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-openmpi4-hpc-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf-gnu-openmpi4-hpc-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-mpich-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-mpich-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-mvapich2-hpc-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-mvapich2-hpc-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-openmpi3-hpc-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-openmpi3-hpc-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-openmpi4-hpc-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libnetcdf_4_7_4-gnu-openmpi4-hpc-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc-gnu-mpich-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc-gnu-mpich-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc-gnu-mvapich2-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc-gnu-mvapich2-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc-gnu-openmpi3-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc-gnu-openmpi3-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc-gnu-openmpi4-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc-gnu-openmpi4-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc_3_14_5-gnu-mpich-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc_3_14_5-gnu-mpich-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc_3_14_5-gnu-mvapich2-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc_3_14_5-gnu-mvapich2-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc_3_14_5-gnu-openmpi3-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc_3_14_5-gnu-openmpi3-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc_3_14_5-gnu-openmpi4-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libpetsc_3_14_5-gnu-openmpi4-hpc-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos-gnu-mpich-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos-gnu-mpich-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos-gnu-mvapich2-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos-gnu-mvapich2-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos-gnu-openmpi3-hpc-13.2.0-150300.3.12.16', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos-gnu-openmpi3-hpc-13.2.0-150300.3.12.16', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos-gnu-openmpi4-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos-gnu-openmpi4-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos_13_2_0-gnu-mpich-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos_13_2_0-gnu-mpich-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos_13_2_0-gnu-mvapich2-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos_13_2_0-gnu-mvapich2-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos_13_2_0-gnu-openmpi3-hpc-13.2.0-150300.3.12.16', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos_13_2_0-gnu-openmpi3-hpc-13.2.0-150300.3.12.16', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos_13_2_0-gnu-openmpi4-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libtrilinos_13_2_0-gnu-openmpi4-hpc-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-hpc-devel-4.7.4-150300.4.7.19', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-mpich-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-mpich-hpc-devel-4.7.4-150300.4.7.19', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-mvapich2-hpc-4.7.4-150300.4.7.20', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-mvapich2-hpc-devel-4.7.4-150300.4.7.20', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-openmpi3-hpc-4.7.4-150300.4.7.17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-openmpi3-hpc-devel-4.7.4-150300.4.7.17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-openmpi4-hpc-4.7.4-150300.4.7.21', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf-gnu-openmpi4-hpc-devel-4.7.4-150300.4.7.21', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-hpc-devel-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-hpc-devel-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-hpc-devel-static-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-hpc-devel-static-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mpich-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mpich-hpc-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mpich-hpc-devel-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mpich-hpc-devel-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mpich-hpc-devel-static-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mpich-hpc-devel-static-4.7.4-150300.4.7.19', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mvapich2-hpc-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mvapich2-hpc-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mvapich2-hpc-devel-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mvapich2-hpc-devel-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mvapich2-hpc-devel-static-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-mvapich2-hpc-devel-static-4.7.4-150300.4.7.20', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi3-hpc-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi3-hpc-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi3-hpc-devel-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi3-hpc-devel-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi3-hpc-devel-static-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi3-hpc-devel-static-4.7.4-150300.4.7.17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi4-hpc-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi4-hpc-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi4-hpc-devel-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi4-hpc-devel-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi4-hpc-devel-static-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'netcdf_4_7_4-gnu-openmpi4-hpc-devel-static-4.7.4-150300.4.7.21', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-doc-3.14.5-150300.3.4.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-gnu-mpich-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-gnu-mpich-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-gnu-mvapich2-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-gnu-mvapich2-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-gnu-openmpi3-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-gnu-openmpi3-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-gnu-openmpi4-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc-gnu-openmpi4-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc_3_14_5-gnu-mpich-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc_3_14_5-gnu-mpich-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc_3_14_5-gnu-mvapich2-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc_3_14_5-gnu-mvapich2-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc_3_14_5-gnu-openmpi3-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc_3_14_5-gnu-openmpi3-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc_3_14_5-gnu-openmpi4-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'petsc_3_14_5-gnu-openmpi4-hpc-devel-3.14.5-150300.3.4.4', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos-gnu-mpich-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos-gnu-mvapich2-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos-gnu-openmpi3-hpc-devel-13.2.0-150300.3.12.16', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos-gnu-openmpi4-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos-hpc-doc-13.2.0-150300.3.12.9', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-gnu-mpich-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-gnu-mpich-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-gnu-mvapich2-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-gnu-mvapich2-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-gnu-openmpi3-hpc-devel-13.2.0-150300.3.12.16', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-gnu-openmpi3-hpc-devel-13.2.0-150300.3.12.16', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-gnu-openmpi4-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-gnu-openmpi4-hpc-devel-13.2.0-150300.3.12.18', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'trilinos_13_2_0-hpc-doc-13.2.0-150300.3.12.9', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'adios-gnu-mpich-hpc / adios-gnu-mpich-hpc-devel / etc');
}
