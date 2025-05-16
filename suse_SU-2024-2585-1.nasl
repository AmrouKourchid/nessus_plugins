#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2585-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(203004);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id("CVE-2024-0090", "CVE-2024-0091", "CVE-2024-0092");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2585-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel-firmware-nvidia-gspx-G06 (SUSE-SU-2024:2585-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:2585-1 advisory.

    Update to version 555.42.06 for CUDA.

    Security Update 550.90.07:

    - CVE-2024-0090: Fixed out of bounds write (bsc#1223356).
    - CVE-2024-0092: Fixed incorrect exception handling (bsc#1223356).
    - CVE-2024-0091: Fixed untrusted pointer dereference (bsc#1223356).

    Changes in kernel-firmware-nvidia-gspx-G06:

    - Update to 550.100 (bsc#1227575)

    - Add a second flavor to be used by the kernel module versions
      used by CUDA. The firmware targetting CUDA contains '-cuda' in
      its name to track its versions separately from the graphics
      firmware. (bsc#1227417)

    Changes in nvidia-open-driver-G06-signed:

    - Update to 550.100 (bsc#1227575)

      * Fixed a bug that caused OpenGL triple buffering to behave like
        double buffering.

    - To avoid issues with missing dependencies when no CUDA repo
      is present make the dependecy to nvidia-compute-G06 conditional.

    - CUDA is not available for Tumbleweed, exclude the build of the
      cuda flavor.

    - preamble: let the -cuda flavor KMP require the -cuda flavor
      firmware

    - Add a second flavor for building the kernel module versions
      used by CUDA. The kmp targetting CUDA contains '-cuda' in
      its name to track its versions separately from the graphics
      kmp. (bsc#1227417)
    - Provide the meta package nv-prefer-signed-open-driver to
      make sure the latest available SUSE-build open driver is
      installed - independent of the latest available open driver
      version in he CUDA repository.
      Rationale:
      The package cuda-runtime provides the link between CUDA and
      the kernel driver version through a
      Requires: cuda-drivers >= %version
      This implies that a CUDA version will run withany kernel driver
      version equal or higher than a base version.
      nvidia-compute-G06 provides the glue layer between CUDA and
      a specific version of he kernel driver both by providing
      a set of base libraries and by requiring a specific kernel
      version. 'cuda-drivers' (provided by nvidia-compute-utils-G06)
      requires an unversioned nvidia-compute-G06. With this, the
      resolver will install the latest available and applicable
      nvidia-compute-G06.
      nv-prefer-signed-open-driver then represents the latest available
      open driver version and restricts the nvidia-compute-G06 version
      to it. (bsc#1227419)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227575");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036081.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0092");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-cuda-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-cuda-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-cuda-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-cuda-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-cuda-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-cuda-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-kmp-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-nvidia-gspx-G06");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-nvidia-gspx-G06-cuda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nv-prefer-signed-open-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nvidia-open-driver-G06-signed-64kb-devel");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-64kb-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-64kb-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-azure-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-64kb-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-64kb-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-azure-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-64kb-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-64kb-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-azure-555.42.06_k6.4.0_150600.8.5-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-64kb-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-64kb-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-azure-550.100_k6.4.0_150600.8.5-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-64kb-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-64kb-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-azure-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-64kb-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-64kb-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-azure-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-64kb-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-64kb-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-azure-555.42.06_k6.4.0_150600.8.5-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-64kb-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-64kb-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-azure-550.100_k6.4.0_150600.8.5-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-550.100-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-nvidia-gspx-G06-cuda-555.42.06-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nv-prefer-signed-open-driver-555.42.06-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-64kb-devel-550.100-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-azure-devel-550.100-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-64kb-devel-555.42.06-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-azure-devel-555.42.06-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-default-devel-555.42.06-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-64kb-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-azure-555.42.06_k6.4.0_150600.8.5-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-cuda-kmp-default-555.42.06_k6.4.0_150600.23.7-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-default-devel-550.100-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-64kb-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-azure-550.100_k6.4.0_150600.8.5-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'nvidia-open-driver-G06-signed-kmp-default-550.100_k6.4.0_150600.23.7-150600.3.7.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-firmware-nvidia-gspx-G06 / etc');
}
