#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-1301.
##

include('compat.inc');

if (description)
{
  script_id(216223);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2020-11023");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Linux 8 : gcc (ELSA-2025-1301)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2025-1301 advisory.

    - Merge Oracle patches to 8.5.0-23.
      Oracle history:
      May-22-2024 Qing Zhao <qing.zhao@oracle.com> 8.5.0-22.0.1
      - Merge Oracle patches to 8.5.0-22.
      Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      March-27-2024 Qing Zhao <qing.zhao@oracle.com> 8.5.0-21.0.1
      - Merge Oracle patches to 8.5.0-21.
      January-19-2024 Qing Zhao <qing.zhao@oracle.com> 8.5.0-20.0.3
      - Fix Orabug 35283123, i.e, the same bug as GCC PR111407.
        gcc14-pr111407.patch
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      January-5-2024 Jose E. Marchesi <jose.marchesi@oracle.com> 8.5.0-20.0.2
      - Restore support for -mpreserve-args in aarch64 targets, adapted to
        new AArch64 stack frame layout.
        Reviewed-by: Cupertino Miranda <cupertino.miranda@oracle.com>
      October-4-2023 David Faust <david.faust@oracle.com> 8.5.0-20.0.1
      - Forward-port Oracle patches
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      September-28-2023 David Faust <david.faust@oracle.com> 8.5.0-18.0.6
      - Backport additional patches from gcc-9 to fix CVE-2023-4039 patches
        interaction with backported aarch64 -fstack-clash-protection support.
        [Orabug 35843962]
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      August-31-2023 Qing Zhao <qing.zhao@oracle.com> 8.5.0-18.0.5
      - CVE-2023-4039 GCC mitigation.
        Orabug 35751743.
        Includes removal of aarch64-preserve-args.patch.
      - CVE-2022-40982 'Intel Downfall' mitigation.
        Orabug 35751810.
        Add two patches originally from GCC upstream releases/gcc-11 branch.
        with major adjustment.
        gcc11-downfall-disable-gather-in-vec.patch
        gcc11-downfall-support-mno-gather.patch
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      May-11-2023 Jose E. Marchesi <jose.marchesi@oracle.com> 8.5.0-18.0.2
      - Support for -mpreserve-args in aarch64.
        Orabug 35065765.
        Reviewed-by: Qing Zhao <qing.zhao@oracle.com>.
      March-28-2023 Qing Zhao <qing.zhao@oracle.com> 8.5.0-18.0.1
      - Merge Oracle patches with gcc-8.5.0-18.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      January-12-2023 Qing Zhao <qing.zhao@oracle.com> 8.5.0-16.0.1
      - Merge oracle patches with gcc-8.5.0-16.
      November-30-2022 Qing Zhao <qing.zhao@oracle.com> 8.5.0-15.0.2
      - Fix Orabug 34679540 - PROFILE COLLECT BUILD AND WORK LOAD TEST
        ISSUES IN LINUX ARM64.
        Removing the buggy patch that has been removed from upstream gcc too:
        gcc10-pr91971.patch
      September-28-2022 Qing Zhao <qing.zhao@oracle.com> 8.5.0-15.0.1
      - Merge oracle patches with gcc-8.5.0-15.
      June-29-2022 Qing Zhao <qing.zhao@oracle.com> 8.5.0-10.1.0.1
      - Merge oracle patches with gcc-8.5.0-10.1.el8_6.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      May-4-2022 Qing Zhao <qing.zhao@oracle.com> 8.5.0-10.0.2
      - Fix Orabug 34066706 only in OL GCC.
        report error when there is no PROGRAM_SUMMARY section in .gcda file.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      April-27-2022 Marek Polacek <polacek@redhat.com> 8.5.0-10.1
      - backport Default widths with -fdec-format-defaults patch (#2079578)
      March-22-2022 Qing Zhao <qing.zhao@oracle.com> 8.5.0-10.0.1
      - Merge with oracle patches.
      January-5-2022 Qing Zhao <qing.zhao@oracle.com> 8.5.0-4.0.2
      - Add patches to support marvell on Arm:
        gcc9-add-support-for-profile-extension.patch
        gcc10-add-initial-octeontx2-support.patch
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      November-16-2021 Qing Zhao <qing.zhao@oracle.com> 8.5.0-4.0.1
      - Merge oracle patches to security errata 8.5.0-4.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      October-14-2021 Indu Bhagat <indu.bhagat@oracle.com> 8.5.0-3.0.2
      - Fix Orabug 33451471 and backport CTF/BTF enhancements
        ctfc: Free CTF container elements in ctfc_delete_container ()
        ctf: Do not warn for CTF not supported for GNU GIMPLE
        ICE in btf_finalize when compiling with -gbtf (PR debug/102507, Orabug
        33451471)
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      October-5-2021 Qing Zhao <qing.zhao@oracle.com> 8.5.0-3.0.1
      - Merge the following oracle patches to OL8.5 beta:
        - Fix an aarch64 compilation error triggered by the oracle patch
          gcc9-multiple-changes-align.patch on OL8U5 source base.
          gcc-fix-aarch64-tune-params.patch
        - Fix Orabug 33281392 Update CTF and BTF support in OL8 GCC
          This commit brings the support for CTF/BTF debug formats at par with
          upstream.  GCC now generates the CTF/BTF debug information by using the
          internal DWARF representation.
          For backward compatibility reasons, OL8 GCC continues to support -gt
          command line option.
          (Indu Bhagat <indu.bhagat@oracle.com> 8.4.1-1.0.3)
        - Add complex divide improvement
          backport of upstream commit 54f0224d55a1b56dde092460ddf76913670e6efc
          (Patrick.McGehearty <patrick.mcgehearty@oracle.com> 8.4.1-1.0.2)
        - Fix Orabug 32301371 - bug using gcov with preserve paths option
          This is the same bug as GCC bug PR gcov-profile/88994
          gcc9-pr88994.patch
          (Qing Zhao <qing.zhao@oracle.com> 8.3.1-5.1.0.2)
        - Fix generation of CTF type records for completed structs referred
          thru pointers.
          Orabug 31095790.
          (Jose E. Marchesi <jose.marchesi@oracle.com> 8.3.1-5.0.4)
        - Fix Orabug 29838827 - provide an option to adjust the maximum depth
          of nested #include
          This is the same bug as gcc upstream PR90581 from Gcc9:
          gcc9-pr90581.patch
        - Fix Orabug 29541051 -  confusing error message when there is a problem
          with ASAN_OPTIONS 'ERROR: expected '=''
          This is the same bug as gcc upstream PR89832 from Gcc9:
          gcc9-pr89832.patch
          (Qing Zhao <qing.zhao@oracle.com> 8.3.1-5.0.3)
        - Update support for CTF
          Fix Orabug 30833294 GCC generates incorrect CTF for single element arrays
          Fix Orabug 30808764 CTF generation fails when __attribute__ ((mode (XX))) is
          used
          (Indu Bhagat <indu.bhagat@oracle.com> 8.3.1-5.0.2)
        - Apply ares/neoverse support patches only ifarch aarch64.
          (Qing Zhao <qing.zhao@oracle.com> 8.3.1-4.5.0.6)
        - Add 4 patches from gcc9 to support Arm Ares and Neoverse-N1 for Aarch64
          gcc9-add-vec-reverse.patch
          gcc9-multiple-changes-align.patch
          gcc9-initial-mcpu-ares-tuning.patch
          gcc9-add-support-for-neoverse-n1.patch
          (Indu Bhagat <indu.bhagat@oracle.com> 8.3.1-4.5.0.5)
        - Update support for CTF
          Fix Orabug 30778534 gcc should generate CTF for functions at file-scope only
          Fix Orabug 30779193 CTF generation fails for some flavors of vla
          Fix Orabug 30784275 Fix issues wtih CTF generation for typedef constructs
          ctf-3-generation-and-emission-for-a-single-compilation.patch
          ctf-4-update-ctf-testsuite.patch
          (Indu Bhagat <indu.bhagat@oracle.com> 8.3.1-4.5.0.4)
        - Add support for CTF in GCC
          Fix Orabug 30102948 gcc: Add CTF generation to compiler
          Fix Orabug 30102949 gcc: Add CTF generation to compiler (aarch64)
          ctf-1-new-function-lang_GNU_GIMPLE.patch
          ctf-2-command-line-options-gtLEVEL.patch
          ctf-3-generation-and-emission-for-a-single-compilation.patch
          ctf-4-update-ctf-testsuite.patch
          ctf-5-handle-ctf-sections-when-lto-enabled.patch
          (Qing Zhao <qing.zhao@oracle.com> 8.3.1-4.5.0.3)
        - CVE-2018-12207 / Intel SKX102
          OL8 gcc: Intel Mitigation for CVE: CVE-2018-12207
        - Allow -flto -Wa,-mbranches-within-32B-boundaries to pass -mbranches-within-32B-boundaries
          to GNU assembler. Without -lfto, -Wa,-mbranches-within-32B-boundaries to pass
          -mbranches-within-32B-boundaries to GNU assembler using existing GCC binaries.
        - Mitigation patch:
          gcc8-Fix-Wa-with-flto.patch
          (Qing Zhao  <qing.zhao@oracle.com> 8.3.1-4.5.0.2)
        - Fix Orabug 29968294 -      Heap corruption with fprofile-dir=%p prevents
          profiling parallel processes, needed for RDBMS:
          Add patch to fix PR86057 from Gcc9:
          gcc9-pr86057.patch
        - Fix Orabug 30044244 - Profile directory concatenated with object file path
          This is the same bug as gcc upstream PR91971:
          gcc9-pr85759.patch
          gcc10-pr91971.patch
          (Indu Bhagat <indu.bhagat@oracle.com> 8.3.1-4.5.0.1)
        - Fix Orabug 29599147 - Need -fprofile-dir=%q{VAR} backported to gcc8
          This is the similar GCC PR47618, add the fix from GCC9:
          gcc9-pr47618.patch
        - Fix Orabug 29272977 - DB SUPPORT: Need way to dump inlining report from GCC
          Add -fopt-info-inline support from GCC9:
          gcc9-opt-info-inline.patch
        - Fix Orabug 29273006 - DB SUPPORT: need way to turn off inlining of global functions
          Add -flive-patching support from GCC9:
          gcc9-fipa-reference-addressable.patch
          gcc9-fipa-stack-alignment.patch
          gcc9-add-fomit-frame-pointer-to-test.patch
          gcc9-extend-live-patching-option-handling.patch
          gcc9-ipa-stack-alignment-386-test.patch
        - Introduce 'oracle_release' into .spec file. Echo it to gcc/DEV-PHASE.
        - Backport 17 ampere patches from
          https://git.theobroma-systems.com/ampere-computing/gcc.git/log/?h=gcc-8_2_0-amp3-branch
          e18301133ea622f6d6796ded1d15466e70475cf8: Retpoline (Spectre-V2 mitigation) for
                                                    aarch64.
          d735f3ae4712f66362326d179b4d7e9332c79677: Revert 2017-10-24  Richard Biener
          271e2811e59c0c77fc022fa86a7030f20b4cac8e: Correct the maximum shift amount for
                                                    shifted
          0512749950d927de3dd695f2f2aacdfd30cf32fd: Add CPU support for Ampere Computing's
                                                    eMAG.
          c8b87078f9e0714cb9cab602e12a18ceb12df05a: eMAG/Xgene: Procedural cost-model for
                                                    X-Gene
          74610471b3577c5d465c3fd095a65b796b1e074c: Updating cost table for xgene1.
          ddba1553ac412be5596e6e2962c148032c4cf231: [AArch64] Add Xgene1 prefetch tunings.
          b7ebb0a10a8900324074070188a0936ed81b28a4: [AArch64] Fix in xgene1_addrcost_table
          393dc5c50d55d069f91627bf0be5bab812978850: X-Gene: Adapt tuning struct for GCC 8.
          b9136d58824af2118c4969c3edb42cad3318b08f: tree-ssa-list-find-pipeline:
                                                    Add pipelining loads for list finds.
          095496dd8a9491a17a9caec173281ad02e559df5: uncse: Added pass to undo common
                                                    subexpression elimination.
          a7c8dc238e3656e9d2f9256ee76f933c8d7956fb: loop-prefetcher: Adapt defaults for
                                                    X-Gene cores.
          256307f293f1750851576e14c8a42b696eced2da: tree-ssa-cpp: Don't crash on SSA names
                                                    without definition stmts.
          6e32f53be4f6733f6bfe267ad2337aecaf4047f6: Introduce new option -funroll-more.
          1ac2485a2fced091a5cce6343fe6a6337f850e73: New option to bypass aliasing-checks.
          66d7d833bece61e58998ad53a609cd32e3ee4fad: cfgloopmanip: Allow forced creation
                                                    of loop preheaders.
          c4f89d50e200538b1ac8889801705300e0b27ef2: Add new pass to optimise loops.

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-1301.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-gdb-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-plugin-annobin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libgomp-offload-nvptx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:liblsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libubsan");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'cpp-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-static-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-8.5.0-23.0.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-static-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-static-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-8.5.0-23.0.1.el8_10', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cpp-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-c++-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gdb-plugin-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-gfortran-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-offload-nvptx-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-annobin-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gcc-plugin-devel-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libasan-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libatomic-static-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgcc-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgfortran-static-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libgomp-offload-nvptx-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libitm-devel-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'liblsan-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-devel-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libquadmath-static-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-devel-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-docs-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libstdc++-static-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtsan-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libubsan-8.5.0-23.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cpp / gcc / gcc-c++ / etc');
}
