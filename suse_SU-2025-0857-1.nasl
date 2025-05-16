#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0857-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(232718);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id("CVE-2024-22038");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0857-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : build (SUSE-SU-2025:0857-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by a vulnerability as referenced in the SUSE-SU-2025:0857-1 advisory.

    -  CVE-2024-22038: Fixed DoS attacks, information leaks with crafted Git repositories (bnc#1230469)

    Other fixes:
    - Fixed behaviour when using '--shell' aka 'osc shell' option
      in a VM build. Startup is faster and permissions stay intact
      now.

    - fixes for POSIX compatibility for obs-docker-support adn
      mkbaselibs
    - Add support for apk in docker/podman builds
    - Add support for 'wget' in Docker images
    - Fix debian support for Dockerfile builds
    - Fix preinstallimages in containers
    - mkosi: add back system-packages used by build-recipe directly
    - pbuild: parse the Release files for debian repos

    - mkosi: drop most systemd/build-packages deps and use obs_scm
             directory as source if present
    - improve source copy handling
    - Introduce --repos-directory and --containers-directory options

    - productcompose: support of building against a baseiso
    - preinstallimage: avoid inclusion of build script generated files
    - preserve timestamps on sources copy-in for kiwi and productcompose
    - alpine package support updates
    - tumbleweed config update

    - debian: Support installation of foreign architecture packages
              (required for armv7l setups)
    - Parse unknown timezones as UTC
    - Apk (Alpine Linux) format support added
    - Implement default value in parameter expansion
    - Also support supplements that use & as 'and'
    - Add workaround for skopeo's argument parser
    - add cap-htm=off on power9
    - Fixed usage of chown calls
    - Remove leading `go` from `purl` locators

    - container related:
      * Implement support for the new <containers> element in kiwi recipes
      * Fixes for SBOM and dependencies of multi stage container builds
      * obs-docker-support: enable dnf and yum substitutions
    - Arch Linux:
      * fix file path for Arch repo
      * exclude unsupported arch
      * Use root as download user
    - build-vm-qemu: force sv48 satp mode on riscv64
    - mkosi:
      * Create .sha256 files after mkosi builds
      * Always pass --image-version to mkosi
    - General improvements and bugfixes (mkosi, pbuild, appimage/livebuild,
                                         obs work detection, documention, SBOM)
    - Support slsa v1 in unpack_slsa_provenance
    - generate_sbom: do not clobber spdx supplier
    - Harden export_debian_orig_from_git (bsc#1230469)

    - SBOM generation:
      - Adding golang introspection support
      - Adding rust binary introspection support
      - Keep track of unknwon licenses and add a 'hasExtractedLicensingInfos'
        section
      - Also normalize licenses for cyclonedx
      - Make generate_sbom errors fatal
      - general improvements
    - Fix noprep building not working because the buildir is removed
    - kiwi image: also detect a debian build if /var/lib/dpkg/status is present
    - Do not use the Encode module to convert a code point to utf8
    - Fix personality syscall number for riscv
    - add more required recommendations for KVM builds
    - set PACKAGER field in build-recipe-arch
    - fix writing _modulemd.yaml
    - pbuild: support --release and --baselibs option
    - container:
      - copy base container information from the annotation into the
        containerinfo
      - track base containers over multiple stages
      - always put the base container last in the dependencies

    - providing fileprovides in createdirdeps tool
    - Introduce buildflag nochecks

    - productcompose: support __all__ option
    - config update: tumbleweed using preinstallexpand
    - minor improvements

    - tumbleweed build config update
    - support the %load macro
    - improve container filename generation (docker)
    - fix hanging curl calls during build (docker)
    - productcompose: fix milestone query

    - tumbleweed build config update
    - 15.6 build config fixes
    - sourcerpm & sourcedep handling fixes
    - productcompose:
      - Fix milestone handling
      - Support bcntsynctag
    - Adding debian support to generate_sbom
    - Add syscall for personality switch on loongarch64 kernel
    - vm-build: ext3 & ext4: fix disk space allocation
    - mkosi format updates, not fully working yet
    - pbuild exception fixes
    - Fixes for current fedora and centos distros
    - Don't copy original dsc sources if OBS-DCH-RELEASE set
    - Unbreak parsing of sources/patches
    - Support ForceMultiVersion in the dockerfile parser
    - Support %bcond of rpm 4.17.1

    - Add a hack for systemd 255.3, creating an empty /etc/os-release
      if missing after preinstall.
    - docker: Fix HEAD request in dummyhttpserver
    - pbuild: Make docker-nobasepackages expand flag the default
    - rpm: Support a couple of builtin rpm macros
    - rpm: Implement argument expansion for define/with/bcond...
    - Fix multiline macro handling
    - Accept -N parameter of %autosetup
    - documentation updates
    - various code cleanup and speedup work.

    - ProductCompose: multiple improvements
    - Add buildflags:define_specfile support
    - Fix copy-in of git subdirectory sources
    - pbuild: Speed up XML parsing
    - pubild: product compose support
    - generate_sbom: add help option
    - podman: enforce runtime=runc
    - Implement direct conflicts from the distro config
    - changelog2spec: fix time zone handling
    - Do not unmount /proc/sys/fs/binfmt_misc before runnint the check scripts
    - spec file cleanup
    - documentation updates

    - productcompose:
      - support schema 0.1
      - support milestones
    - Leap 15.6 config
    - SLE 15 SP6 config

    - productcompose: follow incompatible flavor syntax change
    - pbuild: support for zstd

    - fixed handling for cmdline parameters via kernel packages

    - productcompose:
      * BREAKING: support new schema
      * adapt flavor architecture parsing

    - productcompose:
      * support filtered package lists
      * support default architecture listing
      * fix copy in binaries in VM builds^

    - obsproduct build type got renamed to productcompose

    - Support zstd compressed rpm-md meta data (bsc#1217269)
    - Added Debian 12 configuration
    - First ObsProduct build format support

    - fix SLE 15 SP5 build configuration
    - Improve user agent handling for obs repositories

    - Docker:
      - Support flavor specific build descriptions via Dockerfile.$flavor
      - support 'PlusRecommended' hint to also provide recommended packages
      - use the name/version as filename if both are known
      - Produce docker format containers by default
    - pbuild: Support for signature authentification of OBS resources
    - Fix wiping build root for --vm-type podman
    - Put BUILD_RELEASE and BUILD_CHANGELOG_TIMESTAMP in the /.buildenv
    - build-vm-kvm: use -cpu host on riscv64
    - small fixes and cleanups

    - Added parser for BcntSyncTag in sources

    - pbuild:
      * fix dependency expansion for build types other than spec
      * Reworked cycle handling code
      * add --extra-packs option
      * add debugflags option
    - Pass-through --buildtool-opt
    - Parse Patch and Source lines more accurately
    - fix tunefs functionality
    - minor bugfixes

    - --vm-type=podman added (supports also root-less builds)
    - Also support build constraints in the Dockerfile
    - minor fixes

    - Add SUSE ALP build config

    - BREAKING: Record errors when parsing the project config
                former behaviour was undefined
    - container: Support compression format configuration option
    - Don't setup ccache with --no-init
    - improved loongarch64 support
    - sbom: SPDX supplier tag added
    - kiwi: support different versions per profile
    - preinstallimage: fail when recompression fails
    - Add support for recommends and supplements dependencies
    - Support the 'keepfilerequires' expand flag
    - add '--buildtool-opt=OPTIONS' to pass options to the used build tool
    - distro config updates
      * ArchLinux
      * Tumbleweed
    - documentation updates

    - openSUSE Tumbleweed: sync config and move to suse_version 1699.

    - universal post-build hook, just place a file in /usr/lib/build/post_build.d/
    - mkbaselibs/hwcaps, fix pattern name once again (x86_64_v3)
    - KiwiProduct: add --use-newest-package hint if the option is set

    - Dockerfile support:
      * export multibuild flavor as argument
      * allow parameters in FROM .. scratch lines
      * include OS name in build result if != linux
    - Workaround directory->symlink usrmerge problems for cross arch sysroot
    - multiple fixes for SBOM support

    - KIWI VM image SBOM support added

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230469");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-March/020511.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b990fb9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22038");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22038");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:build-mkbaselibs");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4/5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3/4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'build-20250306-150200.19.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'build-20250306-150200.19.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'build-20250306-150200.19.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'build-20250306-150200.19.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'build-20250306-150200.19.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'build-20250306-150200.19.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'build-20250306-150200.19.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'build-20250306-150200.19.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'build-20250306-150200.19.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'build-20250306-150200.19.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'build-20250306-150200.19.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'build-20250306-150200.19.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'build-20250306-150200.19.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'build-initvm-aarch64-20250306-150200.19.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'build-initvm-powerpc64le-20250306-150200.19.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'build-initvm-s390x-20250306-150200.19.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'build-initvm-x86_64-20250306-150200.19.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'build-mkbaselibs-20250306-150200.19.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'build-mkdrpms-20250306-150200.19.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'build / build-initvm-aarch64 / build-initvm-powerpc64le / etc');
}
