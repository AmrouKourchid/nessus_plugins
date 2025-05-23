#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-6d9aba8c3c
#

include('compat.inc');

if (description)
{
  script_id(211647);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");
  script_xref(name:"FEDORA", value:"2024-6d9aba8c3c");

  script_name(english:"Fedora 41 : llvm-test-suite (2024-6d9aba8c3c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 41 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2024-6d9aba8c3c advisory.

    Remove ClamAV subdirectory because of viruses in input files:

    These were the findings:

    ```
    MultiSource/Applications/ClamAV/inputs/rtf-test/rtf1.rtf: Eicar-Signature
    MultiSource/Applications/ClamAV/inputs/clam.zip: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/rtf-test/docCLAMexe.rtf: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/rtf-test/Doc11.rtf: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/rtf-test/Doc1.rtf: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/clam.cab: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/rtf-test/Doc2.rtf: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/clam.exe.bz2: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/rtf-test/doc3.rtf: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/clam.exe: Clamav.Test.File-6
    MultiSource/Applications/ClamAV/inputs/rtf-test/Doc22.rtf: Clamav.Test.File-6
    ```


    ----

    Remove broken links in source tarball

    Before it wasn't possible to pass `-DTEST_SUITE_SUBDIRS=CTMark` to cmake
    when configuring the llvm-test-suite:

    ```
    -- Adding directory CTMark
    CMake Error at CTMark/CMakeLists.txt:1 (add_subdirectory):
      add_subdirectory given source 7zip which is not an existing directory.

    CMake Error at CTMark/CMakeLists.txt:5 (add_subdirectory):
      add_subdirectory given source lencod which is not an existing directory.
    ```

    The llvm-test-suite command script `pkg_test_suite.sh` removes
    directories with BAD or unreviewed licenses. Currently this leaves at
    least two directories in a broken state:

    ```
    /usr/share/llvm-test-suite/CTMark/7zip -> ../MultiSource/Benchmarks/7zip
    /usr/share/llvm-test-suite/CTMark/lencod -> ../MultiSource/Applications/JM/lencod
    ```

    In both cases the link target is non-existent.

    Therefore I find any broken symbolic links, remove them and adapt the
    `CMakeLists.txt` to not have the `add_subdirectory(broken_link)` entry in
    it. Here's an excerpt of what the `pkg_test_suite.sh` script shows when
    running as a proof of the work it does now.

    ```
    ++ find test-suite-19.1.0.src -type l '!' -exec test -e '{}' ';' -print
    + broken_symlinks='test-suite-19.1.0.src/CTMark/7zip
    test-suite-19.1.0.src/CTMark/lencod'
    + for f in $broken_symlinks
    + test -L test-suite-19.1.0.src/CTMark/7zip
    + rm -fv test-suite-19.1.0.src/CTMark/7zip
    removed 'test-suite-19.1.0.src/CTMark/7zip'
    ++ dirname test-suite-19.1.0.src/CTMark/7zip
    + basedir=test-suite-19.1.0.src/CTMark
    ++ basename test-suite-19.1.0.src/CTMark/7zip
    + dir=7zip
    + cmake_file=test-suite-19.1.0.src/CTMark/CMakeLists.txt
    + test -f test-suite-19.1.0.src/CTMark/CMakeLists.txt
    + sed -i 's/add_subdirectory(7zip)//g' test-suite-19.1.0.src/CTMark/CMakeLists.txt
    + for f in $broken_symlinks
    + test -L test-suite-19.1.0.src/CTMark/lencod
    + rm -fv test-suite-19.1.0.src/CTMark/lencod
    removed 'test-suite-19.1.0.src/CTMark/lencod'
    ++ dirname test-suite-19.1.0.src/CTMark/lencod
    + basedir=test-suite-19.1.0.src/CTMark
    ++ basename test-suite-19.1.0.src/CTMark/lencod
    + dir=lencod
    + cmake_file=test-suite-19.1.0.src/CTMark/CMakeLists.txt
    + test -f test-suite-19.1.0.src/CTMark/CMakeLists.txt
    + sed -i 's/add_subdirectory(lencod)//g' test-suite-19.1.0.src/CTMark/CMakeLists.txt
    ```



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-6d9aba8c3c");
  script_set_attribute(attribute:"solution", value:
"Update the affected llvm-test-suite package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:llvm-test-suite");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^41([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 41', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'llvm-test-suite-19.1.0-4.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'llvm-test-suite');
}
