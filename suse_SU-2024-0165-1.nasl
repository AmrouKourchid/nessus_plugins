#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0165-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(189257);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/29");

  script_cve_id(
    "CVE-2023-6816",
    "CVE-2024-0229",
    "CVE-2024-0408",
    "CVE-2024-0409",
    "CVE-2024-21885",
    "CVE-2024-21886"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0165-1");

  script_name(english:"SUSE SLED15 Security Update : xwayland (SUSE-SU-2024:0165-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:0165-1 advisory.

  - A flaw was found in X.Org server. Both DeviceFocusEvent and the XIQueryPointer reply contain a bit for
    each logical button currently down. Buttons can be arbitrarily mapped to any value up to 255, but the
    X.Org Server was only allocating space for the device's particular number of buttons, leading to a heap
    overflow if a bigger value was used. (CVE-2023-6816)

  - The X.Org project reports: Both DeviceFocusEvent and the XIQueryPointer reply contain a bit
    for each logical button currently down. Buttons can be arbitrarily             mapped to any value up to
    255 but the X.Org Server was only             allocating space for the device's number of buttons,
    leading to a heap overflow if a bigger value was used. If a device has both a button class and a key class
    and             numButtons is zero, we can get an out-of-bounds write due             to event under-
    allocation in the DeliverStateNotifyEvent             function. The XISendDeviceHierarchyEvent() function
    allocates space to             store up to MAXDEVICES (256) xXIHierarchyInfo structures in info.
    If a device with a given ID was removed and a new device with             the same ID added both in the
    same operation,             the single device ID will lead to two info structures being
    written to info.             Since this case can occur for every device ID at once,             a total of
    two times MAXDEVICES info structures might be written             to the allocation, leading to a heap
    buffer overflow. The DisableDevice() function is called whenever an enabled device             is disabled
    and it moves the device from the inputInfo.devices             linked list to the inputInfo.off_devices
    linked list.             However, its link/unlink operation has an issue during the recursive
    call to DisableDevice() due to the prev pointer pointing to a             removed device.             This
    issue leads to a length mismatch between the total number of             devices and the number of device
    in the list, leading to a heap             overflow and, possibly, to local privilege escalation.
    (CVE-2024-0229, CVE-2024-21885, CVE-2024-21886)

  - A flaw was found in the X.Org server. The GLX PBuffer code does not call the XACE hook when creating the
    buffer, leaving it unlabeled. When the client issues another request to access that resource (as with a
    GetGeometry) or when it creates another resource that needs to access that buffer, such as a GC, the
    XSELINUX code will try to use an object that was never labeled and crash because the SID is NULL.
    (CVE-2024-0408)

  - A flaw was found in the X.Org server. The cursor code in both Xephyr and Xwayland uses the wrong type of
    private at creation. It uses the cursor bits type with the cursor as private, and when initiating the
    cursor, that overwrites the XSELINUX context. (CVE-2024-0409)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218846");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-January/017712.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d829f57e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0408");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0409");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21886");
  script_set_attribute(attribute:"solution", value:
"Update the affected xwayland package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xwayland");
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
if (! preg(pattern:"^(SLED15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'xwayland-21.1.4-150400.3.31.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sled-release-15.4']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xwayland');
}
