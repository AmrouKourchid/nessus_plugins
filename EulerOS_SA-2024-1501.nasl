#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192995);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/08");

  script_cve_id(
    "CVE-2023-6816",
    "CVE-2024-0229",
    "CVE-2024-0408",
    "CVE-2024-0409",
    "CVE-2024-21885",
    "CVE-2024-21886"
  );

  script_name(english:"EulerOS 2.0 SP9 : xorg-x11-server (EulerOS-SA-2024-1501)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the xorg-x11-server package installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in X.Org server. Both DeviceFocusEvent and the XIQueryPointer reply contain a bit for
    each logical button currently down. Buttons can be arbitrarily mapped to any value up to 255, but the
    X.Org Server was only allocating space for the device's particular number of buttons, leading to a heap
    overflow if a bigger value was used. (CVE-2023-6816)

  - An out-of-bounds memory access flaw was found in the X.Org server. This issue can be triggered when a
    device frozen by a sync grab is reattached to a different master device. This issue may lead to an
    application crash, local privilege escalation (if the server runs with extended privileges), or remote
    code execution in SSH X11 forwarding environments. (CVE-2024-0229)

  - A flaw was found in the X.Org server. The GLX PBuffer code does not call the XACE hook when creating the
    buffer, leaving it unlabeled. When the client issues another request to access that resource (as with a
    GetGeometry) or when it creates another resource that needs to access that buffer, such as a GC, the
    XSELINUX code will try to use an object that was never labeled and crash because the SID is NULL.
    (CVE-2024-0408)

  - A flaw was found in the X.Org server. The cursor code in both Xephyr and Xwayland uses the wrong type of
    private at creation. It uses the cursor bits type with the cursor as private, and when initiating the
    cursor, that overwrites the XSELINUX context. (CVE-2024-0409)

  - A flaw was found in X.Org server. In the XISendDeviceHierarchyEvent function, it is possible to exceed the
    allocated array length when certain new device IDs are added to the xXIHierarchyInfo struct. This can
    trigger a heap buffer overflow condition, which may lead to an application crash or remote code execution
    in SSH X11 forwarding environments. (CVE-2024-21885)

  - A heap buffer overflow flaw was found in the DisableDevice function in the X.Org server. This issue may
    lead to an application crash or, in some circumstances, remote code execution in SSH X11 forwarding
    environments. (CVE-2024-21886)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1501
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a0977f9");
  script_set_attribute(attribute:"solution", value:
"Update the affected xorg-x11-server packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6816");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-help");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "xorg-x11-server-help-1.20.6-5.h12.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server");
}
