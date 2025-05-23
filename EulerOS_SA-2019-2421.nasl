#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131913);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/04");

  script_cve_id(
    "CVE-2017-10971",
    "CVE-2017-10972",
    "CVE-2017-12176",
    "CVE-2017-12177",
    "CVE-2017-12178",
    "CVE-2017-12179",
    "CVE-2017-12180",
    "CVE-2017-12181",
    "CVE-2017-12182",
    "CVE-2017-12183",
    "CVE-2017-12184",
    "CVE-2017-12185",
    "CVE-2017-12186",
    "CVE-2017-12187",
    "CVE-2017-13721",
    "CVE-2017-2624",
    "CVE-2018-14665"
  );

  script_name(english:"EulerOS 2.0 SP2 : xorg-x11-server (EulerOS-SA-2019-2421)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the xorg-x11-server packages installed,
the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - xorg-x11-server before 1.19.5 was vulnerable to integer
    overflow in ProcDbeGetVisualInfo function allowing
    malicious X client to cause X server to crash or
    possibly execute arbitrary code.(CVE-2017-12177)

  - xorg-x11-server before 1.19.5 had wrong extra length
    check in ProcXIChangeHierarchy function allowing
    malicious X client to cause X server to crash or
    possibly execute arbitrary code.(CVE-2017-12178)

  - xorg-x11-server before 1.19.5 was vulnerable to integer
    overflow in (S)ProcXIBarrierReleasePointer functions
    allowing malicious X client to cause X server to crash
    or possibly execute arbitrary code.(CVE-2017-12179)

  - xorg-x11-server before 1.19.5 was missing length
    validation in XFree86 VidModeExtension allowing
    malicious X client to cause X server to crash or
    possibly execute arbitrary code.(CVE-2017-12180)

  - xorg-x11-server before 1.19.5 was missing length
    validation in XFree86 DGA extension allowing malicious
    X client to cause X server to crash or possibly execute
    arbitrary code.(CVE-2017-12181)

  - xorg-x11-server before 1.19.5 was missing length
    validation in XFree86 DRI extension allowing malicious
    X client to cause X server to crash or possibly execute
    arbitrary code.(CVE-2017-12182)

  - xorg-x11-server before 1.19.5 was missing length
    validation in XFIXES extension allowing malicious X
    client to cause X server to crash or possibly execute
    arbitrary code.(CVE-2017-12183)

  - xorg-x11-server before 1.19.5 was missing length
    validation in XINERAMA extension allowing malicious X
    client to cause X server to crash or possibly execute
    arbitrary code.(CVE-2017-12184)

  - xorg-x11-server before 1.19.5 was missing length
    validation in MIT-SCREEN-SAVER extension allowing
    malicious X client to cause X server to crash or
    possibly execute arbitrary code.(CVE-2017-12185)

  - xorg-x11-server before 1.19.5 was missing length
    validation in X-Resource extension allowing malicious X
    client to cause X server to crash or possibly execute
    arbitrary code.(CVE-2017-12186)

  - xorg-x11-server before 1.19.5 was missing length
    validation in RENDER extension allowing malicious X
    client to cause X server to crash or possibly execute
    arbitrary code.(CVE-2017-12187)

  - In X.Org Server (aka xserver and xorg-server) before
    1.19.4, an attacker authenticated to an X server with
    the X shared memory extension enabled can cause aborts
    of the X server or replace shared memory segments of
    other X clients in the same session.(CVE-2017-13721)

  - It was found that xorg-x11-server before 1.19.0
    including uses memcmp() to check the received MIT
    cookie against a series of valid cookies. If the cookie
    is correct, it is allowed to attach to the Xorg
    session. Since most memcmp() implementations return
    after an invalid byte is seen, this causes a time
    difference between a valid and invalid byte, which
    could allow an efficient brute force
    attack.(CVE-2017-2624)

  - A flaw was found in xorg-x11-server before 1.20.3. An
    incorrect permission check for -modulepath and -logfile
    options when starting Xorg. X server allows
    unprivileged users with the ability to log in to the
    system via physical console to escalate their
    privileges and run arbitrary code under root
    privileges.(CVE-2018-14665)

  - In the X.Org X server before 2017-06-19, a user
    authenticated to an X Session could crash or execute
    code in the context of the X Server by exploiting a
    stack overflow in the endianness conversion of X
    Events.(CVE-2017-10971)

  - Uninitialized data in endianness conversion in the
    XEvent handling of the X.Org X Server before 2017-06-19
    allowed authenticated malicious users to access
    potentially privileged data from the X
    server.(CVE-2017-10972)

  - xorg-x11-server before 1.19.5 was missing extra length
    validation in ProcEstablishConnection function allowing
    malicious X client to cause X server to crash or
    possibly execute arbitrary code.(CVE-2017-12176)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2421
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?611daaca");
  script_set_attribute(attribute:"solution", value:
"Update the affected xorg-x11-server packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12187");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Xorg X11 Server SUID modulepath Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["xorg-x11-server-Xephyr-1.17.2-10.h3",
        "xorg-x11-server-Xorg-1.17.2-10.h3",
        "xorg-x11-server-common-1.17.2-10.h3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server");
}
