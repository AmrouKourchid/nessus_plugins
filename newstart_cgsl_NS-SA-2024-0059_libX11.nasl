#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0059. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206845);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id("CVE-2021-31535", "CVE-2023-3138");

  script_name(english:"NewStart CGSL MAIN 6.02 : libX11 Multiple Vulnerabilities (NS-SA-2024-0059)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has libX11 packages installed that are affected by multiple
vulnerabilities:

  - A missing validation flaw was found in libX11. This flaw allows an attacker to inject X11 protocol
    commands on X clients, and in some cases, also bypass, authenticate (via injection of control characters),
    or potentially execute arbitrary code with permissions of the application compiled with libX11. The
    highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.
    (CVE-2021-31535)

  - A vulnerability was found in libX11. The security flaw occurs because the functions in src/InitExt.c in
    libX11 do not check that the values provided for the Request, Event, or Error IDs are within the bounds of
    the arrays that those functions write to, using those IDs as array indexes. They trust that they were
    called with values provided by an Xserver adhering to the bounds specified in the X11 protocol, as all X
    servers provided by X.Org do. As the protocol only specifies a single byte for these values, an out-of-
    bounds value provided by a malicious server (or a malicious proxy-in-the-middle) can only overwrite other
    portions of the Display structure and not write outside the bounds of the Display structure itself,
    possibly causing the client to crash with this memory corruption. (CVE-2023-3138)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0059");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-31535");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3138");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libX11 packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31535");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libX11-xcb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'libX11-1.6.8-5.el8.cgslv6_2.1.g20b80b6',
    'libX11-common-1.6.8-5.el8.cgslv6_2.1.g20b80b6',
    'libX11-devel-1.6.8-5.el8.cgslv6_2.1.g20b80b6',
    'libX11-xcb-1.6.8-5.el8.cgslv6_2.1.g20b80b6'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libX11');
}
