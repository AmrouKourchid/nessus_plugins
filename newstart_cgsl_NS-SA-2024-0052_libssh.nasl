#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0052. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206832);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2014-0017",
    "CVE-2018-10933",
    "CVE-2019-14889",
    "CVE-2020-1730",
    "CVE-2020-16135",
    "CVE-2021-3634"
  );
  script_xref(name:"IAVA", value:"2018-A-0347-S");
  script_xref(name:"IAVA", value:"2020-A-0203");
  script_xref(name:"IAVA", value:"2022-A-0041-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : libssh Multiple Vulnerabilities (NS-SA-2024-0052)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has libssh packages installed that are affected by multiple
vulnerabilities:

  - The RAND_bytes function in libssh before 0.6.3, when forking is enabled, does not properly reset the state
    of the OpenSSL pseudo-random number generator (PRNG), which causes the state to be shared between children
    processes and allows local users to obtain sensitive information by leveraging a pid collision.
    (CVE-2014-0017)

  - A vulnerability was found in libssh's server-side state machine. A malicious client could create channels
    without first performing authentication, resulting in unauthorized access. (CVE-2018-10933)

  - A flaw was found with the libssh API function ssh_scp_new(). A user able to connect to a server using SCP
    could execute arbitrary command using a user-provided path, leading to a compromise of the remote target.
    (CVE-2019-14889)

  - A flaw was found in libssh. A NULL pointer dereference in tftpserver.c if ssh_buffer_new returns NULL.
    (CVE-2020-16135)

  - A flaw was found in the way libssh handled AES-CTR (or DES ciphers if enabled) ciphers. The server or
    client could crash when the connection hasn't been fully initialized and the system tries to cleanup the
    ciphers when closing the connection. The biggest threat from this vulnerability is system availability.
    (CVE-2020-1730)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0052");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2014-0017");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2018-10933");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2019-14889");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-16135");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-1730");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3634");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libssh packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14889");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-10933");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libssh-config");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'libssh-0.9.6-6.el8.cgslv6_2.2.ga9c3cbc',
    'libssh-config-0.9.6-6.el8.cgslv6_2.2.ga9c3cbc'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libssh');
}
