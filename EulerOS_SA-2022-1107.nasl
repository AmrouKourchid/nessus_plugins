#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157970);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/09");

  script_cve_id("CVE-2020-13529");

  script_name(english:"EulerOS Virtualization 3.0.6.6 : NetworkManager (EulerOS-SA-2022-1107)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the NetworkManager packages installed, the EulerOS Virtualization installation on the
remote host is affected by the following vulnerabilities :

  - An exploitable denial-of-service vulnerability exists in Systemd 245. A specially crafted DHCP FORCERENEW
    packet can cause a server running the DHCP client to be vulnerable to a DHCP ACK spoofing attack. An
    attacker can forge a pair of FORCERENEW and DCHP ACK packets to reconfigure the server. (CVE-2020-13529)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1107
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ae954ad");
  script_set_attribute(attribute:"solution", value:
"Update the affected NetworkManager packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "NetworkManager-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-adsl-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-bluetooth-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-config-server-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-glib-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-libnm-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-team-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-tui-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-wifi-1.10.2-16.h6.eulerosv2r7",
  "NetworkManager-wwan-1.10.2-16.h6.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager");
}
