#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188700);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2023-24593",
    "CVE-2023-25180",
    "CVE-2023-29499",
    "CVE-2023-32611",
    "CVE-2023-32636",
    "CVE-2023-32643",
    "CVE-2023-32665"
  );

  script_name(english:"EulerOS Virtualization 2.9.0 : glib2 (EulerOS-SA-2023-2982)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glib2 package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - Rejected reason: Rejected by upstream. (CVE-2023-24593, CVE-2023-25180)

  - A flaw was found in GLib. GVariant deserialization fails to validate that the input conforms to the
    expected format, leading to denial of service. (CVE-2023-29499)

  - A flaw was found in GLib. GVariant deserialization is vulnerable to a slowdown issue where a crafted
    GVariant can cause excessive processing, leading to denial of service. (CVE-2023-32611)

  - A flaw was found in glib, where the gvariant deserialization code is vulnerable to a denial of service
    introduced by additional input validation added to resolve CVE-2023-29499. The offset table validation may
    be very slow. This bug does not affect any released version of glib but does affect glib distributors who
    followed the guidance of glib developers to backport the initial fix for CVE-2023-29499. (CVE-2023-32636)

  - A flaw was found in GLib. The GVariant deserialization code is vulnerable to a heap buffer overflow
    introduced by the fix for CVE-2023-32665. This bug does not affect any released version of GLib, but does
    affect GLib distributors who followed the guidance of GLib developers to backport the initial fix for
    CVE-2023-32665. (CVE-2023-32643)

  - A flaw was found in GLib. GVariant deserialization is vulnerable to an exponential blowup issue where a
    crafted GVariant can cause excessive processing, leading to denial of service. (CVE-2023-32665)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2982
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cf66c77");
  script_set_attribute(attribute:"solution", value:
"Update the affected glib2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glib2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "glib2-2.62.5-3.h13.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glib2");
}
