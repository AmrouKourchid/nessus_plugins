#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235393);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id("CVE-2025-22134", "CVE-2025-24014");

  script_name(english:"EulerOS 2.0 SP12 : vim (EulerOS-SA-2025-1441)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the vim packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

    When switching to other buffers using the :all command and visual mode still being active, this may cause
    a heap-buffer overflow, because Vim does not properly end visual mode and therefore may try to access
    beyond the end of a line in a buffer. In Patch 9.1.1003 Vim will correctly reset the visual mode before
    opening other windows and buffers and therefore fix this bug. In addition it does verify that it won't try
    to access a position if the position is greater than the corresponding buffer line. Impact is medium since
    the user must have switched on visual mode when executing the :all ex command. The Vim project would like
    to thank github user gandalf4a for reporting this issue. (CVE-2025-22134)

    Vim is an open source, command line text editor. A segmentation fault was found in Vim before 9.1.1043. In
    silent Ex mode (-s -e), Vim typically doesn't show a screen and just operates silently in batch mode.
    However, it is still possible to trigger the function that handles the scrolling of a gui version of Vim
    by feeding some binary characters to Vim. The function that handles the scrolling however may be
    triggering a redraw, which will access the ScreenLines pointer, even so this variable hasn't been
    allocated (since there is no screen). (CVE-2025-24014)

Tenable has extracted the preceding description block directly from the EulerOS vim security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2025-1441
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?357a5326");
  script_set_attribute(attribute:"solution", value:
"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(12)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP12", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "vim-common-9.0-5.h19.eulerosv2r12",
  "vim-enhanced-9.0-5.h19.eulerosv2r12",
  "vim-filesystem-9.0-5.h19.eulerosv2r12",
  "vim-minimal-9.0-5.h19.eulerosv2r12"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"12", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim");
}
