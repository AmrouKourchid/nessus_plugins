#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212608);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/18");

  script_cve_id("CVE-2024-8508", "CVE-2024-33655", "CVE-2024-43168");

  script_name(english:"EulerOS 2.0 SP11 : vim (EulerOS-SA-2024-2974)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the vim packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

    The UNIX editor Vim prior to version 9.1.0678 has a use-after-free error in argument list handling. When
    adding a new file to the argument list, this triggers `Buf*` autocommands. If in such an autocommand the
    buffer that was just opened is closed (including the window where it is shown), this causes the window
    structure to be freed which contains a reference to the argument list that we are actually modifying. Once
    the autocommands are completed, the references to the window and argument list are no longer valid and as
    such cause an use-after-free. Impact is low since the user must either intentionally add some unusual
    autocommands that wipe a buffer during creation (either manually or by sourcing a malicious plugin), but
    it will crash Vim. The issue has been fixed as of Vim patch v9.1.0678.(CVE-2024-43374)

    Vim is an improved version of the unix vi text editor. When flushing the typeahead buffer, Vim moves the
    current position in the typeahead buffer but does not check whether there is enough space left in the
    buffer to handle the next characters.  So this may lead to the tb_off position within the typebuf variable
    to point outside of the valid buffer size, which can then later lead to a heap-buffer overflow in e.g.
    ins_typebuf(). Therefore, when flushing the typeahead buffer, check if there is enough space left before
    advancing the off position. If not, fall back to flush current typebuf contents. It's not quite clear yet,
    what can lead to this situation. It seems to happen when error messages occur (which will cause Vim to
    flush the typeahead buffer) in comnination with several long mappgins and so it may eventually move the
    off position out of a valid buffer size. Impact is low since it is not easily reproducible and requires to
    have several mappings active and run into some error condition. But when this happens, this will cause a
    crash. The issue has been fixed as of Vim patch v9.1.0697. Users are advised to upgrade. There are no
    known workarounds for this issue.(CVE-2024-43802)

    Vim is an open source, command line text editor. A use-after-free was found in Vim  9.1.0764. When
    closing a buffer (visible in a window) a BufWinLeave auto command can cause an use-after-free if this auto
    command happens to re-open the same buffer in a new split window. Impact is low since the user must have
    intentionally set up such a strange auto command and run some buffer unload commands. However this may
    lead to a crash. This issue has been addressed in version 9.1.0764 and all users are advised to upgrade.
    There are no known workarounds for this vulnerability.(CVE-2024-47814)

Tenable has extracted the preceding description block directly from the EulerOS vim security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2974
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?faaac88d");
  script_set_attribute(attribute:"solution", value:
"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "vim-common-9.0-1.h29.eulerosv2r11",
  "vim-enhanced-9.0-1.h29.eulerosv2r11",
  "vim-filesystem-9.0-1.h29.eulerosv2r11",
  "vim-minimal-9.0-1.h29.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
