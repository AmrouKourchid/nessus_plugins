#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210651);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2024-41957",
    "CVE-2024-41965",
    "CVE-2024-43374",
    "CVE-2024-43802"
  );

  script_name(english:"EulerOS 2.0 SP10 : vim (EulerOS-SA-2024-2918)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the vim packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

    Vim is an open source command line text editor.double-free in dialog_changed() in Vim  v9.1.0648.When
    abandoning a buffer, Vim may ask the user what to do with the modified buffer.If the user wants the
    changed buffer to be saved, Vim may create a new Untitled file, if the buffer did not have a name
    yet.However, when setting the buffer name to Unnamed, Vim will falsely free a pointer twice, leading to a
    double-free and possibly later to a heap-use-after-free, which can lead to a crash.The issue has been
    fixed as of Vim patch v9.1.0648.(CVE-2024-41965)

    Vim is an open source command line text editor.Vim  v9.1.0647 has double free in src/alloc.c:616.When
    closing a window, the corresponding tagstack data will be cleared and freed.However a bit later, the
    quickfix list belonging to that window will also be cleared and if that quickfix list points to the same
    tagstack data, Vim will try to free it again, resulting in a double-free/use-after-free access
    exception.Impact is low since the user must intentionally execute vim with several non-default flags, but
    it may cause a crash of Vim.The issue has been fixed as of Vim patch v9.1.0647(CVE-2024-41957)

    The UNIX editor Vim prior to version 9.1.0678 has a use-after-free error in argument list handling.When
    adding a new file to the argument list, this triggers `Buf*` autocommands.If in such an autocommand the
    buffer that was just opened is closed (including the window where it is shown), this causes the window
    structure to be freed which contains a reference to the argument list that we are actually modifying.Once
    the autocommands are completed, the references to the window and argument list are no longer valid and as
    such cause an use-after-free.Impact is low since the user must either intentionally add some unusual
    autocommands that wipe a buffer during creation (either manually or by sourcing a malicious plugin), but
    it will crash Vim.The issue has been fixed as of Vim patch v9.1.0678.(CVE-2024-43374)

    Vim is an improved version of the unix vi text editor.When flushing the typeahead buffer, Vim moves the
    current position in the typeahead buffer but does not check whether there is enough space left in the
    buffer to handle the next characters. So this may lead to the tb_off position within the typebuf variable
    to point outside of the valid buffer size, which can then later lead to a heap-buffer overflow in
    e.g.ins_typebuf().Therefore, when flushing the typeahead buffer, check if there is enough space left
    before advancing the off position.If not, fall back to flush current typebuf contents.It's not quite clear
    yet, what can lead to this situation.It seems to happen when error messages occur (which will cause Vim to
    flush the typeahead buffer) in comnination with several long mappgins and so it may eventually move the
    off position out of a valid buffer size.Impact is low since it is not easily reproducible and requires to
    have several mappings active and run into some error condition.But when this happens, this will cause a
    crash.The issue has been fixed as of Vim patch v9.1.0697.Users are advised to upgrade.There are no known
    workarounds for this issue.(CVE-2024-43802)

Tenable has extracted the preceding description block directly from the EulerOS vim security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-2918
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fed9529e");
  script_set_attribute(attribute:"solution", value:
"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "vim-common-9.0-1.h22.r1.eulerosv2r10",
  "vim-enhanced-9.0-1.h22.r1.eulerosv2r10",
  "vim-filesystem-9.0-1.h22.r1.eulerosv2r10",
  "vim-minimal-9.0-1.h22.r1.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
