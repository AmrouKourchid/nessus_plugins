#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197220);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id(
    "CVE-2023-2609",
    "CVE-2023-4735",
    "CVE-2023-4751",
    "CVE-2023-5344",
    "CVE-2023-46246",
    "CVE-2023-48233",
    "CVE-2023-48234",
    "CVE-2023-48236",
    "CVE-2023-48237"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : vim (EulerOS-SA-2024-1708)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the vim packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.1531. (CVE-2023-2609)

  - Vim is an improved version of the good old UNIX editor Vi. Heap-use-after-free in memory allocated in the
    function `ga_grow_inner` in in the file `src/alloc.c` at line 748, which is freed in the file
    `src/ex_docmd.c` in the function `do_cmdline` at line 1010 and then used again in `src/cmdhist.c` at line
    759. When using the `:history` command, it's possible that the provided argument overflows the accepted
    value. Causing an Integer Overflow and potentially later an use-after-free. This vulnerability has been
    patched in version 9.0.2068. (CVE-2023-46246)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1847. (CVE-2023-4735)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1331. (CVE-2023-4751)

  - Vim is an open source command line text editor. If the count after the :s command is larger than what fits
    into a (signed) long variable, abort with e_value_too_large. Impact is low, user interaction is required
    and a crash may not even happen in all situations. This issue has been addressed in commit `ac6378773`
    which has been included in release version 9.0.2108. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-48233)

  - Vim is an open source command line text editor. When getting the count for a normal mode z command, it may
    overflow for large counts given. Impact is low, user interaction is required and a crash may not even
    happen in all situations. This issue has been addressed in commit `58f9befca1` which has been included in
    release version 9.0.2109. Users are advised to upgrade. There are no known workarounds for this
    vulnerability. (CVE-2023-48234)

  - Vim is an open source command line text editor. When using the z= command, the user may overflow the count
    with values larger than MAX_INT. Impact is low, user interaction is required and a crash may not even
    happen in all situations. This vulnerability has been addressed in commit `73b2d379` which has been
    included in release version 9.0.2111. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2023-48236)

  - Vim is an open source command line text editor. In affected versions when shifting lines in operator
    pending mode and using a very large value, it may be possible to overflow the size of integer. Impact is
    low, user interaction is required and a crash may not even happen in all situations. This issue has been
    addressed in commit `6bf131888` which has been included in version 9.0.2112. Users are advised to upgrade.
    There are no known workarounds for this vulnerability. (CVE-2023-48237)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1969. (CVE-2023-5344)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1708
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1dddbaa5");
  script_set_attribute(attribute:"solution", value:
"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4751");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "vim-X11-8.1.450-1.h56.eulerosv2r8",
  "vim-common-8.1.450-1.h56.eulerosv2r8",
  "vim-enhanced-8.1.450-1.h56.eulerosv2r8",
  "vim-filesystem-8.1.450-1.h56.eulerosv2r8",
  "vim-minimal-8.1.450-1.h56.eulerosv2r8"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim");
}
