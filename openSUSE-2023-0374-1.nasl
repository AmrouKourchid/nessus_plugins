#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0374-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(185986);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/19");

  script_cve_id("CVE-2023-35934", "CVE-2023-46121");

  script_name(english:"openSUSE 15 Security Update : yt-dlp (openSUSE-SU-2023:0374-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0374-1 advisory.

  - yt-dlp is a command-line program to download videos from video sites. During file downloads, yt-dlp or the
    external downloaders that yt-dlp employs may leak cookies on HTTP redirects to a different host, or leak
    them when the host for download fragments differs from their parent manifest's host. This vulnerable
    behavior is present in yt-dlp prior to 2023.07.06 and nightly 2023.07.06.185519. All native and external
    downloaders are affected, except for `curl` and `httpie` (version 3.1.0 or later). At the file download
    stage, all cookies are passed by yt-dlp to the file downloader as a `Cookie` header, thereby losing their
    scope. This also occurs in yt-dlp's info JSON output, which may be used by external tools. As a result,
    the downloader or external tool may indiscriminately send cookies with requests to domains or paths for
    which the cookies are not scoped. yt-dlp version 2023.07.06 and nightly 2023.07.06.185519 fix this issue
    by removing the `Cookie` header upon HTTP redirects; having native downloaders calculate the `Cookie`
    header from the cookiejar, utilizing external downloaders' built-in support for cookies instead of passing
    them as header arguments, disabling HTTP redirectiong if the external downloader does not have proper
    cookie support, processing cookies passed as HTTP headers to limit their scope, and having a separate
    field for cookies in the info dict storing more information about scoping Some workarounds are available
    for those who are unable to upgrade. Avoid using cookies and user authentication methods. While extractors
    may set custom cookies, these usually do not contain sensitive information. Alternatively, avoid using
    `--load-info-json`. Or, if authentication is a must: verify the integrity of download links from unknown
    sources in browser (including redirects) before passing them to yt-dlp; use `curl` as external downloader,
    since it is not impacted; and/or avoid fragmented formats such as HLS/m3u8, DASH/mpd and ISM.
    (CVE-2023-35934)

  - yt-dlp is a youtube-dl fork with additional features and fixes. The Generic Extractor in yt-dlp is
    vulnerable to an attacker setting an arbitrary proxy for a request to an arbitrary url, allowing the
    attacker to MITM the request made from yt-dlp's HTTP session. This could lead to cookie exfiltration in
    some cases. Version 2023.11.14 removed the ability to smuggle `http_headers` to the Generic extractor, as
    well as other extractors that use the same pattern. Users are advised to upgrade. Users unable to upgrade
    should disable the Ggneric extractor (or only pass trusted sites with trusted content) and ake caution
    when using `--no-check-certificate`. (CVE-2023-46121)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216467");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6MA5EHVFVH4HRBQQ5KZZ4YVOXJFQUG3W/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a80df22");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46121");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python311-yt-dlp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yt-dlp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yt-dlp-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yt-dlp-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:yt-dlp-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'python311-yt-dlp-2023.11.14-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yt-dlp-2023.11.14-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yt-dlp-bash-completion-2023.11.14-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yt-dlp-fish-completion-2023.11.14-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'yt-dlp-zsh-completion-2023.11.14-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python311-yt-dlp / yt-dlp / yt-dlp-bash-completion / etc');
}
