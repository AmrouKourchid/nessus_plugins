#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4469-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(185941);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/09");

  script_cve_id(
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39320",
    "CVE-2023-39321",
    "CVE-2023-39322",
    "CVE-2023-39323",
    "CVE-2023-39325",
    "CVE-2023-44487",
    "CVE-2023-45283",
    "CVE-2023-45284"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4469-1");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : go1.21-openssl (SUSE-SU-2023:4469-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2023:4469-1 advisory.

  - The html/template package does not properly handle HTML-like  comment tokens, nor hashbang #! comment
    tokens, in <script> contexts. This may cause the template parser to improperly interpret the contents of
    <script> contexts, causing actions to be improperly escaped. This may be leveraged to perform an XSS
    attack. (CVE-2023-39318)

  - The html/template package does not apply the proper rules for handling occurrences of <script, <!--,
    and </script within JS literals in <script> contexts. This may cause the template parser to improperly
    consider script contexts to be terminated early, causing actions to be improperly escaped. This could be
    leveraged to perform an XSS attack. (CVE-2023-39319)

  - The go.mod toolchain directive, introduced in Go 1.21, can be leveraged to execute scripts and binaries
    relative to the root of the module when the go command was executed within the module. This applies to
    modules downloaded using the go command from the module proxy, as well as modules downloaded directly
    using VCS software. (CVE-2023-39320)

  - Processing an incomplete post-handshake message for a QUIC connection can cause a panic. (CVE-2023-39321)

  - QUIC connections do not set an upper bound on the amount of data buffered when reading post-handshake
    messages, allowing a malicious QUIC connection to cause unbounded memory growth. With fix, connections now
    consistently reject messages larger than 65KiB in size. (CVE-2023-39322)

  - Line directives (//line) can be used to bypass the restrictions on //go:cgo_ directives, allowing
    blocked linker and compiler flags to be passed during compilation. This can result in unexpected execution
    of arbitrary code when running go build. The line directive requires the absolute path of the file in
    which the directive lives, which makes exploiting this issue significantly more complex. (CVE-2023-39323)

  - A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive
    server resource consumption. While the total number of requests is bounded by the
    http2.Server.MaxConcurrentStreams setting, resetting an in-progress request allows the attacker to create
    a new request while the existing one is still executing. With the fix applied, HTTP/2 servers now bound
    the number of simultaneously executing handler goroutines to the stream concurrency limit
    (MaxConcurrentStreams). New requests arriving when at the limit (which can only happen after the client
    has reset an existing, in-flight request) will be queued until a handler exits. If the request queue grows
    too large, the server will terminate the connection. This issue is also fixed in golang.org/x/net/http2
    for users manually configuring HTTP/2. The default stream concurrency limit is 250 streams (requests) per
    HTTP/2 connection. This value may be adjusted using the golang.org/x/net/http2 package; see the
    Server.MaxConcurrentStreams setting and the ConfigureServer function. (CVE-2023-39325)

  - The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation
    can reset many streams quickly, as exploited in the wild in August through October 2023. (CVE-2023-44487)

  - The filepath package does not recognize paths with a \??\ prefix as special. On Windows, a path beginning
    with \??\ is a Root Local Device path equivalent to a path beginning with \\?\. Paths with a \??\ prefix
    may be used to access arbitrary locations on the system. For example, the path \??\c:\x is equivalent to
    the more common path c:\x. Before fix, Clean could convert a rooted path such as \a\..\??\b into the root
    local device path \??\b. Clean will now convert this to .\??\b. Similarly, Join(\, ??, b) could convert a
    seemingly innocent sequence of path elements into the root local device path \??\b. Join will now convert
    this to \.\??\b. In addition, with fix, IsAbs now correctly reports paths beginning with \??\ as absolute,
    and VolumeName correctly reports the \??\ prefix as a volume name. (CVE-2023-45283)

  - On Windows, The IsLocal function does not correctly detect reserved device names in some cases. Reserved
    names followed by spaces, such as COM1 , and reserved names COM and LPT followed by superscript 1,
    2, or 3, are incorrectly reported as local. With fix, IsLocal now correctly reports these names as non-
    local. (CVE-2023-45284)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216944");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-November/017050.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7d18c76");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39325");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-44487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45284");
  script_set_attribute(attribute:"solution", value:
"Update the affected go1.21-openssl, go1.21-openssl-doc and / or go1.21-openssl-race packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39320");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.21-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.21-openssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.21-openssl-race");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'go1.21-openssl-1.21.4.1-150000.1.5.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'go1.21-openssl-doc-1.21.4.1-150000.1.5.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'go1.21-openssl-race-1.21.4.1-150000.1.5.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'go1.21-openssl / go1.21-openssl-doc / go1.21-openssl-race');
}
