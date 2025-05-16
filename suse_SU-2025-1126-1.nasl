#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1126-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(233841);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2024-56337", "CVE-2025-24813");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/22");
  script_xref(name:"IAVA", value:"2024-A-0822-S");
  script_xref(name:"IAVA", value:"2025-A-0156");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1126-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : tomcat (SUSE-SU-2025:1126-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2025:1126-1 advisory.

    - CVE-2025-24813: Fixed potential RCE and/or information disclosure/corruption with partial PUT
    (bsc#1239302)

    - Update to Tomcat 9.0.102
      * Fixes:
        - launch with java 17 (bsc#1239676)
      * Catalina
        - Fix: Weak etags in the If-Range header should not match as strong etags
          are required. (remm)
        - Fix: When looking up class loader resources by resource name, the resource
          name should not start with '/'. If the resource name does start with '/',
          Tomcat is lenient and looks it up as if the '/' was not present. When the
          web application class loader was configured with external repositories and
          names starting with '/' were used for lookups, it was possible that cached
          'not found' results could effectively hide lookup results using the
          correct resource name. (markt)
        - Fix: Enable the JNDIRealm to validate credentials provided to
          HttpServletRequest.login(String username, String password) when the realm
          is configured to use GSSAPI authentication. (markt)
        - Fix: Fix a bug in the JRE compatibility detection that incorrectly
          identified Java 19 and Java 20 as supporting Java 21 features. (markt)
        - Fix: Improve the checks for exposure to and protection against
          CVE-2024-56337 so that reflection is not used unless required. The checks
          for whether the file system is case sensitive or not have been removed.
          (markt)
        - Fix: Avoid scenarios where temporary files used for partial PUT would not
          be deleted. (remm)
        - Fix: 69602: Fix regression in releases from 12-2024 that were too strict
          and rejected weak etags in the If-Range header. (remm)
        - Fix: 69576: Avoid possible failure initializing JreCompat due to uncaught
          exception introduced for the check for CVE-2024-56337. (remm)
      * Cluster
        - Add: 69598: Add detection of service account token changes to the
          KubernetesMembershipProvider implementation and reload the token if it
          changes. Based on a patch by Miroslav Jezbera. (markt)
      * Coyote
        - Fix: 69575: Avoid using compression if a response is already compressed
          using compress, deflate or zstd. (remm)
        - Update: Use Transfer-Encoding for compression rather than Content-Encoding
          if the client submits a TE header containing gzip. (remm)
        - Fix: Fix a race condition in the handling of HTTP/2 stream reset that
          could cause unexpected 500 responses. (markt)
      * Other
        - Add: Add makensis as an option for building the Installer for Windows on
          non-Windows platforms. (rjung/markt)
        - Update: Update Byte Buddy to 1.17.1. (markt)
        - Update: Update Checkstyle to 10.21.3. (markt)
        - Update: Update SpotBugs to 4.9.1. (markt)
        - Update: Update JSign to 7.1. (markt)
        - Add: Improvements to French translations. (remm)
        - Add: Improvements to Japanese translations by tak7iji. (markt)
        - Add: Add org.apache.juli.JsonFormatter to format log as one line JSON
          documents. (remm)

    - Update to Tomcat 9.0.99
      * Catalina
        - Update: Add tableName configuration on the DataSourcePropertyStore that
          may be used by the WebDAV Servlet. (remm)
        - Update: Improve HTTP If headers processing according to RFC 9110. Based on
          pull request #796 by Chenjp. (remm/markt)
        - Update: Allow readOnly attribute configuration on the Resources element
          and allow configure the readOnly attribute value of the main resources.
          The attribute value will also be used by the default and WebDAV Servlets.
          (remm)
        + Fix: 69285: Optimise the creation of the parameter map for included
          requests. Based on sample code and test cases provided by John
          Engebretson. (markt)
        + Fix: 69527: Avoid rare cases where a cached resource could be set with 0
          content length, or could be evicted immediately. (remm)
        + Fix: Fix possible edge cases (such as HTTP/1.0) with trying to detect
          requests without body for WebDAV LOCK and PROPFIND. (remm)
        + Fix: 69528: Add multi-release JAR support for the bloom
          archiveIndexStrategy of the Resources. (remm)
        + Fix: Improve checks for WEB-INF and META-INF in the WebDAV servlet. Based
          on a patch submitted by Chenjp. (remm)
        + Add: Add a check to ensure that, if one or more web applications are
          potentially vulnerable to CVE-2024-56337, the JVM has been configured to
          protect against the vulnerability and to configure the JVM correctly if
          not. Where one or more web applications are potentially vulnerable to
          CVE-2024-56337 and the JVM cannot be correctly configured or it cannot be
          confirmed that the JVM has been correctly configured, prevent the impacted
          web applications from starting. (markt)
        + Fix: Remove unused session to client map from CrawlerSessionManagerValve.
          Submitted by Brian Matzon. (remm)
        + Fix: When using the WebDAV servlet with serveSubpathOnly set to true,
          ensure that the destination for any requested WebDAV operation is also
          restricted to the sub-path. (markt)
        + Fix: Generate an appropriate Allow HTTP header when the Default servlet
          returns a 405 (method not allowed) response in response to a DELETE
          request because the target resource cannot be deleted. Pull request #802
          provided by Chenjp. (markt)
        + Code: Refactor creation of RequestDispatcher instances so that the
          processing of the provided path is consistent with normal request
          processing. (markt)
        + Add: Add encodedReverseSolidusHandling and encodedSolidusHandling
          attributes to Context to provide control over the handling of the path
          used to created a RequestDispatcher. (markt)
        + Fix: Handle a potential NullPointerException after an IOException occurs
          on a non-container thread during asynchronous processing. (markt)
        + Fix: Enhance lifecycle of temporary files used by partial PUT. (remm)
      * Coyote
        + Fix: Don't log warnings for registered HTTP/2 settings that Tomcat does
          not support. These settings are now silently ignored. (markt)
        + Fix: Avoid a rare NullPointerException when recycling the
          Http11InputBuffer. (markt)
        + Fix: Lower the log level to debug for logging an invalid socket channel
          when processing poller events for the NIO Connector as this may occur in
          normal usage. (markt)
        + Code: Clean-up references to the HTTP/2 stream once request processing has
          completed to aid GC and reduce the size of the HTTP/2 recycled request and
          response cache. (markt)
        + Add: Add a new Connector configuration attribute,
          encodedReverseSolidusHandling, to control how %5c sequences in URLs are
          handled. The default behaviour is unchanged (decode) keeping in mind that
          the allowBackslash attribute determines how the decoded URI is processed.
          (markt)
        + Fix: 69545: Improve CRLF skipping for the available method of the
          ChunkedInputFilter. (remm)
        + Fix: Improve the performance of repeated calls to getHeader(). Pull
          request #813 provided by Adwait Kumar Singh. (markt)
        + Fix: 69559: Ensure that the Java 24 warning regarding the use of
          sun.misc.Unsafe::invokeCleaner is only reported by the JRE when the code
          will be used. (markt)
      * Jasper
        + Fix: 69508: Correct a regression in the fix for 69382 that broke JSP
          include actions if both the page attribute and the body contained
          parameters. Pull request #803 provided by Chenjp. (markt)
        + Fix: 69521: Update the EL Parser to allow the full range of valid
          characters in an EL identifier as defined by the Java Language
          Specification. (markt)
        + Fix: 69532: Optimise the creation of ExpressionFactory instances. Patch
          provided by John Engebretson. (markt)
      * Web applications
        + Add: Documentation. Expand the description of the security implications of
          setting mapperContextRootRedirectEnabled and/or
          mapperDirectoryRedirectEnabled to true. (markt)
        + Fix: Documentation. Better document the default for the truststoreProvider
          attribute of a SSLHostConfig element. (markt)
      * Other
        + Update: Update to Commons Daemon 1.4.1. (markt)
        + Update: Update the internal fork of Commons Pool to 2.12.1. (markt)
        + Update: Update Byte Buddy to 1.16.1. (markt)
        + Update: Update UnboundID to 7.0.2. (markt)
        + Update: Update Checkstyle to 10.21.2. (markt)
        + Update: Update SpotBugs to 4.9.0. (markt)
        + Add: Improvements to French translations. (remm)
        + Add: Improvements to Chinese translations by leeyazhou. (markt)
        + Add: Improvements to Japanese translations by tak7iji. (markt)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239676");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038899.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56337");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24813");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-el-3_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-jsp-2_3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-servlet-4_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4/5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3/4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-admin-webapps-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-docs-webapp-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-el-3_0-api-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-embed-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-javadoc-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-jsp-2_3-api-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-jsvc-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-lib-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-servlet-4_0-api-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat-webapps-9.0.102-150200.78.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc');
}
