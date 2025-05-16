#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4105-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212695);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2024-52316");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4105-1");
  script_xref(name:"IAVA", value:"2024-A-0754-S");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : tomcat10 (SUSE-SU-2024:4105-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by a vulnerability
as referenced in the SUSE-SU-2024:4105-1 advisory.

    - Update to Tomcat 10.1.33
      * Fixed CVEs:
        - CVE-2024-52316: If the Jakarta Authentication fails with an exception,
          set a 500 status (bsc#1233434)
      * Catalina
        - Add: Add support for the new Servlet API method HttpServletResponse.sendEarlyHints(). (markt)
        - Add: 55470: Add debug logging that reports the class path when a
          ClassNotFoundException occurs in the digester or the web application class loader.
          Based on a patch by Ralf Hauser. (markt)
        - Update: 69374: Properly separate between table header and body in
          DefaultServlet's listing. (michaelo)
        - Update: 69373: Make DefaultServlet's HTML listing file last modified
          rendering better (flexible). (michaelo)
        - Update: Improve HTML output of DefaultServlet. (michaelo)
        - Code: Refactor RateLimitFilter to use FilterBase as the base class.
          The primary advantage is less code to process init-param values. (markt)
        - Update: 69370: DefaultServlet's HTML listing uses incorrect labels.
          (michaelo)
        - Fix: Avoid NPE in CrawlerSessionManagerValve for partially mapped requests. (remm)
        - Fix: Add missing WebDAV Lock-Token header in the response when locking
          a folder. (remm)
        - Fix: Invalid WebDAV lock requests should be rejected with 400. (remm)
        - Fix: Fix regression in WebDAV when attempting to unlock a collection. (remm)
        - Fix: Verify that destination is not locked for a WebDAV copy operation. (remm)
        - Fix: Send 415 response to WebDAV MKCOL operations that include a request
          body since this is optional and unsupported. (remm)
        - Fix: Enforce DAV: namespace on WebDAV XML elements. (remm)
        - Fix: Do not allow a new WebDAV lock on a child resource if a parent
          collection is locked (RFC 4918 section 6.1). (remm)
        - Fix: WebDAV DELETE should remove any existing lock on successfully
          deleted resources. (remm)
        - Update: Remove WebDAV lock null support in accordance with RFC 4918
          section 7.3 and annex D. Instead, a lock on a non-existing resource will
          create an empty file locked with a regular lock. (remm)
        - Update: Rewrite implementation of WebDAV shared locks to comply with
          RFC 4918. (remm)
        - Update: Implement WebDAV If header using code from the Apache Jackrabbit
          project. (remm)
        - Add: Add PropertyStore interface in the WebDAV Servlet, to allow
          implementation of dead properties storage. The store used can be configured
          using the propertyStore init parameter of the WebDAV servlet by specifying
          the class name of the store. A simple non-persistent implementation is
          used if no custom store is configured. (remm)
        - Update: Implement WebDAV PROPPATCH method using the newly added
          PropertyStore, and update PROPFIND to support it. (remm)
        - Fix: Cache not found results when searching for web application class
          loader resources. This addresses performance problems caused by components
          such as java.sql.DriverManager, which in some circumstances will search
          for the same class repeatedly. The size of the cache can be controlled
          via the new notFoundClassResourceCacheSize on the StandardContext. (markt)
        - Fix: Stop after INITIALIZED state should be a noop since it is possible
          for subcomponents to be in FAILED after init. (remm)
        + Fix: Fix incorrect web resource cache size calculations when there are
          concurrent PUT and DELETE requests for the same resource. (markt)
        + Add: Add debug logging for the web resource cache so the current size
          can be tracked as resources are added and removed. (markt)
        + Update: Replace legacy WebDAV opaquelocktoken: scheme for lock tokens
          with urn:uuid: as recommended by RFC 4918, and remove secret init
          parameter. (remm)
        + Fix: Concurrent reads and writes (e.g. GET and PUT / DELETE) for the
          same path caused corruption of the FileResource where some of the fields
          were set as if the file exists and some as set as if it does not. This
          resulted in inconsistent metadata. (markt)
        + Fix: 69415: Ensure that the ExpiresFilter only sets cache headers on
          GET and HEAD requests. Also, skip requests where the application has
          set Cache-Control: no-store. (markt)
        + Fix: 69419: Improve the performance of ServletRequest.getAttribute()
          when there are multiple levels of nested includes. Based on a patch
          provided by John Engebretson. (markt)
        + Add: All applications to send an early hints informational response
          by calling HttpServletResponse.sendError() with a status code of 103.
          (schultz)
        + Fix: Ensure that ServerAuthModule.initialize() is called when a
          Jakarta Authentication module is configured via registerServerAuthModule().
          (markt)
        + Fix: Ensure that the Jakarta Authentication CallbackHandler only creates
          one GenericPrincipal in the Subject. (markt)
        + Fix: If the Jakarta Authentication process fails with an Exception,
          explicitly set the HTTP response status to 500 as the ServerAuthContext
          may not have set it. (markt)
        + Fix: When persisting the Jakarta Authentication provider configuration,
          create any necessary parent directories that don't already exist. (markt)
        + Fix: Correct the logic used to detect errors when deleting temporary files
          associated with persisting the Jakarta Authentication provider
          configuration. (markt)
        + Fix: When processing Jakarta Authentication callbacks, don't overwrite
          a Principal obtained from the PasswordValidationCallback with null if the
          CallerPrincipalCallback does not provide a Principal. (markt)
        + Fix: Avoid store config backup loss when storing one configuration more
          than once per second. (remm)
        + Fix: 69359: WebdavServlet duplicates getRelativePath() method from
          super class with incorrect Javadoc. (michaelo)
        + Fix: 69360: Inconsistent DELETE behavior between WebdavServlet and
          DefaultServlet. (michaelo)
        + Fix: Make WebdavServlet properly return the Allow header when deletion
          of a resource is not allowed. (michaelo)
        + Fix: Add log warning if non-wildcard mappings are used with the WebdavServlet.
          (remm)
        + Fix: 69361: Ensure that the order of entries in a multi-status response
          to a WebDAV is consistent with the order in which resources were processed.
          (markt)
        + Fix: 69362: Provide a better multi-status response when deleting a
          collection via WebDAV fails. Empty directories that cannot be deleted
          will now be included in the response. (markt)
        + Fix: 69363: Use getPathPrefix() consistently in the WebDAV servlet to
          ensure that the correct path is used when the WebDAV servlet is mounted
          at a sub-path within the web application. (markt)
        + Fix 69320, a regression in the fix for 69302 that meant the HTTP/2 processing
          was likely to be broken for all clients once any client sent an HTTP/2
          reset frame. (markt)
        + Fix: Improve performance of ApplicationHttpRequest.parseParameters().
          Based on sample code and test cases provided by John Engebretson. (markt)
        + Fix:  Correct regressions in the refactoring that added recycling of the coyote
          request and response to the HTTP/2 processing. (markt)
        + Add: Add support for RFC 8297 (Early Hints). Applications can use this
          feature by casting the HttpServletResponse to org.apache.catalina.connector.
          Response and then calling the method void sendEarlyHints(). This method
          will be added to the Servlet API (removing the need for the cast) in Servlet
          6.2 onwards. (markt)
        + Fix: 69214: Do not reject a CORS request that uses POST but does not include
          a content-type header. Tomcat now correctly processes this as a simple CORS
          request. Based on a patch suggested by thebluemountain. (markt)
        + Fix: Refactor SpnegoAuthenticator so it uses Subject.callAs() rather than
          Subject.doAs() when available. (markt)
        + Fix: Allow JAASRealm to use the configuration source to load a configured
          configFile, for easier use with testing. (remm)
        + Fix: Add missing algorithm callback to the JAASCallbackHandler. (remm)
        + Fix: Add the OpenSSL version number on the APR and OpenSSL status classes.
          (remm)
        + Fix: 69131: Expand the implementation of the filter value of the Authenticator
          attribute allowCorsPreflight, so that it applies to all requests that match
          the configured URL patterns for the CORS filter, rather than only applying
          if the CORS filter is mapped to /*. (markt)
        + Fix: Using the OpenSSLListener will now cause the connector to use OpenSSL
          if available. (remm)
      * Coyote
        + Fix: Return null SSL session id on zero-length byte array returned
          from the SSL implementation. (remm)
        + Fix: Skip OpenSSLConf with BoringSSL since it is unsupported. (remm)
        + Fix: Create the HttpParser in Http11Processor if it is not present on
          the AbstractHttp11Protocol to provide better lifecycle robustness for
          regular HTTP/1.1. The new behavior was introduced in a previous refactoring
          to improve HTTP/2 performance. (remm)
        + Fix: OpenSSLContext will now throw a KeyManagementException if something
          is known to have gone wrong in the init method, which is the behavior
          documented by javax.net.ssl.SSLContext.init. This makes error handling
          more consistent. (remm)
        + Fix: 69379: The default HEAD response no longer includes the payload
          HTTP header fields as per section 9.3.2 of RFC 9110. (markt)
        + Fix: 69316: Ensure that FastHttpDateFormat#getCurrentDate() (used to
          generate Date headers for HTTP responses) generates the correct string
          for the given input. Prior to this change, the output may have been
          wrong by one second in some cases. Pull request #751 provided by Chenjp.
          (markt)
        + Fix: Request start time may not have been accurately recorded for HTTP/1.1
          requests preceded by a large number of blank lines. (markt)
        + Add: Add server and serverRemoveAppProvidedValues to the list of attributes
          the HTTP/2 protocol will inherit from the HTTP/1.1 connector it is nested
          within. (markt)
        + Fix: Avoid possible crashes when using Apache Tomcat Native, caused by
          destroying SSLContext objects through GC after APR has been terminated.
          (remm)
        + Fix: Improve HTTP/2 handling of trailer fields for requests. Trailer fields
          no longer need to be received before the headers of the subsequent stream,
          nor are trailer fields for an in-progress stream swallowed if the Connector
          is paused before the trailer fields are received. (markt)
        + Fix: Ensure the request and response are not recycled too soon for an
          HTTP/2 stream when a stream-level error is detected during the processing
          of incoming HTTP/2 frames. This could lead to incorrect processing times
          appearing in the access log. (markt)
        + Fix: Correct a regression in the fix for non-blocking reads of chunked
          request bodies that caused InputStream.available() to return a non-zero
          value when there was no data to read. In some circumstances this could
          cause a blocking read to block waiting for more data rather than return
          the data it had already received. (markt)
        + Add: Add a new attribute cookiesWithoutEquals to the Rfc6265CookieProcessor.
          The default behaviour is unchanged. (markt)
        + Fix: Ensure that Tomcat sends a TLS close_notify message after receiving
          one from the client when using the OpenSSLImplementation. (markt)
        + Fix: 69301: Fix trailer headers replacing non-trailer headers when writing
          response headers to the access log. Based on a patch and test case
          provided by hypnoce. (markt)
        + Fix: 69302: If an HTTP/2 client resets a stream before the request body
          is fully written, ensure that any ReadListener is notified via a call
          to ReadListener.onError(). (markt)
        + Fix: Ensure that HTTP/2 stream input buffers are only created when there is
          a request body to be read. (markt)
        + Code: Refactor creation of HttpParser instances from the Processor level to
          the Protocol level since the parser configuration depends on the protocol
          and the parser is, otherwise, stateless. (markt)
        + Add: Align HTTP/2 with HTTP/1.1 and recycle the container internal request
          and response processing objects by default. This behaviour can be controlled
          via the new discardRequestsAndResponses attribute on the HTTP/2 upgrade protocol.
          (markt)
        + Fix: Clean and log OpenSSL errors before processing of OpenSSL conf commands
          in the FFM code. (remm)
        + Fix: 69121: Ensure that the onComplete() event is triggered if AsyncListener.
          onError() dispatches to a target that throws an exception. (markt)
        + Fix: Following the trailer header field refactoring, -1 is no longer an allowed
          value for maxTrailerSize. Adjust documentation accordingly. (remm)
        + Update: Move OpenSSL support using FFM to a separate JAR named tomcat-coyote-ffm.
          jar that advertises Java 22 in its manifest. (remm)
        + Fix: Fix search for OpenSSL library for FFM on Mac OS so that java.library.path
          is searched. (markt)
        + Update: Add FFM compatibility methods for LibreSSL support. Renegotiation is
          not supported at the moment. (remm)
        + Update: Add org.apache.tomcat.util.openssl.LIBRARY_NAME (specifies the name
          of the library to load) and org.apache.tomcat.util.openssl.USE_SYSTEM_LOAD_LIBRARY
          (set to true to use System.loadLibrary rather than the FFM library loading code)
          to configure the OpenSSL library loading using FFM. (remm)
        + Update: Add FFM compatibility methods for BoringSSL support. Renegotiation is
          not supported in many cases. (remm)
      * Jasper
        + Fix: Add back tag release method as deprecated in the runtime for
          compatibility with old generated code. (remm)
        + Fix: 69399: Fix regression caused by improvement 69333, which caused
          the tag release to be called when using tag pooling, and to be skipped
          when not using it. Patch submitted by Michal Sobkiewicz. (remm)
        + Fix: 69381: Improve method lookup performance in expression language.
          When the required method has no arguments, there is no need to consider
          casting or coercion, and the method lookup process can be simplified.
          Based on a pull request by John Engebretson. (markt)
        + Fix: 69382: Improve the performance of the JSP include action by re-using
          results of relatively expensive method calls in the generated code rather
          than repeating them. Patch provided by John Engebretson. (markt)
        + Fix: 69398: Avoid unnecessary object allocation in PageContextImpl.
          Based on a suggestion by John Engebretson. (markt)
        + Fix: 69406: When using StringInterpreterEnum, do not throw an
          IllegalArgumentException when an invalid Enum is encountered. Instead,
          resolve the value at runtime. Patch provided by John Engebretson. (markt)
        + Fix: 69429: Optimize EL evaluation of method parameters for methods
          that do not accept any parameters. Patch provided by John Engebretson. (markt)
        + Fix: Further optimize EL evaluation of method parameters. Patch provided
          by Paolo B. (markt)
        + Fix: 69333: Remove unnecessary code from generated JSPs. (markt)
        + Fix: 69338: Improve the performance of processing expressions that include
          AND or OR operations with more than two operands and expressions that use
          not empty. (markt)
        + Fix: 69348: Reduce memory consumption in ELContext by using lazy
          initialization for the data structure used to track lambda arguments. (markt)
        + Fix: Switch the TldScanner back to logging detailed scan results at debug
          level rather than trace level. (markt)
        + Fix: Update the optimisation in jakarta.el.ImportHandler so it is aware of
          new classes added to the java.lang package in Java 23. (markt)
        + Fix: Ensure that an exception in toString() still results in an ELException
          when an object is coerced to a String using ExpressionFactory.coerceToType().
          (markt)
        + Add: Add support for specifying Java 24 (with the value 24) as the compiler
          source and/or compiler target for JSP compilation. If used with an Eclipse JDT
          compiler version that does not support these values, a warning will be logged
          and the default will be used. (markt)
        + Fix: 69135: When using include directives in a tag file packaged in a JAR file,
          ensure that context relative includes are processed correctly. (markt)
        + Fix: 69135: When using include directives in a tag file packaged in a JAR file,
          ensure that file relative includes are processed correctly. (markt)
        + Fix: 69135: When using include directives in a tag file packaged in a JAR file,
          ensure that file relative includes are not permitted to access files outside
          of the /META_INF/tags/ directory nor outside of the JAR file. (markt)
      * WebSocket
        + Fix: If a blocking message write exceeds the timeout, don't attempt the
          write again before throwing the exception. (markt)
        + Fix: An EncodeException being thrown during a message write should not
          automatically cause the connection to close. The application should handle
          the exception and make the decision whether or not to close the connection.
          (markt)
      * Web applications
        + Fix: The manager webapp will now be able to access certificates again
          when OpenSSL is used. (remm)
        + Fix: Documentation. Align the logging configuration documentation with
          the current defaults. (markt)
        + Fix: Fix status servlet detailed view of the connectors when using automatic
          port. (remm)
      * jdbc-pool
        + Fix: 69255: Correct a regression in the fix for 69206 that meant exceptions
          executing statements were wrapped in a java.lang.reflect.UndeclaredThrowableException
          rather than the application seeing the original SQLException. Fixed by pull
          request #744 provided by Michael Clarke. (markt)
        + Fix: 69279: Correct a regression in the fix for 69206 that meant that methods
          that previously returned a null ResultSet were returning a proxy with a
          null delegate. Fixed by pull request #745 provided by Huub de Beer. (markt)
        + Fix: 69206: Ensure statements returned from Statement methods executeQuery(),
          getResultSet() and getGeneratedKeys() are correctly wrapped before being returned
          to the caller. Based on pull request #742 provided by Michael Clarke. (markt)
      * Other
        + Update: Switch from DigiCert ONE to ssl.com eSigner for code signing. (markt)
        + Update: Update Byte Buddy to 1.15.10. (markt)
        + Update: Update CheckStyle to 10.20.0. (markt)
        + Add: Improvements to German translations. (remm)
        + Update: Update Byte Buddy to 1.15.3. (markt)
        + Update: Update CheckStyle to 10.18.2. (markt)
        + Add: Improvements to French translations. (remm)
        + Add: Improvements to Japanese translations by tak7iji. (markt)
        + Add: Improvements to Chinese translations by Ch_jp. (markt)
        + Add: Exclude the tomcat-coyote-ffm.jar from JAR scanning by default. (markt)
        + Fix: Change the default log handler level to ALL so log messages are not
          dropped by default if a logger is configured to use trace (FINEST) level
          logging. (markt)
        + Update: Update Hamcrest to 3.0. (markt)
        + Update: Update EasyMock to 5.4.0. (markt)
        + Update: Update Byte Buddy to 1.15.0. (markt)
        + Update: Update CheckStyle to 10.18.0. (markt)
        + Update: Update the internal fork of Apache Commons BCEL to 6.10.0. (markt)
        + Add: Improvements to Spanish translations by Fernando. (markt)
        + Add: Improvements to French translations. (remm)
        + Add: Improvements to Japanese translations by tak7iji. (markt)
        + Fix: Fix packaging regression with missing osgi information following addition
          of the test-only build target. (remm)
        + Update: Update Tomcat Native to 2.0.8. (markt)
        + Update: Update Byte Buddy to 1.14.18. (markt)
        + Add: Improvements to French translations. (remm)
        + Add: Improvements to Japanese translations by tak7iji. (markt)
        + Update: Add test-only build target to allow running only the testsuite,
          supporting Java versions down to the minimum supported to run Tomcat. (rjung)
        + Update: Update UnboundID to 7.0.1. (markt)
        + Update: Update to SpotBugs 4.8.6. (markt)
        + Update: Remove cglib dependency as it is not required by the version of EasyMock
          used by the unit tests. (markt)
        + Update: Update EasyMock to 5.3.0. This adds a test dependency on Byte-Buddy
          1.14.17. (markt)
        + Add: Improvements to Czech translations by Vladim?r Chlup. (markt)
        + Add: Improvements to French translations. (remm)
        + Add: Improvements to Japanese translations by tak7iji. (markt)
        + Add: Improvements to Chinese translations by fangzheng. (markt)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233434");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019867.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?368b65cc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52316");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat10-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat10-el-5_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat10-jsp-3_1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat10-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat10-servlet-6_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat10-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'tomcat10-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat10-admin-webapps-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat10-el-5_0-api-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat10-jsp-3_1-api-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat10-lib-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat10-servlet-6_0-api-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat10-webapps-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'tomcat10-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat10-admin-webapps-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat10-el-5_0-api-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat10-jsp-3_1-api-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat10-lib-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat10-servlet-6_0-api-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat10-webapps-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'tomcat10-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'tomcat10-admin-webapps-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'tomcat10-el-5_0-api-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'tomcat10-jsp-3_1-api-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'tomcat10-lib-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'tomcat10-servlet-6_0-api-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'tomcat10-webapps-10.1.33-150200.5.28.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'tomcat10-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat10-admin-webapps-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat10-el-5_0-api-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat10-jsp-3_1-api-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat10-lib-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat10-servlet-6_0-api-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat10-webapps-10.1.33-150200.5.28.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-web-scripting-release-15.6', 'sles-release-15.6']},
    {'reference':'tomcat10-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-admin-webapps-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-docs-webapp-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-el-5_0-api-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-embed-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-jsp-3_1-api-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-jsvc-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-lib-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-servlet-6_0-api-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-webapps-10.1.33-150200.5.28.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'tomcat10-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-admin-webapps-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-doc-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-docs-webapp-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-el-5_0-api-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-embed-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-jsp-3_1-api-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-jsvc-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-lib-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-servlet-6_0-api-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'tomcat10-webapps-10.1.33-150200.5.28.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat10 / tomcat10-admin-webapps / tomcat10-doc / etc');
}
