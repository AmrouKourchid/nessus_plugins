#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201209);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/02");

  script_cve_id(
    "CVE-2018-10237",
    "CVE-2020-8908",
    "CVE-2021-29425",
    "CVE-2022-36364",
    "CVE-2022-40896",
    "CVE-2022-40897",
    "CVE-2022-40898",
    "CVE-2022-40899",
    "CVE-2023-2976",
    "CVE-2023-5752",
    "CVE-2023-32681",
    "CVE-2023-34453",
    "CVE-2023-34454",
    "CVE-2023-34455",
    "CVE-2023-35116",
    "CVE-2023-37276",
    "CVE-2023-37920",
    "CVE-2023-39410",
    "CVE-2023-43642",
    "CVE-2023-43804",
    "CVE-2023-45803",
    "CVE-2023-47627",
    "CVE-2024-3651"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Splunk Enterprise 9.0.0 < 9.0.9, 9.1.0 < 9.1.4, 9.2.0 < 9.2.1 (SVD-2024-0718)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the SVD-2024-0718 advisory.

  - jackson-databind through 2.15.2 allows attackers to cause a denial of service or other unspecified impact
    via a crafted object that uses cyclic dependencies. NOTE: the vendor's perspective is that this is not a
    valid vulnerability report, because the steps of constructing a cyclic data structure and trying to
    serialize it cannot be achieved by an external attacker. (CVE-2023-35116)

  - In Apache Commons IO before 2.7, When invoking the method FileNameUtils.normalize with an improper input
    string, like //../foo, or \\..\foo, the result would be the same value, thus possibly providing access
    to files in the parent directory, but not further above (thus limited path traversal), if the calling
    code would use the result to construct a path value. (CVE-2021-29425)

  - snappy-java is a Java port of the snappy, a fast C++ compresser/decompresser developed by Google. The
    SnappyInputStream was found to be vulnerable to Denial of Service (DoS) attacks when decompressing data
    with a too large chunk size. Due to missing upper bound check on chunk length, an unrecoverable fatal
    error can occur. All versions of snappy-java including the latest released version 1.1.10.3 are vulnerable
    to this issue. A fix has been introduced in commit `9f8c3cf74` which will be included in the 1.1.10.4
    release. Users are advised to upgrade. Users unable to upgrade should only accept compressed data from
    trusted sources. (CVE-2023-43642)

  - snappy-java is a fast compressor/decompressor for Java. Due to unchecked multiplications, an integer
    overflow may occur in versions prior to 1.1.10.1, causing a fatal error. The function `shuffle(int[]
    input)` in the file `BitShuffle.java` receives an array of integers and applies a bit shuffle on it. It
    does so by multiplying the length by 4 and passing it to the natively compiled shuffle function. Since the
    length is not tested, the multiplication by four can cause an integer overflow and become a smaller value
    than the true size, or even zero or negative. In the case of a negative value, a
    `java.lang.NegativeArraySizeException` exception will raise, which can crash the program. In a case of a
    value that is zero or too small, the code that afterwards references the shuffled array will assume a
    bigger size of the array, which might cause exceptions such as `java.lang.ArrayIndexOutOfBoundsException`.
    The same issue exists also when using the `shuffle` functions that receive a double, float, long and
    short, each using a different multiplier that may cause the same issue. Version 1.1.10.1 contains a patch
    for this vulnerability. (CVE-2023-34453)

  - snappy-java is a fast compressor/decompressor for Java. Due to unchecked multiplications, an integer
    overflow may occur in versions prior to 1.1.10.1, causing an unrecoverable fatal error. The function
    `compress(char[] input)` in the file `Snappy.java` receives an array of characters and compresses it. It
    does so by multiplying the length by 2 and passing it to the rawCompress` function. Since the length is
    not tested, the multiplication by two can cause an integer overflow and become negative. The rawCompress
    function then uses the received length and passes it to the natively compiled maxCompressedLength
    function, using the returned value to allocate a byte array. Since the maxCompressedLength function treats
    the length as an unsigned integer, it doesn't care that it is negative, and it returns a valid value,
    which is casted to a signed integer by the Java engine. If the result is negative, a
    `java.lang.NegativeArraySizeException` exception will be raised while trying to allocate the array `buf`.
    On the other side, if the result is positive, the `buf` array will successfully be allocated, but its size
    might be too small to use for the compression, causing a fatal Access Violation error. The same issue
    exists also when using the `compress` functions that receive double, float, int, long and short, each
    using a different multiplier that may cause the same issue. The issue most likely won't occur when using a
    byte array, since creating a byte array of size 0x80000000 (or any other negative value) is impossible in
    the first place. Version 1.1.10.1 contains a patch for this issue. (CVE-2023-34454)

  - snappy-java is a fast compressor/decompressor for Java. Due to use of an unchecked chunk length, an
    unrecoverable fatal error can occur in versions prior to 1.1.10.1. The code in the function hasNextChunk
    in the fileSnappyInputStream.java checks if a given stream has more chunks to read. It does that by
    attempting to read 4 bytes. If it wasn't possible to read the 4 bytes, the function returns false.
    Otherwise, if 4 bytes were available, the code treats them as the length of the next chunk. In the case
    that the `compressed` variable is null, a byte array is allocated with the size given by the input data.
    Since the code doesn't test the legality of the `chunkSize` variable, it is possible to pass a negative
    number (such as 0xFFFFFFFF which is -1), which will cause the code to raise a
    `java.lang.NegativeArraySizeException` exception. A worse case would happen when passing a huge positive
    value (such as 0x7FFFFFFF), which would raise the fatal `java.lang.OutOfMemoryError` error. Version
    1.1.10.1 contains a patch for this issue. (CVE-2023-34455)

  - When deserializing untrusted or corrupted data, it is possible for a reader to consume memory beyond the
    allowed constraints and thus lead to out of memory on the system. This issue affects Java applications
    using Apache Avro Java SDK up to and including 1.11.2. Users should update to apache-avro version 1.11.3
    which addresses this issue. (CVE-2023-39410)

  - Apache Calcite Avatica JDBC driver creates HTTP client instances based on class names provided via
    `httpclient_impl` connection property; however, the driver does not verify if the class implements the
    expected interface before instantiating it, which can lead to code execution loaded via arbitrary classes
    and in rare cases remote code execution. To exploit the vulnerability: 1) the attacker needs to have
    privileges to control JDBC connection parameters; 2) and there should be a vulnerable class (constructor
    with URL parameter and ability to execute code) in the classpath. From Apache Calcite Avatica 1.22.0
    onwards, it will be verified that the class implements the expected interface before invoking its
    constructor. (CVE-2022-36364)

  - A temp directory creation vulnerability exists in all versions of Guava, allowing an attacker with access
    to the machine to potentially access data in a temporary directory created by the Guava API
    com.google.common.io.Files.createTempDir(). By default, on unix-like systems, the created directory is
    world-readable (readable by an attacker with access to the system). The method in question has been marked
    @Deprecated in versions 30.0 and later and should not be used. For Android developers, we recommend
    choosing a temporary directory API provided by Android, such as context.getCacheDir(). For other Java
    developers, we recommend migrating to the Java 7 API java.nio.file.Files.createTempDirectory() which
    explicitly configures permissions of 700, or configuring the Java runtime's java.io.tmpdir system property
    to point to a location whose permissions are appropriately configured. (CVE-2020-8908)

  - Use of Java's default temporary directory for file creation in `FileBackedOutputStream` in Google Guava
    versions 1.0 to 31.1 on Unix systems and Android Ice Cream Sandwich allows other users and apps on the
    machine with access to the default Java temporary directory to be able to access the files created by the
    class. Even though the security vulnerability is fixed in version 32.0.0, we recommend using version
    32.0.1 as version 32.0.0 breaks some functionality under Windows. (CVE-2023-2976)

  - Unbounded memory allocation in Google Guava 11.0 through 24.x before 24.1.1 allows remote attackers to
    conduct denial of service attacks against servers that depend on this library and deserialize attacker-
    provided data, because the AtomicDoubleArray class (when serialized with Java serialization) and the
    CompoundOrdering class (when serialized with GWT serialization) perform eager allocation without
    appropriate checks on what a client has sent and whether the data size is reasonable. (CVE-2018-10237)

  - aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. aiohttp v3.8.4 and earlier
    are bundled with llhttp v6.0.6. Vulnerable code is used by aiohttp for its HTTP request parser when
    available which is the default case when installing from a wheel. This vulnerability only affects users of
    aiohttp as an HTTP server (ie `aiohttp.Application`), you are not affected by this vulnerability if you
    are using aiohttp as an HTTP client library (ie `aiohttp.ClientSession`). Sending a crafted HTTP request
    will cause the server to misinterpret one of the HTTP header values leading to HTTP request smuggling.
    This issue has been addressed in version 3.8.5. Users are advised to upgrade. Users unable to upgrade can
    reinstall aiohttp using `AIOHTTP_NO_EXTENSIONS=1` as an environment variable to disable the llhttp HTTP
    request parser implementation. The pure Python implementation isn't vulnerable. (CVE-2023-37276)

  - aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. The HTTP parser in AIOHTTP
    has numerous problems with header parsing, which could lead to request smuggling. This parser is only used
    when AIOHTTP_NO_EXTENSIONS is enabled (or not using a prebuilt wheel). These bugs have been addressed in
    commit `d5c12ba89` which has been included in release version 3.8.6. Users are advised to upgrade. There
    are no known workarounds for these issues. (CVE-2023-47627)

  - urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header
    special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user.
    However, it is possible for a user to specify a `Cookie` header and unknowingly leak information via HTTP
    redirects to a different origin if that user doesn't disable redirects explicitly. This issue has been
    patched in urllib3 version 1.26.17 or 2.0.5. (CVE-2023-43804)

  - urllib3 is a user-friendly HTTP client library for Python. urllib3 previously wouldn't remove the HTTP
    request body when an HTTP redirect response using status 301, 302, or 303 after the request had its method
    changed from one that could accept a request body (like `POST`) to `GET` as is required by HTTP RFCs.
    Although this behavior is not specified in the section for redirects, it can be inferred by piecing
    together information from different sections and we have observed the behavior in other major HTTP client
    implementations like curl and web browsers. Because the vulnerability requires a previously trusted
    service to become compromised in order to have an impact on confidentiality we believe the exploitability
    of this vulnerability is low. Additionally, many users aren't putting sensitive data in HTTP request
    bodies, if this is the case then this vulnerability isn't exploitable. Both of the following conditions
    must be true to be affected by this vulnerability: 1. Using urllib3 and submitting sensitive information
    in the HTTP request body (such as form data or JSON) and 2. The origin service is compromised and starts
    redirecting using 301, 302, or 303 to a malicious peer or the redirected-to service becomes compromised.
    This issue has been addressed in versions 1.26.18 and 2.0.7 and users are advised to update to resolve
    this issue. Users unable to update should disable redirects for services that aren't expecting to respond
    with redirects with `redirects=False` and disable automatic redirects with `redirects=False` and handle
    301, 302, and 303 redirects manually by stripping the HTTP request body. (CVE-2023-45803)

  - Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL
    certificates while verifying the identity of TLS hosts. Certifi prior to version 2023.07.22 recognizes
    e-Tugra root certificates. e-Tugra's root certificates were subject to an investigation prompted by
    reporting of security issues in their systems. Certifi 2023.07.22 removes root certificates from e-Tugra
    from the root store. (CVE-2023-37920)

  - When installing a package from a Mercurial VCS URL (ie pip install hg+...) with pip prior to v23.3, the
    specified Mercurial revision could be used to inject arbitrary configuration options to the hg clone
    call (ie --config). Controlling the Mercurial configuration can modify how and which repository is
    installed. This vulnerability does not affect users who aren't installing from Mercurial. (CVE-2023-5752)

  - Python Packaging Authority (PyPA) setuptools before 65.5.1 allows remote attackers to cause a denial of
    service via HTML in a crafted package or custom PackageIndex page. There is a Regular Expression Denial of
    Service (ReDoS) in package_index.py. (CVE-2022-40897)

  - A ReDoS issue was discovered in pygments/lexers/smithy.py in pygments through 2.15.0 via SmithyLexer.
    (CVE-2022-40896)

  - An issue discovered in Python Packaging Authority (PyPA) Wheel 0.37.1 and earlier allows remote attackers
    to cause a denial of service via attacker controlled input to wheel cli. (CVE-2022-40898)

  - Requests is a HTTP library. Since Requests 2.3.0, Requests has been leaking Proxy-Authorization headers to
    destination servers when redirected to an HTTPS endpoint. This is a product of how we use
    `rebuild_proxies` to reattach the `Proxy-Authorization` header to requests. For HTTP connections sent
    through the tunnel, the proxy will identify the header in the request itself and remove it prior to
    forwarding to the destination server. However when sent over HTTPS, the `Proxy-Authorization` header must
    be sent in the CONNECT request as the proxy has no visibility into the tunneled request. This results in
    Requests forwarding proxy credentials to the destination server unintentionally, allowing a malicious
    actor to potentially exfiltrate sensitive information. This issue has been patched in version 2.31.0.
    (CVE-2023-32681)

  - An issue discovered in Python Charmers Future 0.18.2 and earlier allows remote attackers to cause a denial
    of service via crafted Set-Cookie header from malicious web server. (CVE-2022-40899)

  - python-idna: potential DoS via resource consumption via specially crafted inputs to idna.encode()
    (CVE-2024-3651)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://advisory.splunk.com/advisories/SVD-2024-0718.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to versions 9.2.1, 9.1.4, and 9.0.9, or higher.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29425");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-37920");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin", "splunk_nix_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.9', 'license' : 'Enterprise' },
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.4', 'license' : 'Enterprise' },
  { 'min_version' : '9.2.0', 'fixed_version' : '9.2.1', 'license' : 'Enterprise' }
];
vcf::splunk::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
