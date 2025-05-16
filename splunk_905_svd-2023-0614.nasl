#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194927);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/30");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2020-8169",
    "CVE-2020-8177",
    "CVE-2020-8231",
    "CVE-2020-8284",
    "CVE-2020-8285",
    "CVE-2020-8286",
    "CVE-2021-22876",
    "CVE-2021-22890",
    "CVE-2021-22897",
    "CVE-2021-22898",
    "CVE-2021-22901",
    "CVE-2021-22922",
    "CVE-2021-22923",
    "CVE-2021-22924",
    "CVE-2021-22925",
    "CVE-2021-22926",
    "CVE-2021-22945",
    "CVE-2021-22946",
    "CVE-2021-22947",
    "CVE-2021-31566",
    "CVE-2021-3520",
    "CVE-2021-36976",
    "CVE-2022-22576",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27778",
    "CVE-2022-27779",
    "CVE-2022-27780",
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-30115",
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208",
    "CVE-2022-32221",
    "CVE-2022-35252",
    "CVE-2022-35260",
    "CVE-2022-35737",
    "CVE-2022-36227",
    "CVE-2022-37434",
    "CVE-2022-40303",
    "CVE-2022-40304",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2022-4304",
    "CVE-2022-43551",
    "CVE-2022-43552",
    "CVE-2023-0215",
    "CVE-2023-0286",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-23916",
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27537",
    "CVE-2023-27538"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Universal Forwarders < 8.1.14, 8.2.0 < 8.2.11, 9.0.0 < 9.0.5 (SVD-2023-0614)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the SVD-2023-0614 advisory.

  - An issue was discovered in libxml2 before 2.10.3. When parsing a multi-gigabyte XML document with the
    XML_PARSE_HUGE parser option enabled, several integer counters can overflow. This results in an attempt to
    access an array at a negative 2GB offset, typically leading to a segmentation fault. (CVE-2022-40303)

  - An issue was discovered in libxml2 before 2.10.3. Certain invalid XML entity definitions can corrupt a
    hash table key, potentially leading to subsequent logic errors. In one case, a double-free can be
    provoked. (CVE-2022-40304)

  - There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.
    X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME
    incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently
    interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL
    checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may
    allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or
    enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate
    chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these
    inputs, the other input must already contain an X.400 address as a CRL distribution point, which is
    uncommon. As such, this vulnerability is most likely to only affect applications which have implemented
    their own functionality for retrieving CRLs over a network. (CVE-2023-0286)

  - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. It is
    primarily used internally to OpenSSL to support the SMIME, CMS and PKCS7 streaming capabilities, but may
    also be called directly by end user applications. The function receives a BIO from the caller, prepends a
    new BIO_f_asn1 filter BIO onto the front of it to form a BIO chain, and then returns the new head of the
    BIO chain to the caller. Under certain conditions, for example if a CMS recipient public key is invalid,
    the new filter BIO is freed and the function returns a NULL result indicating a failure. However, in this
    case, the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal
    pointers to the previously freed filter BIO. If the caller then goes on to call BIO_pop() on the BIO then
    a use-after-free will occur. This will most likely result in a crash. This scenario occurs directly in the
    internal function B64_write_ASN1() which may cause BIO_new_NDEF() to be called and will subsequently call
    BIO_pop() on the BIO. This internal function is in turn called by the public API functions
    PEM_write_bio_ASN1_stream, PEM_write_bio_CMS_stream, PEM_write_bio_PKCS7_stream, SMIME_write_ASN1,
    SMIME_write_CMS and SMIME_write_PKCS7. Other public API functions that may be impacted by this include
    i2d_ASN1_bio_stream, BIO_new_CMS, BIO_new_PKCS7, i2d_CMS_bio_stream and i2d_PKCS7_bio_stream. The OpenSSL
    cms and smime command line applications are similarly affected. (CVE-2023-0215)

  - A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient
    to recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful
    decryption an attacker would have to be able to send a very large number of trial messages for decryption.
    The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS
    connection, RSA is commonly used by a client to send an encrypted pre-master secret to the server. An
    attacker that had observed a genuine connection between a client and a server could use this flaw to send
    trial messages to the server and record the time taken to process them. After a sufficiently large number
    of messages the attacker could recover the pre-master secret used for the original connection and thus be
    able to decrypt the application data sent over that connection. (CVE-2022-4304)

  - An authentication bypass vulnerability exists in libcurl prior to v8.0.0 where it reuses a previously
    established SSH connection despite the fact that an SSH option was modified, which should have prevented
    reuse. libcurl maintains a pool of previously used connections to reuse them for subsequent transfers if
    the configurations match. However, two SSH settings were omitted from the configuration check, allowing
    them to match easily, potentially leading to the reuse of an inappropriate connection. (CVE-2023-27538)

  - A double free vulnerability exists in libcurl <8.0.0 when sharing HSTS data between separate handles.
    This sharing was introduced without considerations for do this sharing across separate threads but there
    was no indication of this fact in the documentation. Due to missing mutexes or thread locks, two threads
    sharing the same HSTS data could end up doing a double-free or use-after-free. (CVE-2023-27537)

  - An authentication bypass vulnerability exists libcurl <8.0.0 in the connection reuse feature which can
    reuse previously established connections with incorrect user permissions due to a failure to check for
    changes in the CURLOPT_GSSAPI_DELEGATION option. This vulnerability affects krb5/kerberos/negotiate/GSSAPI
    transfers and could potentially result in unauthorized access to sensitive information. The safest option
    is to not reuse connections if the CURLOPT_GSSAPI_DELEGATION option has been changed. (CVE-2023-27536)

  - An authentication bypass vulnerability exists in libcurl <8.0.0 in the FTP connection reuse feature that
    can result in wrong credentials being used during subsequent transfers. Previously created connections are
    kept in a connection pool for reuse if they match the current setup. However, certain FTP settings such as
    CURLOPT_FTP_ACCOUNT, CURLOPT_FTP_ALTERNATIVE_TO_USER, CURLOPT_FTP_SSL_CCC, and CURLOPT_USE_SSL were not
    included in the configuration match checks, causing them to match too easily. This could lead to libcurl
    using the wrong credentials when performing a transfer, potentially allowing unauthorized access to
    sensitive information. (CVE-2023-27535)

  - A path traversal vulnerability exists in curl <8.0.0 SFTP implementation causes the tilde (~) character to
    be wrongly replaced when used as a prefix in the first path element, in addition to its intended use as
    the first element to indicate a path relative to the user's home directory. Attackers can exploit this
    flaw to bypass filtering or execute arbitrary code by crafting a path like /~2/foo while accessing a
    server with a specific user. (CVE-2023-27534)

  - A vulnerability in input validation exists in curl <8.0 during communication using the TELNET protocol may
    allow an attacker to pass on maliciously crafted user name and telnet options during server negotiation.
    The lack of proper input scrubbing allows an attacker to send content or perform option negotiation
    without the application's intent. This vulnerability could be exploited if an application allows user
    input, thereby enabling attackers to execute arbitrary code on the system. (CVE-2023-27533)

  - An allocation of resources without limits or throttling vulnerability exists in curl <v7.88.0 based on the
    chained HTTP compression algorithms, meaning that a server response can be compressed multiple times and
    potentially with differentalgorithms. The number of acceptable links in this decompression chain
    wascapped, but the cap was implemented on a per-header basis allowing a maliciousserver to insert a
    virtually unlimited number of compression steps simply byusing many headers. The use of such a
    decompression chain could result in a malloc bomb, making curl end up spending enormous amounts of
    allocated heap memory, or trying to and returning out of memory errors. (CVE-2023-23916)

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality to behave incorrectly when multiple URLs are requested in parallel. Using its HSTS
    support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP step even when
    HTTP is provided in the URL. This HSTS mechanism would however surprisingly fail when multiple transfers
    are done in parallel as the HSTS cache file gets overwritten by the most recentlycompleted transfer. A
    later HTTP-only transfer to the earlier host name would then *not* get upgraded properly to HSTS.
    (CVE-2023-23915)

  - A cleartext transmission of sensitive information vulnerability exists in curl <v7.88.0 that could cause
    HSTS functionality fail when multiple URLs are requested serially. Using its HSTS support, curl can be
    instructed to use HTTPS instead of usingan insecure clear-text HTTP step even when HTTP is provided in the
    URL. ThisHSTS mechanism would however surprisingly be ignored by subsequent transferswhen done on the same
    command line because the state would not be properlycarried on. (CVE-2023-23914)

  - A use after free vulnerability exists in curl <7.87.0. Curl can be asked to *tunnel* virtually all
    protocols it supports through an HTTP proxy. HTTP proxies can (and often do) deny such tunnel operations.
    When getting denied to tunnel the specific protocols SMB or TELNET, curl would use a heap-allocated struct
    after it had been freed, in its transfer shutdown code path. (CVE-2022-43552)

  - A vulnerability exists in curl <7.87.0 HSTS check that could be bypassed to trick it to keep using HTTP.
    Using its HSTS support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP
    step even when HTTP is provided in the URL. However, the HSTS mechanism could be bypassed if the host name
    in the given URL first uses IDN characters that get replaced to ASCII counterparts as part of the IDN
    conversion. Like using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full
    stop (U+002E) `.`. Then in a subsequent request, it does not detect the HSTS state and makes a clear text
    transfer. Because it would store the info IDN encoded but look for it IDN decoded. (CVE-2022-43551)

  - In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS
    support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step)
    even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the given URL
    uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, e.g., using
    the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of U+002E (.).
    The earliest affected version is 7.77.0 2021-05-26. (CVE-2022-42916)

  - curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a non-
    HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to the proxy, and
    then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP proxies often
    only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead return a non-200
    status code to the client. Due to flaws in the error/cleanup handling, this could trigger a double free in
    curl if one of the following schemes were used in the URL for the transfer: dict, gopher, gophers, ldap,
    ldaps, rtmp, rtmps, or telnet. The earliest affected version is 7.77.0. (CVE-2022-42915)

  - curl can be told to parse a `.netrc` file for credentials. If that file endsin a line with 4095
    consecutive non-white space letters and no newline, curlwould first read past the end of the stack-based
    buffer, and if the readworks, write a zero byte beyond its boundary.This will in most cases cause a
    segfault or similar, but circumstances might also cause different outcomes.If a malicious user can provide
    a custom netrc file to an application or otherwise affect its contents, this flaw could be used as denial-
    of-service. (CVE-2022-35260)

  - When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to
    ask for data to send, even when the `CURLOPT_POSTFIELDS` option has been set, if the same handle
    previously was used to issue a `PUT` request which used that callback. This flaw may surprise the
    application and cause it to misbehave and either send off the wrong data or use memory after free or
    similar in the subsequent `POST` request. The problem exists in the logic for a reused handle when it is
    changed from a PUT to a POST. (CVE-2022-32221)

  - When curl is used to retrieve and parse cookies from a HTTP(S) server, itaccepts cookies using control
    codes that when later are sent back to a HTTPserver might make the server return 400 responses.
    Effectively allowing asister site to deny service to all siblings. (CVE-2022-35252)

  - When curl < 7.84.0 does FTP transfers secured by krb5, it handles message verification failures wrongly.
    This flaw makes it possible for a Man-In-The-Middle attack to go unnoticed and even allows it to inject
    data to the client. (CVE-2022-32208)

  - When curl < 7.84.0 saves cookies, alt-svc and hsts data to local files, it makes the operation atomic by
    finalizing the operation with a rename from a temporary name to the final target file name.In that rename
    operation, it might accidentally *widen* the permissions for the target file, leaving the updated file
    accessible to more users than intended. (CVE-2022-32207)

  - curl < 7.84.0 supports chained HTTP compression algorithms, meaning that a serverresponse can be
    compressed multiple times and potentially with different algorithms. The number of acceptable links in
    this decompression chain was unbounded, allowing a malicious server to insert a virtually unlimited
    number of compression steps.The use of such a decompression chain could result in a malloc bomb,
    makingcurl end up spending enormous amounts of allocated heap memory, or trying toand returning out of
    memory errors. (CVE-2022-32206)

  - A malicious server can serve excessive amounts of `Set-Cookie:` headers in a HTTP response to curl and
    curl < 7.84.0 stores all of them. A sufficiently large amount of (big) cookies make subsequent HTTP
    requests to this, or other servers to which the cookies match, create requests that become larger than the
    threshold that curl uses internally to avoid sending crazy large requests (1048576 bytes) and instead
    returns an error.This denial state might remain for as long as the same cookies are kept, match and
    haven't expired. Due to cookie matching rules, a server on `foo.example.com` can set cookies that also
    would match for `bar.example.com`, making it it possible for a sister server to effectively cause a
    denial of service for a sibling site on the same second level domain using this method. (CVE-2022-32205)

  - Using its HSTS support, curl can be instructed to use HTTPS directly insteadof using an insecure clear-
    text HTTP step even when HTTP is provided in theURL. This mechanism could be bypassed if the host name in
    the given URL used atrailing dot while not using one when it built the HSTS cache. Or the otherway around
    - by having the trailing dot in the HSTS cache and *not* using thetrailing dot in the URL.
    (CVE-2022-30115)

  - libcurl would reuse a previously created connection even when a TLS or SSHrelated option had been changed
    that should have prohibited reuse.libcurl keeps previously used connections in a connection pool for
    subsequenttransfers to reuse if one of them matches the setup. However, several TLS andSSH settings were
    left out from the configuration match checks, making themmatch too easily. (CVE-2022-27782)

  - libcurl provides the `CURLOPT_CERTINFO` option to allow applications torequest details to be returned
    about a server's certificate chain.Due to an erroneous function, a malicious server could make libcurl
    built withNSS get stuck in a never-ending busy-loop when trying to retrieve thatinformation.
    (CVE-2022-27781)

  - The curl URL parser wrongly accepts percent-encoded URL separators like '/'when decoding the host name
    part of a URL, making it a *different* URL usingthe wrong host name when it is later retrieved.For
    example, a URL like `http://example.com%2F127.0.0.1/`, would be allowed bythe parser and get transposed
    into `http://example.com/127.0.0.1/`. This flawcan be used to circumvent filters, checks and more.
    (CVE-2022-27780)

  - libcurl wrongly allows cookies to be set for Top Level Domains (TLDs) if thehost name is provided with a
    trailing dot.curl can be told to receive and send cookies. curl's cookie engine can bebuilt with or
    without [Public Suffix List](https://publicsuffix.org/)awareness. If PSL support not provided, a more
    rudimentary check exists to atleast prevent cookies from being set on TLDs. This check was broken if
    thehost name in the URL uses a trailing dot.This can allow arbitrary sites to set cookies that then would
    get sent to adifferent and unrelated site or domain. (CVE-2022-27779)

  - A use of incorrectly resolved name vulnerability fixed in 7.83.1 might remove the wrong file when `--no-
    clobber` is used together with `--remove-on-error`. (CVE-2022-27778)

  - A insufficiently protected credentials vulnerability in fixed in curl 7.83.0 might leak authentication or
    cookie header data on HTTP redirects to the same host but another port number. (CVE-2022-27776)

  - An information disclosure vulnerability exists in curl 7.65.0 to 7.82.0 are vulnerable that by using an
    IPv6 address that was in the connection pool but with a different zone id it could reuse a connection
    instead. (CVE-2022-27775)

  - An insufficiently protected credentials vulnerability exists in curl 4.9 to and include curl 7.82.0 are
    affected that could allow an attacker to extract credentials when follows HTTP(S) redirects is used with
    authentication could leak credentials to other services that exist on different protocols or port numbers.
    (CVE-2022-27774)

  - An improper authentication vulnerability exists in curl 7.33.0 to and including 7.82.0 which might allow
    reuse OAUTH2-authenticated connections without properly making sure that the connection was authenticated
    with the same credentials as set for this transfer. This affects SASL-enabled protocols: SMPTP(S),
    IMAP(S), POP3(S) and LDAP(S) (openldap only). (CVE-2022-22576)

  - When curl >= 7.20.0 and <= 7.78.0 connects to an IMAP or POP3 server to retrieve data using STARTTLS to
    upgrade to TLS security, the server can respond and send back multiple responses at once that curl caches.
    curl would then upgrade to TLS but not flush the in-queue of cached responses but instead continue using
    and trustingthe responses it got *before* the TLS handshake as if they were authenticated.Using this flaw,
    it allows a Man-In-The-Middle attacker to first inject the fake responses, then pass-through the TLS
    traffic from the legitimate server and trick curl into sending data back to the user thinking the
    attacker's injected data comes from the TLS-protected server. (CVE-2021-22947)

  - A user can tell curl >= 7.20.0 and <= 7.78.0 to require a successful upgrade to TLS when speaking to an
    IMAP, POP3 or FTP server (`--ssl-reqd` on the command line or`CURLOPT_USE_SSL` set to `CURLUSESSL_CONTROL`
    or `CURLUSESSL_ALL` withlibcurl). This requirement could be bypassed if the server would return a properly
    crafted but perfectly legitimate response.This flaw would then make curl silently continue its operations
    **withoutTLS** contrary to the instructions and expectations, exposing possibly sensitive data in clear
    text over the network. (CVE-2021-22946)

  - When sending data to an MQTT server, libcurl <= 7.73.0 and 7.78.0 could in some circumstances erroneously
    keep a pointer to an already freed memory area and both use that again in a subsequent call to send data
    and also free it *again*. (CVE-2021-22945)

  - libcurl-using applications can ask for a specific client certificate to be used in a transfer. This is
    done with the `CURLOPT_SSLCERT` option (`--cert` with the command line tool).When libcurl is built to use
    the macOS native TLS library Secure Transport, an application can ask for the client certificate by name
    or with a file name - using the same option. If the name exists as a file, it will be used instead of by
    name.If the appliction runs with a current working directory that is writable by other users (like
    `/tmp`), a malicious user can create a file name with the same name as the app wants to use by name, and
    thereby trick the application to use the file based cert instead of the one referred to by name making
    libcurl send the wrong client certificate in the TLS connection handshake. (CVE-2021-22926)

  - curl supports the `-t` command line option, known as `CURLOPT_TELNETOPTIONS`in libcurl. This rarely used
    option is used to send variable=content pairs toTELNET servers.Due to flaw in the option parser for
    sending `NEW_ENV` variables, libcurlcould be made to pass on uninitialized data from a stack based buffer
    to theserver. Therefore potentially revealing sensitive internal information to theserver using a clear-
    text network protocol.This could happen because curl did not call and use sscanf() correctly whenparsing
    the string provided by the application. (CVE-2021-22925)

  - libcurl keeps previously used connections in a connection pool for subsequenttransfers to reuse, if one of
    them matches the setup.Due to errors in the logic, the config matching function did not take 'issuercert'
    into account and it compared the involved paths *case insensitively*,which could lead to libcurl reusing
    wrong connections.File paths are, or can be, case sensitive on many systems but not all, and caneven vary
    depending on used file systems.The comparison also didn't include the 'issuer cert' which a transfer can
    setto qualify how to verify the server certificate. (CVE-2021-22924)

  - When curl is instructed to get content using the metalink feature, and a user name and password are used
    to download the metalink XML file, those same credentials are then subsequently passed on to each of the
    servers from which curl will download or try to download the contents from. Often contrary to the user's
    expectations and intentions and without telling the user it happened. (CVE-2021-22923)

  - When curl is instructed to download content using the metalink feature, thecontents is verified against a
    hash provided in the metalink XML file.The metalink XML file points out to the client how to get the same
    contentfrom a set of different URLs, potentially hosted by different servers and theclient can then
    download the file from one or several of them. In a serial orparallel manner.If one of the servers hosting
    the contents has been breached and the contentsof the specific file on that server is replaced with a
    modified payload, curlshould detect this when the hash of the file mismatches after a completeddownload.
    It should remove the contents and instead try getting the contentsfrom another URL. This is not done, and
    instead such a hash mismatch is onlymentioned in text and the potentially malicious content is kept in the
    file ondisk. (CVE-2021-22922)

  - curl 7.75.0 through 7.76.1 suffers from a use-after-free vulnerability resulting in already freed memory
    being used when a TLS 1.3 session ticket arrives over a connection. A malicious server can use this in
    rare unfortunate circumstances to potentially reach remote code execution in the client. When libcurl at
    run-time sets up support for TLS 1.3 session tickets on a connection using OpenSSL, it stores pointers to
    the transfer in-memory object for later retrieval when a session ticket arrives. If the connection is used
    by multiple transfers (like with a reused HTTP/1.1 connection or multiplexed HTTP/2 connection) that first
    transfer object might be freed before the new session is established on that connection and then the
    function will access a memory buffer that might be freed. When using that memory, libcurl might even call
    a function pointer in the object, making it possible for a remote code execution if the server could
    somehow manage to get crafted memory content into the correct place in memory. (CVE-2021-22901)

  - curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as
    `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a
    flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized
    data from a stack based buffer to the server, resulting in potentially revealing sensitive internal
    information to the server using a clear-text network protocol. (CVE-2021-22898)

  - curl 7.61.0 through 7.76.1 suffers from exposure of data element to wrong session due to a mistake in the
    code for CURLOPT_SSL_CIPHER_LIST when libcurl is built to use the Schannel TLS library. The selected
    cipher set was stored in a single static variable in the library, which has the surprising side-effect
    that if an application sets up multiple concurrent transfers, the last one that sets the ciphers will
    accidentally control the set used by all transfers. In a worst-case scenario, this weakens transport
    security significantly. (CVE-2021-22897)

  - curl 7.63.0 to and including 7.75.0 includes vulnerability that allows a malicious HTTPS proxy to MITM a
    connection due to bad handling of TLS 1.3 session tickets. When using a HTTPS proxy and TLS 1.3, libcurl
    can confuse session tickets arriving from the HTTPS proxy but work as if they arrived from the remote
    server and then wrongly short-cut the host handshake. When confusing the tickets, a HTTPS proxy can
    trick libcurl to use the wrong session ticket resume for the host and thereby circumvent the server TLS
    certificate check and make a MITM attack to be possible to perform unnoticed. Note that such a malicious
    HTTPS proxy needs to provide a certificate that curl will accept for the MITMed server for an attack to
    work - unless curl has been told to ignore the server certificate check. (CVE-2021-22890)

  - curl 7.1.1 to and including 7.75.0 is vulnerable to an Exposure of Private Personal Information to an
    Unauthorized Actor by leaking credentials in the HTTP Referer: header. libcurl does not strip off user
    credentials from the URL when automatically populating the Referer: HTTP request header field in outgoing
    HTTP requests, and therefore risks leaking sensitive data to the server that is the target of the second
    HTTP request. (CVE-2021-22876)

  - curl 7.41.0 through 7.73.0 is vulnerable to an improper check for certificate revocation due to
    insufficient verification of the OCSP response. (CVE-2020-8286)

  - curl 7.21.0 to and including 7.73.0 is vulnerable to uncontrolled recursion due to a stack overflow issue
    in FTP wildcard match parsing. (CVE-2020-8285)

  - A malicious server can use the FTP PASV response to trick curl 7.73.0 and earlier into connecting back to
    a given IP address and port, and this way potentially make curl extract information about services that
    are otherwise private and not disclosed, for example doing port scanning and service banner extractions.
    (CVE-2020-8284)

  - Due to use of a dangling pointer, libcurl 7.29.0 through 7.71.1 can use the wrong connection when sending
    data. (CVE-2020-8231)

  - curl 7.20.0 through 7.70.0 is vulnerable to improper restriction of names for files and other resources
    that can lead too overwriting a local file when the -J flag is used. (CVE-2020-8177)

  - curl 7.62.0 through 7.70.0 is vulnerable to an information disclosure vulnerability that can lead to a
    partial password being leaked over the network and to the DNS server(s). (CVE-2020-8169)

  - In libarchive before 3.6.2, the software does not check for an error after calling calloc function that
    can return with a NULL pointer if the function fails, which leads to a resultant NULL pointer dereference.
    NOTE: the discoverer cites this CWE-476 remark but third parties dispute the code-execution impact: In
    rare circumstances, when NULL is equivalent to the 0x0 memory address and privileged code can access it,
    then writing or reading memory is possible, which may lead to code execution. (CVE-2022-36227)

  - An improper link resolution flaw can occur while extracting an archive leading to changing modes, times,
    access control lists, and flags of a file outside of the archive. An attacker may provide a malicious
    archive to a victim user, who would trigger this flaw when trying to extract the archive. A local attacker
    may use this flaw to gain more privileges in a system. (CVE-2021-31566)

  - libarchive 3.4.1 through 3.5.1 has a use-after-free in copy_string (called from do_uncompress_block and
    process_block). (CVE-2021-36976)

  - There's a flaw in lz4. An attacker who submits a crafted file to an application linked with lz4 may be
    able to trigger an integer overflow, leading to calling of memmove() on a negative size argument, causing
    an out-of-bounds write and/or a crash. The greatest impact of this flaw is to availability, with some
    potential impact to confidentiality and integrity as well. (CVE-2021-3520)

  - SQLite 1.0.12 through 3.39.x before 3.39.2 sometimes allows an array-bounds overflow if billions of bytes
    are used in a string argument to a C API. (CVE-2022-35737)

  - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many
    distant matches. (CVE-2018-25032)

  - zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a
    large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some
    common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g.,
    see the nodejs/node reference). (CVE-2022-37434)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://advisory.splunk.com/advisories/SVD-2023-0614.html");
  script_set_attribute(attribute:"solution", value:
"For Splunk Universal Forwarder, upgrade versions to 8.1.14, 8.2.11, 9.0.5, or higher.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:universal_forwarder");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin", "splunk_nix_installed.nbin", "splunk_universal_forwarder_nix_installed.nbin", "splunk_universal_forwarder_win_installed.nbin");
  script_require_ports("installed_sw/Splunk", "installed_sw/Splunk Universal Forwarder");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'fixed_version' : '8.1.14', 'license' : 'Forwarder' },
  { 'min_version' : '8.2.0', 'fixed_version' : '8.2.11', 'license' : 'Forwarder' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.5', 'license' : 'Forwarder' }
];
vcf::splunk::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
