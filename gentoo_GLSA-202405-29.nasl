#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-29.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(195166);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/08");

  script_cve_id(
    "CVE-2020-7774",
    "CVE-2021-3672",
    "CVE-2021-22883",
    "CVE-2021-22884",
    "CVE-2021-22918",
    "CVE-2021-22930",
    "CVE-2021-22931",
    "CVE-2021-22939",
    "CVE-2021-22940",
    "CVE-2021-22959",
    "CVE-2021-22960",
    "CVE-2021-37701",
    "CVE-2021-37712",
    "CVE-2021-39134",
    "CVE-2021-39135",
    "CVE-2021-44531",
    "CVE-2021-44532",
    "CVE-2021-44533",
    "CVE-2022-0778",
    "CVE-2022-3602",
    "CVE-2022-3786",
    "CVE-2022-21824",
    "CVE-2022-32212",
    "CVE-2022-32213",
    "CVE-2022-32214",
    "CVE-2022-32215",
    "CVE-2022-32222",
    "CVE-2022-35255",
    "CVE-2022-35256",
    "CVE-2022-35948",
    "CVE-2022-35949",
    "CVE-2022-43548",
    "CVE-2023-30581",
    "CVE-2023-30582",
    "CVE-2023-30583",
    "CVE-2023-30584",
    "CVE-2023-30586",
    "CVE-2023-30587",
    "CVE-2023-30588",
    "CVE-2023-30589",
    "CVE-2023-30590",
    "CVE-2023-32002",
    "CVE-2023-32003",
    "CVE-2023-32004",
    "CVE-2023-32005",
    "CVE-2023-32006",
    "CVE-2023-32558",
    "CVE-2023-32559"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2022-0036");

  script_name(english:"GLSA-202405-29 : Node.js: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-29 (Node.js: Multiple Vulnerabilities)

  - The package y18n before 3.2.2, 4.0.1 and 5.0.5, is vulnerable to Prototype Pollution. (CVE-2020-7774)

  - A flaw was found in c-ares library, where a missing input validation check of host names returned by DNS
    (Domain Name Servers) can lead to output of wrong hostnames which might potentially lead to Domain
    Hijacking. The highest threat from this vulnerability is to confidentiality and integrity as well as
    system availability. (CVE-2021-3672)

  - Node.js before 10.24.0, 12.21.0, 14.16.0, and 15.10.0 is vulnerable to a denial of service attack when too
    many connection attempts with an 'unknownProtocol' are established. This leads to a leak of file
    descriptors. If a file descriptor limit is configured on the system, then the server is unable to accept
    new connections and prevent the process also from opening, e.g. a file. If no file descriptor limit is
    configured, then this lead to an excessive memory usage and cause the system to run out of memory.
    (CVE-2021-22883)

  - Node.js before 10.24.0, 12.21.0, 14.16.0, and 15.10.0 is vulnerable to DNS rebinding attacks as the
    whitelist includes localhost6. When localhost6 is not present in /etc/hosts, it is just an ordinary
    domain that is resolved via DNS, i.e., over network. If the attacker controls the victim's DNS server or
    can spoof its responses, the DNS rebinding protection can be bypassed by using the localhost6 domain. As
    long as the attacker uses the localhost6 domain, they can still apply the attack described in
    CVE-2018-7160. (CVE-2021-22884)

  - Node.js before 16.4.1, 14.17.2, 12.22.2 is vulnerable to an out-of-bounds read when uv__idna_toascii() is
    used to convert strings to ASCII. The pointer p is read and increased without checking whether it is
    beyond pe, with the latter holding a pointer to the end of the buffer. This can lead to information
    disclosures or crashes. This function can be triggered via uv_getaddrinfo(). (CVE-2021-22918)

  - Node.js before 16.6.0, 14.17.4, and 12.22.4 is vulnerable to a use after free attack where an attacker
    might be able to exploit the memory corruption, to change process behavior. (CVE-2021-22930)

  - Node.js before 16.6.0, 14.17.4, and 12.22.4 is vulnerable to Remote Code Execution, XSS, Application
    crashes due to missing input validation of host names returned by Domain Name Servers in Node.js dns
    library which can lead to output of wrong hostnames (leading to Domain Hijacking) and injection
    vulnerabilities in applications using the library. (CVE-2021-22931)

  - If the Node.js https API was used incorrectly and undefined was in passed for the rejectUnauthorized
    parameter, no error was returned and connections to servers with an expired certificate would have been
    accepted. (CVE-2021-22939)

  - Node.js before 16.6.1, 14.17.5, and 12.22.5 is vulnerable to a use after free attack where an attacker
    might be able to exploit the memory corruption, to change process behavior. (CVE-2021-22940)

  - The parser in accepts requests with a space (SP) right after the header name before the colon. This can
    lead to HTTP Request Smuggling (HRS) in llhttp < v2.1.4 and < v6.0.6. (CVE-2021-22959)

  - The parse function in llhttp < 2.1.4 and < 6.0.6. ignores chunk extensions when parsing the body of
    chunked requests. This leads to HTTP Request Smuggling (HRS) under certain conditions. (CVE-2021-22960)

  - The npm package tar (aka node-tar) before versions 4.4.16, 5.0.8, and 6.1.7 has an arbitrary file
    creation/overwrite and arbitrary code execution vulnerability. node-tar aims to guarantee that any file
    whose location would be modified by a symbolic link is not extracted. This is, in part, achieved by
    ensuring that extracted directories are not symlinks. Additionally, in order to prevent unnecessary stat
    calls to determine whether a given path is a directory, paths are cached when directories are created.
    This logic was insufficient when extracting tar files that contained both a directory and a symlink with
    the same name as the directory, where the symlink and directory names in the archive entry used
    backslashes as a path separator on posix systems. The cache checking logic used both `\` and `/`
    characters as path separators, however `\` is a valid filename character on posix systems. By first
    creating a directory, and then replacing that directory with a symlink, it was thus possible to bypass
    node-tar symlink checks on directories, essentially allowing an untrusted tar file to symlink into an
    arbitrary location and subsequently extracting arbitrary files into that location, thus allowing arbitrary
    file creation and overwrite. Additionally, a similar confusion could arise on case-insensitive
    filesystems. If a tar archive contained a directory at `FOO`, followed by a symbolic link named `foo`,
    then on case-insensitive file systems, the creation of the symbolic link would remove the directory from
    the filesystem, but _not_ from the internal directory cache, as it would not be treated as a cache hit. A
    subsequent file entry within the `FOO` directory would then be placed in the target of the symbolic link,
    thinking that the directory had already been created. These issues were addressed in releases 4.4.16,
    5.0.8 and 6.1.7. The v3 branch of node-tar has been deprecated and did not receive patches for these
    issues. If you are still using a v3 release we recommend you update to a more recent version of node-tar.
    If this is not possible, a workaround is available in the referenced GHSA-9r2w-394v-53qc. (CVE-2021-37701)

  - The npm package tar (aka node-tar) before versions 4.4.18, 5.0.10, and 6.1.9 has an arbitrary file
    creation/overwrite and arbitrary code execution vulnerability. node-tar aims to guarantee that any file
    whose location would be modified by a symbolic link is not extracted. This is, in part, achieved by
    ensuring that extracted directories are not symlinks. Additionally, in order to prevent unnecessary stat
    calls to determine whether a given path is a directory, paths are cached when directories are created.
    This logic was insufficient when extracting tar files that contained both a directory and a symlink with
    names containing unicode values that normalized to the same value. Additionally, on Windows systems, long
    path portions would resolve to the same file system entities as their 8.3 short path counterparts. A
    specially crafted tar archive could thus include a directory with one form of the path, followed by a
    symbolic link with a different string that resolves to the same file system entity, followed by a file
    using the first form. By first creating a directory, and then replacing that directory with a symlink that
    had a different apparent name that resolved to the same entry in the filesystem, it was thus possible to
    bypass node-tar symlink checks on directories, essentially allowing an untrusted tar file to symlink into
    an arbitrary location and subsequently extracting arbitrary files into that location, thus allowing
    arbitrary file creation and overwrite. These issues were addressed in releases 4.4.18, 5.0.10 and 6.1.9.
    The v3 branch of node-tar has been deprecated and did not receive patches for these issues. If you are
    still using a v3 release we recommend you update to a more recent version of node-tar. If this is not
    possible, a workaround is available in the referenced GHSA-qq89-hq3f-393p. (CVE-2021-37712)

  - `@npmcli/arborist`, the library that calculates dependency trees and manages the `node_modules` folder
    hierarchy for the npm command line interface, aims to guarantee that package dependency contracts will be
    met, and the extraction of package contents will always be performed into the expected folder. This is, in
    part, accomplished by resolving dependency specifiers defined in `package.json` manifests for dependencies
    with a specific name, and nesting folders to resolve conflicting dependencies. When multiple dependencies
    differ only in the case of their name, Arborist's internal data structure saw them as separate items that
    could coexist within the same level in the `node_modules` hierarchy. However, on case-insensitive file
    systems (such as macOS and Windows), this is not the case. Combined with a symlink dependency such as
    `file:/some/path`, this allowed an attacker to create a situation in which arbitrary contents could be
    written to any location on the filesystem. For example, a package `pwn-a` could define a dependency in
    their `package.json` file such as `foo: file:/some/path`. Another package, `pwn-b` could define a
    dependency such as `FOO: file:foo.tgz`. On case-insensitive file systems, if `pwn-a` was installed, and
    then `pwn-b` was installed afterwards, the contents of `foo.tgz` would be written to `/some/path`, and any
    existing contents of `/some/path` would be removed. Anyone using npm v7.20.6 or earlier on a case-
    insensitive filesystem is potentially affected. This is patched in @npmcli/arborist 2.8.2 which is
    included in npm v7.20.7 and above. (CVE-2021-39134)

  - `@npmcli/arborist`, the library that calculates dependency trees and manages the node_modules folder
    hierarchy for the npm command line interface, aims to guarantee that package dependency contracts will be
    met, and the extraction of package contents will always be performed into the expected folder. This is
    accomplished by extracting package contents into a project's `node_modules` folder. If the `node_modules`
    folder of the root project or any of its dependencies is somehow replaced with a symbolic link, it could
    allow Arborist to write package dependencies to any arbitrary location on the file system. Note that
    symbolic links contained within package artifact contents are filtered out, so another means of creating a
    `node_modules` symbolic link would have to be employed. 1. A `preinstall` script could replace
    `node_modules` with a symlink. (This is prevented by using `--ignore-scripts`.) 2. An attacker could
    supply the target with a git repository, instructing them to run `npm install --ignore-scripts` in the
    root. This may be successful, because `npm install --ignore-scripts` is typically not capable of making
    changes outside of the project directory, so it may be deemed safe. This is patched in @npmcli/arborist
    2.8.2 which is included in npm v7.20.7 and above. For more information including workarounds please see
    the referenced GHSA-gmw6-94gg-2rc2. (CVE-2021-39135)

  - Accepting arbitrary Subject Alternative Name (SAN) types, unless a PKI is specifically defined to use a
    particular SAN type, can result in bypassing name-constrained intermediates. Node.js < 12.22.9, < 14.18.3,
    < 16.13.2, and < 17.3.1 was accepting URI SAN types, which PKIs are often not defined to use.
    Additionally, when a protocol allows URI SANs, Node.js did not match the URI correctly.Versions of Node.js
    with the fix for this disable the URI SAN type when checking a certificate against a hostname. This
    behavior can be reverted through the --security-revert command-line option. (CVE-2021-44531)

  - Node.js < 12.22.9, < 14.18.3, < 16.13.2, and < 17.3.1 converts SANs (Subject Alternative Names) to a
    string format. It uses this string to check peer certificates against hostnames when validating
    connections. The string format was subject to an injection vulnerability when name constraints were used
    within a certificate chain, allowing the bypass of these name constraints.Versions of Node.js with the fix
    for this escape SANs containing the problematic characters in order to prevent the injection. This
    behavior can be reverted through the --security-revert command-line option. (CVE-2021-44532)

  - Node.js < 12.22.9, < 14.18.3, < 16.13.2, and < 17.3.1 did not handle multi-value Relative Distinguished
    Names correctly. Attackers could craft certificate subjects containing a single-value Relative
    Distinguished Name that would be interpreted as a multi-value Relative Distinguished Name, for example, in
    order to inject a Common Name that would allow bypassing the certificate subject verification.Affected
    versions of Node.js that do not accept multi-value Relative Distinguished Names and are thus not
    vulnerable to such attacks themselves. However, third-party code that uses node's ambiguous presentation
    of certificate subjects may be vulnerable. (CVE-2021-44533)

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed the malicious certificate or for the application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to
    overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash
    (causing a denial of service) or potentially remote code execution. Many platforms implement stack
    overflow protections which would mitigate against the risk of remote code execution. The risk may be
    further mitigated based on stack layout for any given platform/compiler. Pre-announcements of
    CVE-2022-3602 described this issue as CRITICAL. Further analysis based on some of the mitigating factors
    described above have led this to be downgraded to HIGH. Users are still encouraged to upgrade to a new
    version as soon as possible. In a TLS client, this can be triggered by connecting to a malicious server.
    In a TLS server, this can be triggered if the server requests client authentication and a malicious client
    connects. Fixed in OpenSSL 3.0.7 (Affected 3.0.0,3.0.1,3.0.2,3.0.3,3.0.4,3.0.5,3.0.6). (CVE-2022-3602)

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed a malicious certificate or for an application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a
    certificate to overflow an arbitrary number of bytes containing the `.' character (decimal 46) on the
    stack. This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this
    can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server
    requests client authentication and a malicious client connects. (CVE-2022-3786)

  - Due to the formatting logic of the console.table() function it was not safe to allow user controlled
    input to be passed to the properties parameter while simultaneously passing a plain object with at least
    one property as the first parameter, which could be __proto__. The prototype pollution has very limited
    control, in that it only allows an empty string to be assigned to numerical keys of the object
    prototype.Node.js >= 12.22.9, >= 14.18.3, >= 16.13.2, and >= 17.3.1 use a null protoype for the object
    these properties are being assigned to. (CVE-2022-21824)

  - A OS Command Injection vulnerability exists in Node.js versions <14.20.0, <16.20.0, <18.5.0 due to an
    insufficient IsAllowedHost check that can easily be bypassed because IsIPAddress does not properly check
    if an IP address is invalid before making DBS requests allowing rebinding attacks. (CVE-2022-32212)

  - The llhttp parser <v14.20.1, <v16.17.1 and <v18.9.1 in the http module in Node.js does not correctly parse
    and validate Transfer-Encoding headers and can lead to HTTP Request Smuggling (HRS). (CVE-2022-32213)

  - The llhttp parser <v14.20.1, <v16.17.1 and <v18.9.1 in the http module in Node.js does not strictly use
    the CRLF sequence to delimit HTTP requests. This can lead to HTTP Request Smuggling (HRS).
    (CVE-2022-32214)

  - The llhttp parser <v14.20.1, <v16.17.1 and <v18.9.1 in the http module in Node.js does not correctly
    handle multi-line Transfer-Encoding headers. This can lead to HTTP Request Smuggling (HRS).
    (CVE-2022-32215)

  - A cryptographic vulnerability exists on Node.js on linux in versions of 18.x prior to 18.40.0 which
    allowed a default path for openssl.cnf that might be accessible under some circumstances to a non-admin
    user instead of /etc/ssl as was the case in versions prior to the upgrade to OpenSSL 3. (CVE-2022-32222)

  - A weak randomness in WebCrypto keygen vulnerability exists in Node.js 18 due to a change with
    EntropySource() in SecretKeyGenTraits::DoKeyGen() in src/crypto/crypto_keygen.cc. There are two problems
    with this: 1) It does not check the return value, it assumes EntropySource() always succeeds, but it can
    (and sometimes will) fail. 2) The random data returned byEntropySource() may not be cryptographically
    strong and therefore not suitable as keying material. (CVE-2022-35255)

  - The llhttp parser in the http module in Node v18.7.0 does not correctly handle header fields that are not
    terminated with CLRF. This may result in HTTP Request Smuggling. (CVE-2022-35256)

  - undici is an HTTP/1.1 client, written from scratch for Node.js.`=< undici@5.8.0` users are vulnerable to
    _CRLF Injection_ on headers when using unsanitized input as request headers, more specifically, inside the
    `content-type` header. Example: ``` import { request } from 'undici' const unsanitizedContentTypeInput =
    'application/json\r\n\r\nGET /foo2 HTTP/1.1' await request('http://localhost:3000, { method: 'GET',
    headers: { 'content-type': unsanitizedContentTypeInput }, }) ``` The above snippet will perform two
    requests in a single `request` API call: 1) `http://localhost:3000/` 2) `http://localhost:3000/foo2` This
    issue was patched in Undici v5.8.1. Sanitize input when sending content-type headers using user input as a
    workaround. (CVE-2022-35948)

  - undici is an HTTP/1.1 client, written from scratch for Node.js.`undici` is vulnerable to SSRF (Server-side
    Request Forgery) when an application takes in **user input** into the `path/pathname` option of
    `undici.request`. If a user specifies a URL such as `http://127.0.0.1` or `//127.0.0.1` ```js const undici
    = require(undici) undici.request({origin: http://example.com, pathname: //127.0.0.1}) ``` Instead of
    processing the request as `http://example.org//127.0.0.1` (or `http://example.org/http://127.0.0.1` when
    `http://127.0.0.1 is used`), it actually processes the request as `http://127.0.0.1/` and sends it to
    `http://127.0.0.1`. If a developer passes in user input into `path` parameter of `undici.request`, it can
    result in an _SSRF_ as they will assume that the hostname cannot change, when in actual fact it can change
    because the specified path parameter is combined with the base URL. This issue was fixed in
    `undici@5.8.1`. The best workaround is to validate user input before passing it to the `undici.request`
    call. (CVE-2022-35949)

  - A OS Command Injection vulnerability exists in Node.js versions <14.21.1, <16.18.1, <18.12.1, <19.0.1 due
    to an insufficient IsAllowedHost check that can easily be bypassed because IsIPAddress does not properly
    check if an IP address is invalid before making DBS requests allowing rebinding attacks.The fix for this
    issue in https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32212 was incomplete and this new CVE is
    to complete the fix. (CVE-2022-43548)

  - The use of __proto__ in process.mainModule.__proto__.require() can bypass the policy mechanism and require
    modules outside of the policy.json definition. This vulnerability affects all users using the experimental
    policy mechanism in all active release lines: v16, v18 and, v20. Please note that at the time this CVE was
    issued, the policy is an experimental feature of Node.js (CVE-2023-30581)

  - A privilege escalation vulnerability exists in Node.js 20 that allowed loading arbitrary OpenSSL engines
    when the experimental permission model is enabled, which can bypass and/or disable the permission model.
    The attack complexity is high. However, the crypto.setEngine() API can be used to bypass the permission
    model when called with a compatible OpenSSL engine. The OpenSSL engine can, for example, disable the
    permission model in the host process by manipulating the process's stack memory to locate the permission
    model Permission::enabled_ in the host process's heap memory. Please note that at the time this CVE was
    issued, the permission model is an experimental feature of Node.js. (CVE-2023-30586)

  - When an invalid public key is used to create an x509 certificate using the crypto.X509Certificate() API a
    non-expect termination occurs making it susceptible to DoS attacks when the attacker could force
    interruptions of application processing, as the process terminates when accessing public key info of
    provided certificates from user code. The current context of the users will be gone, and that will cause a
    DoS scenario. This vulnerability affects all active Node.js versions v16, v18, and, v20. (CVE-2023-30588)

  - The llhttp parser in the http module in Node v20.2.0 does not strictly use the CRLF sequence to delimit
    HTTP requests. This can lead to HTTP Request Smuggling (HRS). The CR character (without LF) is sufficient
    to delimit HTTP header fields in the llhttp parser. According to RFC7230 section 3, only the CRLF sequence
    should delimit each header-field. This impacts all Node.js active versions: v16, v18, and, v20
    (CVE-2023-30589)

  - The generateKeys() API function returned from crypto.createDiffieHellman() only generates missing (or
    outdated) keys, that is, it only generates a private key if none has been set yet, but the function is
    also needed to compute the corresponding public key after calling setPrivateKey(). However, the
    documentation says this API call: Generates private and public Diffie-Hellman key values. The documented
    behavior is very different from the actual behavior, and this difference could easily lead to security
    issues in applications that use these APIs as the DiffieHellman may be used as the basis for application-
    level security, implications are consequently broad. (CVE-2023-30590)

  - The use of `Module._load()` can bypass the policy mechanism and require modules outside of the policy.json
    definition for a given module. This vulnerability affects all users using the experimental policy
    mechanism in all active release lines: 16.x, 18.x and, 20.x. Please note that at the time this CVE was
    issued, the policy is an experimental feature of Node.js. (CVE-2023-32002)

  - `fs.mkdtemp()` and `fs.mkdtempSync()` can be used to bypass the permission model check using a path
    traversal attack. This flaw arises from a missing check in the fs.mkdtemp() API and the impact is a
    malicious actor could create an arbitrary directory. This vulnerability affects all users using the
    experimental permission model in Node.js 20. Please note that at the time this CVE was issued, the
    permission model is an experimental feature of Node.js. (CVE-2023-32003)

  - A vulnerability has been discovered in Node.js version 20, specifically within the experimental permission
    model. This flaw relates to improper handling of Buffers in file system APIs causing a traversal path to
    bypass when verifying file permissions. This vulnerability affects all users using the experimental
    permission model in Node.js 20. Please note that at the time this CVE was issued, the permission model is
    an experimental feature of Node.js. (CVE-2023-32004)

  - A vulnerability has been identified in Node.js version 20, affecting users of the experimental permission
    model when the --allow-fs-read flag is used with a non-* argument. This flaw arises from an inadequate
    permission model that fails to restrict file stats through the `fs.statfs` API. As a result, malicious
    actors can retrieve stats from files that they do not have explicit read access to. This vulnerability
    affects all users using the experimental permission model in Node.js 20. Please note that at the time this
    CVE was issued, the permission model is an experimental feature of Node.js. (CVE-2023-32005)

  - The use of `module.constructor.createRequire()` can bypass the policy mechanism and require modules
    outside of the policy.json definition for a given module. This vulnerability affects all users using the
    experimental policy mechanism in all active release lines: 16.x, 18.x, and, 20.x. Please note that at the
    time this CVE was issued, the policy is an experimental feature of Node.js. (CVE-2023-32006)

  - The use of the deprecated API `process.binding()` can bypass the permission model through path traversal.
    This vulnerability affects all users using the experimental permission model in Node.js 20.x. Please note
    that at the time this CVE was issued, the permission model is an experimental feature of Node.js.
    (CVE-2023-32558)

  - A privilege escalation vulnerability exists in the experimental policy mechanism in all active release
    lines: 16.x, 18.x and, 20.x. The use of the deprecated API `process.binding()` can bypass the policy
    mechanism by requiring internal modules and eventually take advantage of `process.binding('spawn_sync')`
    run arbitrary code, outside of the limits defined in a `policy.json` file. Please note that at the time
    this CVE was issued, the policy is an experimental feature of Node.js. (CVE-2023-32559)

  - A vulnerability has been identified in Node.js version 20, affecting users of the experimental permission
    model when the --allow-fs-read flag is used with a non-* argument. This flaw arises from an inadequate
    permission model that fails to restrict file watching through the fs.watchFile API. As a result, malicious
    actors can monitor files that they do not have explicit read access to. This vulnerability affects all
    users using the experimental permission model in Node.js 20. Please note that at the time this CVE was
    issued, the permission model is an experimental feature of Node.js. Thanks to Colin Ihrig for reporting
    this vulnerability and to Rafael Gonzaga for fixing it. (CVE-2023-30582)

  - fs.openAsBlob() can bypass the experimental permission model when using the file system read restriction
    with the --allow-fs-read flag in Node.js 20. This flaw arises from a missing check in the fs.openAsBlob()
    API. This vulnerability affects all users using the experimental permission model in Node.js 20. Thanks to
    Colin Ihrig for reporting this vulnerability and to Rafael Gonzaga for fixing it. Please note that at the
    time this CVE was issued, the permission model is an experimental feature of Node.js. (CVE-2023-30583)

  - A vulnerability has been discovered in Node.js version 20, specifically within the experimental permission
    model. This flaw relates to improper handling of path traversal bypass when verifying file permissions.
    This vulnerability affects all users using the experimental permission model in Node.js 20. Please note
    that at the time this CVE was issued, the permission model is an experimental feature of Node.js. Thank
    you, to Axel Chong for reporting this vulnerability and thank you Rafael Gonzaga for fixing it.
    (CVE-2023-30584)

  - A vulnerability in Node.js version 20 allows for bypassing restrictions set by the --experimental-
    permission flag using the built-in inspector module (node:inspector). By exploiting the Worker class's
    ability to create an internal worker with the kIsInternal Symbol, attackers can modify the isInternal
    value when an inspector is attached within the Worker constructor before initializing a new WorkerImpl.
    This vulnerability exclusively affects Node.js users employing the permission model mechanism in Node.js
    20. Please note that at the time this CVE was issued, the permission model is an experimental feature of
    Node.js. Thank you, to mattaustin for reporting this vulnerability and thank you Rafael Gonzaga for fixing
    it. (CVE-2023-30587)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-29");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=772422");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=781704");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=800986");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=805053");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807775");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=811273");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=817938");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831037");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835615");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=857111");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=865627");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=872692");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=879617");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918086");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=918614");
  script_set_attribute(attribute:"solution", value:
"All Node.js 20 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-libs/nodejs-20.5.1
        
All Node.js 18 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-libs/nodejs-18.17.1
        
All Node.js 16 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-libs/nodejs-16.20.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22931");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-32002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'net-libs/nodejs',
    'unaffected' : make_list("ge 16.20.2", "lt 16.0.0"),
    'vulnerable' : make_list("lt 16.20.2")
  },
  {
    'name' : 'net-libs/nodejs',
    'unaffected' : make_list("ge 18.17.1", "lt 18.0.0"),
    'vulnerable' : make_list("lt 18.17.1")
  },
  {
    'name' : 'net-libs/nodejs',
    'unaffected' : make_list("ge 20.5.1", "lt 20.0.0"),
    'vulnerable' : make_list("lt 20.5.1")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Node.js');
}
