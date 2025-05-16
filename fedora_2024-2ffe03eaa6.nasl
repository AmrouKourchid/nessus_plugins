#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-2ffe03eaa6
#

include('compat.inc');

if (description)
{
  script_id(194592);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2024-27982", "CVE-2024-27983");
  script_xref(name:"FEDORA", value:"2024-2ffe03eaa6");

  script_name(english:"Fedora 40 : nodejs20 (2024-2ffe03eaa6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-2ffe03eaa6 advisory.

    ## 2024-04-03, Version 20.12.1 'Iron' (LTS), @RafaelGSS

    This is a security release

    ### Notable Changes

    * CVE-2024-27983 - Assertion failed in node::http2::Http2Session::\~Http2Session() leads to HTTP/2 server
    crash- (High)
    * CVE-2024-27982 - HTTP Request Smuggling via Content Length Obfuscation - (Medium)
    * llhttp version 9.2.1
    * undici version 5.28.4

    ### Commits

    * \[[`bd8f10a257`](https://github.com/nodejs/node/commit/bd8f10a257)] - **deps**: update undici to v5.28.4
    (Matteo Collina) [nodejs-private/node-private#576](https://github.com/nodejs-private/node-
    private/pull/576)
    * \[[`5e34540a96`](https://github.com/nodejs/node/commit/5e34540a96)] - **http**: do not allow OBS fold in
    headers by default (Paolo Insogna) [nodejs-private/node-private#557](https://github.com/nodejs-
    private/node-private/pull/557)
    * \[[`ba1ae6d188`](https://github.com/nodejs/node/commit/ba1ae6d188)] - **src**: ensure to close stream
    when destroying session (Anna Henningsen) [nodejs-private/node-private#561](https://github.com/nodejs-
    private/node-private/pull/561)

    ----

    ## 2024-04-03, Version 20.12.1 'Iron' (LTS), @RafaelGSS

    This is a security release

    ### Notable Changes

    * CVE-2024-27983 - Assertion failed in node::http2::Http2Session::\~Http2Session() leads to HTTP/2 server
    crash- (High)
    * CVE-2024-27982 - HTTP Request Smuggling via Content Length Obfuscation - (Medium)
    * llhttp version 9.2.1
    * undici version 5.28.4


    ----

    ## 2024-03-26, Version 20.12.0 'Iron' (LTS), @richardlau

    ### Notable Changes

    #### crypto: implement crypto.hash()

    This patch introduces a helper crypto.hash() that computes
    a digest from the input at one shot. This can be 1.2-2x faster
    than the object-based createHash() for smaller inputs (<= 5MB)
    that are readily available (not streamed) and incur less memory
    overhead since no intermediate objects will be created.

    ```js
    const crypto = require('node:crypto');

    // Hashing a string and return the result as a hex-encoded string.
    const string = 'Node.js';
    // 10b3493287f831e81a438811a1ffba01f8cec4b7
    console.log(crypto.hash('sha1', string));
    ```

    Contributed by Joyee Cheung in [#51044](https://github.com/nodejs/node/pull/51044).

    #### Loading and parsing environment variables

    * `process.loadEnvFile(path)`:
      * Use this function to load the `.env` file. If no path is specified, it automatically loads the .env
    file in the current directory. Example: `process.loadEnvFile()`.
      * Load a specific .env file by specifying its path. Example: `process.loadEnvFile('./development.env')`.

    * `util.parseEnv(content)`:
      * Use this function to parse an existing string containing environment variable assignments.
      * Example usage: `require('node:util').parseEnv('HELLO=world')`.

    Contributed by Yagiz Nizipli in [#51476](https://github.com/nodejs/node/pull/51476).

    #### New connection attempt events

    Three new events were added in the `net.createConnection` flow:

    * `connectionAttempt`: Emitted when a new connection attempt is established. In case of Happy Eyeballs,
    this might emitted multiple times.
    * `connectionAttemptFailed`: Emitted when a connection attempt failed. In case of Happy Eyeballs, this
    might emitted multiple times.
    * `connectionAttemptTimeout`: Emitted when a connection attempt timed out. In case of Happy Eyeballs, this
    will not be emitted for the last attempt. This is not emitted at all if Happy Eyeballs is not used.

    Additionally, a previous bug has been fixed where a new connection attempt could have been started after a
    previous one failed and after the connection was destroyed by the user.
    This led to a failed assertion.

    Contributed by Paolo Insogna in [#51045](https://github.com/nodejs/node/pull/51045).

    #### Permission Model changes

    Node.js 20.12.0 comes with several fixes for the experimental permission model and two new semver-minor
    commits.
    We're adding a new flag `--allow-addons` to enable addon usage when using the Permission Model.

    ```console
    $ node --experimental-permission --allow-addons
    ```

    Contributed by Rafael Gonzaga in [#51183](https://github.com/nodejs/node/pull/51183)

    And relative paths are now supported through the `--allow-fs-*` flags.
    Therefore, with this release one can use:

    ```console
    $ node --experimental-permission --allow-fs-read=./index.js
    ```

    To give only read access to the entrypoint of the application.

    Contributed by Rafael Gonzaga and Carlos Espa in [#50758](https://github.com/nodejs/node/pull/50758).

    #### sea: support embedding assets

    Users can now include assets by adding a key-path dictionary
    to the configuration as the `assets` field. At build time, Node.js
    would read the assets from the specified paths and bundle them into
    the preparation blob. In the generated executable, users can retrieve
    the assets using the `sea.getAsset()` and `sea.getAssetAsBlob()` API.

    ```json
    {
      main: /path/to/bundled/script.js,
      output: /path/to/write/the/generated/blob.blob,
      assets: {
        a.jpg: /path/to/a.jpg,
        b.txt: /path/to/b.txt
      }
    }
    ```

    The single-executable application can access the assets as follows:

    ```cjs
    const { getAsset } = require('node:sea');
    // Returns a copy of the data in an ArrayBuffer
    const image = getAsset('a.jpg');
    // Returns a string decoded from the asset as UTF8.
    const text = getAsset('b.txt', 'utf8');
    // Returns a Blob containing the asset without copying.
    const blob = getAssetAsBlob('a.jpg');
    ```

    Contributed by Joyee Cheung in [#50960](https://github.com/nodejs/node/pull/50960).

    #### Support configurable snapshot through `--build-snapshot-config` flag

    We are adding a new flag `--build-snapshot-config` to configure snapshots through a custom JSON
    configuration file.

    ```console
    $ node --build-snapshot-config=/path/to/myconfig.json
    ```

    When using this flag, additional script files provided on the command line will
    not be executed and instead be interpreted as regular command line arguments.

    These changes were contributed by Joyee Cheung and Anna Henningsen in
    [#50453](https://github.com/nodejs/node/pull/50453)

    #### Text Styling

    * `util.styleText(format, text)`: This function returns a formatted text considering the `format` passed.

    A new API has been created to format text based on `util.inspect.colors`, enabling you to style text in
    different colors (such as red, blue, ...) and emphasis (italic, bold, ...).

    ```cjs
    const { styleText } = require('node:util');
    const errorMessage = styleText('red', 'Error! Error!');
    console.log(errorMessage);
    ```

    Contributed by Rafael Gonzaga in [#51850](https://github.com/nodejs/node/pull/51850).

    #### vm: support using the default loader to handle dynamic import()

    This patch adds support for using `vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER` as the
    `importModuleDynamically` option in all vm APIs that take this option except `vm.SourceTextModule`. This
    allows users to have a shortcut to support dynamic `import()` in the compiled code without missing the
    compilation cache if they don't need customization of the loading process. We emit an experimental warning
    when the `import()` is actually handled by the default loader through this option instead of requiring
    `--experimental-vm-modules`.

    ```js
    const { Script, constants } = require('node:vm');
    const { resolve } = require('node:path');
    const { writeFileSync } = require('node:fs');

    // Write test.js and test.txt to the directory where the current script
    // being run is located.
    writeFileSync(resolve(__dirname, 'test.mjs'),
                  'export const filename = ./test.json;');
    writeFileSync(resolve(__dirname, 'test.json'),
                  '{hello: world}');

    // Compile a script that loads test.mjs and then test.json
    // as if the script is placed in the same directory.
    const script = new Script(
      `(async function() {
        const { filename } = await import('./test.mjs');
        return import(filename, { with: { type: 'json' } })
      })();`,
      {
        filename: resolve(__dirname, 'test-with-default.js'),
        importModuleDynamically: constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
      });

    // { default: { hello: 'world' } }
    script.runInThisContext().then(console.log);
    ```

    Contributed by Joyee Cheung in [#51244](https://github.com/nodejs/node/pull/51244).

    #### Root certificates updated to NSS 3.98

    Certificates added:

    * Telekom Security TLS ECC Root 2020
    * Telekom Security TLS RSA Root 2023

    Certificates removed:

    * Security Communication Root CA

    #### Updated dependencies

    * acorn updated to 8.11.3.
    * ada updated to 2.7.6.
    * base64 updated to 0.5.2.
    * brotli updated to 1.1.0.
    * c-ares updated to 1.27.0.
    * corepack updated to 0.25.2.
    * ICU updated to 74.2. Includes CLDR 44.1 and Unicode 15.1.
    * nghttp2 updated to 1.60.0.
    * npm updated to 10.5.0. Fixes a regression in signals not being passed onto child processes.
    * simdutf8 updated to 4.0.8.
    * Timezone updated to 2024a.
    * zlib updated to 1.3.0.1-motley-40e35a7.

    ----

    Include `Provides: nodejs20-*` for non-versioned packages.


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-2ffe03eaa6");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:nodejs20 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27982");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-27983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'nodejs20-20.12.2-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs20');
}
