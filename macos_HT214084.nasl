#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191713);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id(
    "CVE-2022-42816",
    "CVE-2022-48554",
    "CVE-2023-42853",
    "CVE-2023-48795",
    "CVE-2023-51384",
    "CVE-2023-51385",
    "CVE-2024-0258",
    "CVE-2024-23205",
    "CVE-2024-23216",
    "CVE-2024-23225",
    "CVE-2024-23226",
    "CVE-2024-23227",
    "CVE-2024-23229",
    "CVE-2024-23230",
    "CVE-2024-23231",
    "CVE-2024-23232",
    "CVE-2024-23233",
    "CVE-2024-23234",
    "CVE-2024-23235",
    "CVE-2024-23238",
    "CVE-2024-23239",
    "CVE-2024-23241",
    "CVE-2024-23242",
    "CVE-2024-23244",
    "CVE-2024-23245",
    "CVE-2024-23246",
    "CVE-2024-23247",
    "CVE-2024-23248",
    "CVE-2024-23249",
    "CVE-2024-23250",
    "CVE-2024-23253",
    "CVE-2024-23254",
    "CVE-2024-23255",
    "CVE-2024-23257",
    "CVE-2024-23258",
    "CVE-2024-23259",
    "CVE-2024-23260",
    "CVE-2024-23261",
    "CVE-2024-23263",
    "CVE-2024-23264",
    "CVE-2024-23265",
    "CVE-2024-23266",
    "CVE-2024-23267",
    "CVE-2024-23268",
    "CVE-2024-23269",
    "CVE-2024-23270",
    "CVE-2024-23272",
    "CVE-2024-23273",
    "CVE-2024-23274",
    "CVE-2024-23275",
    "CVE-2024-23276",
    "CVE-2024-23277",
    "CVE-2024-23278",
    "CVE-2024-23279",
    "CVE-2024-23280",
    "CVE-2024-23281",
    "CVE-2024-23283",
    "CVE-2024-23284",
    "CVE-2024-23285",
    "CVE-2024-23286",
    "CVE-2024-23287",
    "CVE-2024-23288",
    "CVE-2024-23289",
    "CVE-2024-23290",
    "CVE-2024-23291",
    "CVE-2024-23292",
    "CVE-2024-23293",
    "CVE-2024-23294",
    "CVE-2024-23296",
    "CVE-2024-23299",
    "CVE-2024-27789",
    "CVE-2024-27792",
    "CVE-2024-27809",
    "CVE-2024-27853",
    "CVE-2024-27886",
    "CVE-2024-27887",
    "CVE-2024-27888"
  );
  script_xref(name:"APPLE-SA", value:"HT214084");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/27");
  script_xref(name:"IAVA", value:"2024-A-0142-S");
  script_xref(name:"IAVA", value:"2024-A-0275-S");
  script_xref(name:"IAVA", value:"2024-A-0455-S");
  script_xref(name:"IAVA", value:"2024-A-0578-S");

  script_name(english:"macOS 14.x < 14.4 Multiple Vulnerabilities (HT214084)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 14.x prior to 14.4. It is, therefore, affected by
multiple vulnerabilities:

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Ventura 13. An
    app may be able to modify protected parts of the file system. (CVE-2022-42816)

  - File before 5.43 has an stack-based buffer over-read in file_copystr in funcs.c. NOTE: File is the name
    of an Open Source project. (CVE-2022-48554)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.1, macOS Monterey
    12.7.1, macOS Ventura 13.6.1. An app may be able to access user-sensitive data. (CVE-2023-42853)

  - The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other
    products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the
    extension negotiation message), and a client and server may consequently end up with a connection for
    which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because
    the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and
    mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of
    ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and
    (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API
    before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80,
    AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0,
    Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15,
    SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH
    through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang
    XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd
    through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and
    LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3,
    Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server
    before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the
    mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh
    crate before 0.40.2 for Rust. (CVE-2023-48795)

  - In ssh-agent in OpenSSH before 9.6, certain destination constraints can be incompletely applied. When
    destination constraints are specified during addition of PKCS#11-hosted private keys, these constraints
    are only applied to the first key, even if a PKCS#11 token returns multiple keys. (CVE-2023-51384)

  - In ssh in OpenSSH before 9.6, OS command injection might occur if a user name or host name has shell
    metacharacters, and this name is referenced by an expansion token in certain situations. For example, an
    untrusted Git repository can have a submodule with shell metacharacters in a user name or host name.
    (CVE-2023-51385)

  - The issue was addressed with improved memory handling. This issue is fixed in tvOS 17.4, iOS 17.4 and
    iPadOS 17.4, macOS Sonoma 14.4, watchOS 10.4. An app may be able to execute arbitrary code out of its
    sandbox or with certain elevated privileges. (CVE-2024-0258)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Sonoma 14.4, iOS 17.4 and iPadOS 17.4. An app may be able to access sensitive user data.
    (CVE-2024-23205)

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Sonoma 14.4,
    macOS Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to overwrite arbitrary files.
    (CVE-2024-23216)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 16.7.6 and
    iPadOS 16.7.6, iOS 17.4 and iPadOS 17.4. An attacker with arbitrary kernel read and write capability may
    be able to bypass kernel memory protections. Apple is aware of a report that this issue may have been
    exploited. (CVE-2024-23225)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.4, visionOS
    1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, tvOS 17.4. Processing web content may lead to arbitrary code
    execution. (CVE-2024-23226)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Sonoma 14.4, macOS Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to read sensitive location
    information. (CVE-2024-23227)

  - This issue was addressed with improved redaction of sensitive information. This issue is fixed in macOS
    Monterey 12.7.5, macOS Ventura 13.6.5, macOS Sonoma 14.4. A malicious application may be able to access
    Find My data. (CVE-2024-23229)

  - This issue was addressed with improved file handling. This issue is fixed in macOS Sonoma 14.4, macOS
    Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to access sensitive user data. (CVE-2024-23230)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Ventura 13.6.5, macOS Sonoma 14.4, iOS 17.4 and iPadOS 17.4, watchOS 10.4, iOS 16.7.6 and iPadOS
    16.7.6. An app may be able to access user-sensitive data. (CVE-2024-23231)

  - A privacy issue was addressed with improved handling of temporary files. This issue is fixed in macOS
    Sonoma 14.4. An app may be able to capture a user's screen. (CVE-2024-23232)

  - This issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4. Entitlements and
    privacy permissions granted to this app may be used by a malicious app. (CVE-2024-23233)

  - An out-of-bounds write issue was addressed with improved input validation. This issue is fixed in macOS
    Sonoma 14.4, macOS Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to execute arbitrary code
    with kernel privileges. (CVE-2024-23234)

  - A race condition was addressed with additional validation. This issue is fixed in macOS Sonoma 14.4,
    visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, iOS 16.7.6 and iPadOS 16.7.6, tvOS 17.4. An app may
    be able to access user-sensitive data. (CVE-2024-23235)

  - An access issue was addressed with improved access restrictions. This issue is fixed in macOS Sonoma 14.4.
    An app may be able to edit NVRAM variables. (CVE-2024-23238)

  - A race condition was addressed with improved state handling. This issue is fixed in tvOS 17.4, iOS 17.4
    and iPadOS 17.4, macOS Sonoma 14.4, watchOS 10.4. An app may be able to leak sensitive user information.
    (CVE-2024-23239)

  - This issue was addressed through improved state management. This issue is fixed in tvOS 17.4, iOS 17.4 and
    iPadOS 17.4, macOS Sonoma 14.4. An app may be able to leak sensitive user information. (CVE-2024-23241)

  - A privacy issue was addressed by not logging contents of text fields. This issue is fixed in macOS Sonoma
    14.4, iOS 17.4 and iPadOS 17.4. An app may be able to view Mail data. (CVE-2024-23242)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Sonoma 14.4, macOS
    Monterey 12.7.4. An app from a standard user account may be able to escalate privilege after admin user
    login. (CVE-2024-23244)

  - This issue was addressed by adding an additional prompt for user consent. This issue is fixed in macOS
    Sonoma 14.4, macOS Monterey 12.7.4, macOS Ventura 13.6.5. Third-party shortcuts may use a legacy action
    from Automator to send events to apps without user consent. (CVE-2024-23245)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sonoma 14.4,
    visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, iOS 16.7.6 and iPadOS 16.7.6, tvOS 17.4. An app may
    be able to break out of its sandbox. (CVE-2024-23246)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.4, macOS
    Monterey 12.7.4, macOS Ventura 13.6.5. Processing a file may lead to unexpected app termination or
    arbitrary code execution. (CVE-2024-23247)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.4.
    Processing a file may lead to a denial-of-service or potentially disclose memory contents.
    (CVE-2024-23248, CVE-2024-23249)

  - An access issue was addressed with improved access restrictions. This issue is fixed in tvOS 17.4, iOS
    17.4 and iPadOS 17.4, macOS Sonoma 14.4, watchOS 10.4. An app may be able to access Bluetooth-connected
    microphones without user permission. (CVE-2024-23250)

  - A permissions issue was addressed with additional restrictions. This issue is fixed in macOS Sonoma 14.4.
    An app may be able to access a user's Photos Library. (CVE-2024-23253)

  - The issue was addressed with improved UI handling. This issue is fixed in tvOS 17.4, macOS Sonoma 14.4,
    visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, Safari 17.4. A malicious website may exfiltrate
    audio data cross-origin. (CVE-2024-23254)

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Sonoma
    14.4, iOS 17.4 and iPadOS 17.4. Photos in the Hidden Photos Album may be viewed without authentication.
    (CVE-2024-23255)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.7.4, macOS
    Ventura 13.6.5, macOS Sonoma 14.4, visionOS 1.1, iOS 16.7.6 and iPadOS 16.7.6. Processing an image may
    result in disclosure of process memory. (CVE-2024-23257)

  - An out-of-bounds read was addressed with improved input validation. This issue is fixed in visionOS 1.1,
    macOS Sonoma 14.4. Processing an image may lead to arbitrary code execution. (CVE-2024-23258)

  - The issue was addressed with improved checks. This issue is fixed in iOS 16.7.6 and iPadOS 16.7.6, iOS
    17.4 and iPadOS 17.4, macOS Sonoma 14.4. Processing web content may lead to a denial-of-service.
    (CVE-2024-23259)

  - This issue was addressed by removing additional entitlements. This issue is fixed in macOS Sonoma 14.4. An
    app may be able to access user-sensitive data. (CVE-2024-23260)

  - A logic issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.7.6,
    macOS Sonoma 14.4, macOS Ventura 13.6.8. An attacker may be able to read information belonging to another
    user. (CVE-2024-23261)

  - A logic issue was addressed with improved validation. This issue is fixed in tvOS 17.4, macOS Sonoma 14.4,
    visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, iOS 16.7.6 and iPadOS 16.7.6, Safari 17.4.
    Processing maliciously crafted web content may prevent Content Security Policy from being enforced.
    (CVE-2024-23263)

  - A validation issue was addressed with improved input sanitization. This issue is fixed in macOS Monterey
    12.7.4, macOS Ventura 13.6.5, macOS Sonoma 14.4, visionOS 1.1, iOS 17.4 and iPadOS 17.4, iOS 16.7.6 and
    iPadOS 16.7.6, tvOS 17.4. An application may be able to read restricted memory. (CVE-2024-23264)

  - A memory corruption vulnerability was addressed with improved locking. This issue is fixed in macOS
    Monterey 12.7.4, macOS Ventura 13.6.5, macOS Sonoma 14.4, visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS
    10.4, iOS 16.7.6 and iPadOS 16.7.6, tvOS 17.4. An app may be able to cause unexpected system termination
    or write kernel memory. (CVE-2024-23265)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Monterey
    12.7.4, macOS Ventura 13.6.5. An app may be able to modify protected parts of the file system.
    (CVE-2024-23266)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Monterey
    12.7.4, macOS Ventura 13.6.5. An app may be able to bypass certain Privacy preferences. (CVE-2024-23267)

  - An injection issue was addressed with improved input validation. This issue is fixed in macOS Sonoma 14.4,
    macOS Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to elevate privileges. (CVE-2024-23268,
    CVE-2024-23274)

  - A downgrade issue affecting Intel-based Mac computers was addressed with additional code-signing
    restrictions. This issue is fixed in macOS Sonoma 14.4, macOS Monterey 12.7.4, macOS Ventura 13.6.5. An
    app may be able to modify protected parts of the file system. (CVE-2024-23269)

  - The issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.7.4, macOS
    Ventura 13.6.5, macOS Sonoma 14.4, iOS 17.4 and iPadOS 17.4, tvOS 17.4. An app may be able to execute
    arbitrary code with kernel privileges. (CVE-2024-23270)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Monterey
    12.7.4, macOS Ventura 13.6.5. A user may gain access to protected parts of the file system.
    (CVE-2024-23272)

  - This issue was addressed through improved state management. This issue is fixed in Safari 17.4, iOS 17.4
    and iPadOS 17.4, macOS Sonoma 14.4. Private Browsing tabs may be accessed without authentication.
    (CVE-2024-23273)

  - A race condition was addressed with additional validation. This issue is fixed in macOS Sonoma 14.4, macOS
    Monterey 12.7.4, macOS Ventura 13.6.5. An app may be able to access protected user data. (CVE-2024-23275)

  - A logic issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Monterey
    12.7.4, macOS Ventura 13.6.5. An app may be able to elevate privileges. (CVE-2024-23276)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, iOS 17.4 and
    iPadOS 17.4. An attacker in a privileged network position may be able to inject keystrokes by spoofing a
    keyboard. (CVE-2024-23277)

  - The issue was addressed with improved checks. This issue is fixed in macOS Ventura 13.6.5, macOS Sonoma
    14.4, iOS 17.4 and iPadOS 17.4, watchOS 10.4, iOS 16.7.6 and iPadOS 16.7.6, tvOS 17.4. An app may be able
    to break out of its sandbox. (CVE-2024-23278)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    macOS Sonoma 14.4. An app may be able to access user-sensitive data. (CVE-2024-23279, CVE-2024-27809)

  - An injection issue was addressed with improved validation. This issue is fixed in Safari 17.4, macOS
    Sonoma 14.4, iOS 17.4 and iPadOS 17.4, watchOS 10.4, tvOS 17.4. A maliciously crafted webpage may be able
    to fingerprint the user. (CVE-2024-23280)

  - This issue was addressed with improved state management. This issue is fixed in macOS Sonoma 14.4. An app
    may be able to access sensitive user data. (CVE-2024-23281)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    iOS 16.7.6 and iPadOS 16.7.6, macOS Monterey 12.7.4, macOS Sonoma 14.4, macOS Ventura 13.6.5. An app may
    be able to access user-sensitive data. (CVE-2024-23283)

  - A logic issue was addressed with improved state management. This issue is fixed in tvOS 17.4, macOS Sonoma
    14.4, visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, iOS 16.7.6 and iPadOS 16.7.6, Safari 17.4.
    Processing maliciously crafted web content may prevent Content Security Policy from being enforced.
    (CVE-2024-23284)

  - This issue was addressed with improved handling of symlinks. This issue is fixed in macOS Sonoma 14.4. An
    app may be able to create symlinks to protected regions of the disk. (CVE-2024-23285)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Monterey
    12.7.4, macOS Ventura 13.6.5, macOS Sonoma 14.4, visionOS 1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, iOS
    16.7.6 and iPadOS 16.7.6, tvOS 17.4. Processing an image may lead to arbitrary code execution.
    (CVE-2024-23286)

  - A privacy issue was addressed with improved handling of temporary files. This issue is fixed in macOS
    Sonoma 14.4, iOS 17.4 and iPadOS 17.4, watchOS 10.4. An app may be able to access user-sensitive data.
    (CVE-2024-23287)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in tvOS 17.4, iOS 17.4 and
    iPadOS 17.4, macOS Sonoma 14.4, watchOS 10.4. An app may be able to elevate privileges. (CVE-2024-23288)

  - A lock screen issue was addressed with improved state management. This issue is fixed in iOS 16.7.6 and
    iPadOS 16.7.6, iOS 17.4 and iPadOS 17.4, macOS Sonoma 14.4, watchOS 10.4. A person with physical access to
    a device may be able to use Siri to access private calendar information. (CVE-2024-23289)

  - A logic issue was addressed with improved restrictions. This issue is fixed in tvOS 17.4, iOS 17.4 and
    iPadOS 17.4, macOS Sonoma 14.4, watchOS 10.4. An app may be able to access user-sensitive data.
    (CVE-2024-23290)

  - A privacy issue was addressed with improved private data redaction for log entries. This issue is fixed in
    tvOS 17.4, iOS 17.4 and iPadOS 17.4, macOS Sonoma 14.4, watchOS 10.4. A malicious app may be able to
    observe user data in log entries related to accessibility notifications. (CVE-2024-23291)

  - This issue was addressed with improved data protection. This issue is fixed in macOS Sonoma 14.4, iOS 17.4
    and iPadOS 17.4. An app may be able to access information about a user's contacts. (CVE-2024-23292)

  - This issue was addressed through improved state management. This issue is fixed in tvOS 17.4, iOS 17.4 and
    iPadOS 17.4, macOS Sonoma 14.4, watchOS 10.4. An attacker with physical access may be able to use Siri to
    access sensitive user data. (CVE-2024-23293)

  - This issue was addressed by removing the vulnerable code. This issue is fixed in macOS Sonoma 14.4.
    Processing malicious input may lead to code execution. (CVE-2024-23294)

  - A memory corruption issue was addressed with improved validation. This issue is fixed in iOS 17.4 and
    iPadOS 17.4. An attacker with arbitrary kernel read and write capability may be able to bypass kernel
    memory protections. Apple is aware of a report that this issue may have been exploited. (CVE-2024-23296)

  - The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4, macOS Ventura
    13.6.5, macOS Monterey 12.7.4. An app may be able to break out of its sandbox. (CVE-2024-23299)

  - A logic issue was addressed with improved checks. This issue is fixed in iOS 16.7.8 and iPadOS 16.7.8,
    macOS Monterey 12.7.5, macOS Ventura 13.6.7, macOS Sonoma 14.4. An app may be able to access user-
    sensitive data. (CVE-2024-27789)

  - This issue was addressed by adding an additional prompt for user consent. This issue is fixed in macOS
    Sonoma 14.4. An app may be able to access user-sensitive data. (CVE-2024-27792)

  - This issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14.4. A maliciously
    crafted ZIP archive may bypass Gatekeeper checks. (CVE-2024-27853)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Sonoma 14.4. An
    unprivileged app may be able to log keystrokes in other apps including those using secure input mode.
    (CVE-2024-27886)

  - A path handling issue was addressed with improved validation. This issue is fixed in macOS Sonoma 14.4. An
    app may be able to access user-sensitive data. (CVE-2024-27887)

  - A permissions issue was addressed by removing vulnerable code and adding additional checks. This issue is
    fixed in macOS Sonoma 14.4. An app may be able to modify protected parts of the file system.
    (CVE-2024-27888)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT214084");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 14.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:14.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '14.4.0', 'min_version' : '14.0', 'fixed_display' : 'macOS Sonoma 14.4' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
