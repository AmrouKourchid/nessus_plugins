#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3606. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(182754);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-4030",
    "CVE-2020-4031",
    "CVE-2020-4032",
    "CVE-2020-4033",
    "CVE-2020-11017",
    "CVE-2020-11018",
    "CVE-2020-11019",
    "CVE-2020-11038",
    "CVE-2020-11039",
    "CVE-2020-11040",
    "CVE-2020-11041",
    "CVE-2020-11042",
    "CVE-2020-11043",
    "CVE-2020-11044",
    "CVE-2020-11045",
    "CVE-2020-11046",
    "CVE-2020-11047",
    "CVE-2020-11048",
    "CVE-2020-11049",
    "CVE-2020-11058",
    "CVE-2020-11085",
    "CVE-2020-11086",
    "CVE-2020-11087",
    "CVE-2020-11088",
    "CVE-2020-11089",
    "CVE-2020-11095",
    "CVE-2020-11096",
    "CVE-2020-11097",
    "CVE-2020-11098",
    "CVE-2020-11099",
    "CVE-2020-13396",
    "CVE-2020-13397",
    "CVE-2020-13398",
    "CVE-2020-15103",
    "CVE-2023-39350",
    "CVE-2023-39351",
    "CVE-2023-39352",
    "CVE-2023-39353",
    "CVE-2023-39354",
    "CVE-2023-39355",
    "CVE-2023-39356",
    "CVE-2023-40181",
    "CVE-2023-40186",
    "CVE-2023-40188",
    "CVE-2023-40567",
    "CVE-2023-40569",
    "CVE-2023-40589"
  );

  script_name(english:"Debian dla-3606 : freerdp2-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3606 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3606-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    October 07, 2023                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : freerdp2
    Version        : 2.3.0+dfsg1-2+deb10u3
    CVE ID         : CVE-2020-4030 CVE-2020-4031 CVE-2020-4032 CVE-2020-4033
                     CVE-2020-11017 CVE-2020-11018 CVE-2020-11019 CVE-2020-11038
                     CVE-2020-11039 CVE-2020-11040 CVE-2020-11041 CVE-2020-11042
                     CVE-2020-11043 CVE-2020-11044 CVE-2020-11045 CVE-2020-11046
                     CVE-2020-11047 CVE-2020-11048 CVE-2020-11049 CVE-2020-11058
                     CVE-2020-11085 CVE-2020-11086 CVE-2020-11087 CVE-2020-11088
                     CVE-2020-11089 CVE-2020-11095 CVE-2020-11096 CVE-2020-11097
                     CVE-2020-11098 CVE-2020-11099 CVE-2020-13396 CVE-2020-13397
                     CVE-2020-13398 CVE-2020-15103 CVE-2023-39350 CVE-2023-39351
                     CVE-2023-39352 CVE-2023-39353 CVE-2023-39354 CVE-2023-39355
                     CVE-2023-39356 CVE-2023-40567 CVE-2023-40181 CVE-2023-40186
                     CVE-2023-40188 CVE-2023-40569 CVE-2023-40589
    Debian Bug     : 965979 1051638

    Multiple vulnerabilties have been found in freelrdp2, a free
    implementation of the Remote Desktop Protocol (RDP).
    The vulnerabilties potentially allows buffer overreads, buffer overflows,
    interger overflows, use-after-free, DoS vectors.

    CVE-2020-4030

        In FreeRDP before version 2.1.2, there is an out of bounds read in
        TrioParse. Logging might bypass string length checks due to an
        integer overflow. This is fixed in version 2.1.2.

    CVE-2020-4031

        In FreeRDP before version 2.1.2, there is a use-after-free in
        gdi_SelectObject. All FreeRDP clients using compatibility mode with
        /relax-order-checks are affected. This is fixed in version 2.1.2.

    CVE-2020-4032

        In FreeRDP before version 2.1.2, there is an integer casting
        vulnerability in update_recv_secondary_order. All clients with
        +glyph-cache /relax-order-checks are affected. This is fixed in
        version 2.1.2.

    CVE-2020-4033

        In FreeRDP before version 2.1.2, there is an out of bounds read in
        RLEDECOMPRESS. All FreeRDP based clients with sessions with color
        depth < 32 are affected. This is fixed in version 2.1.2.

    CVE-2020-11017

        In FreeRDP less than or equal to 2.0.0, by providing manipulated
        input a malicious client can create a double free condition and
        crash the server. This is fixed in version 2.1.0.

    CVE-2020-11018

        In FreeRDP less than or equal to 2.0.0, a possible resource
        exhaustion vulnerability can be performed. Malicious clients could
        trigger out of bound reads causing memory allocation with random
        size. This has been fixed in 2.1.0.

    CVE-2020-11019

        In FreeRDP less than or equal to 2.0.0, when running with logger set
        to WLOG_TRACE, a possible crash of application could occur due to
        a read of an invalid array index. Data could be printed as string to
        local terminal. This has been fixed in 2.1.0.

    CVE-2020-11038

        In FreeRDP less than or equal to 2.0.0, an Integer Overflow to
        Buffer Overflow exists. When using /video redirection, a manipulated
        server can instruct the client to allocate a buffer with a smaller
        size than requested due to an integer overflow in size calculation.
        With later messages, the server can manipulate the client to write
        data out of bound to the previously allocated buffer. This has been
        patched in 2.1.0.

    CVE-2020-11039

        In FreeRDP less than or equal to 2.0.0, when using a manipulated
        server with USB redirection enabled (nearly) arbitrary memory can be
        read and written due to integer overflows in length checks. This has
        been patched in 2.1.0.

    CVE-2020-11040

        In FreeRDP less than or equal to 2.0.0, there is an out-of-bound
        data read from memory in clear_decompress_subcode_rlex, visualized
        on screen as color. This has been patched in 2.1.0.

    CVE-2020-11041

        In FreeRDP less than or equal to 2.0.0, an outside controlled array
        index is used unchecked for data used as configuration for sound
        backend (alsa, oss, pulse, ...). The most likely outcome is a crash
        of the client instance followed by no or distorted sound or a
        session disconnect. If a user cannot upgrade to the patched version,
        a workaround is to disable sound for the session. This has been
        patched in 2.1.0.

    CVE-2020-11042

        In FreeRDP greater than 1.1 and before 2.0.0, there is an
        out-of-bounds read in update_read_icon_info. It allows reading a
        attacker-defined amount of client memory (32bit unsigned -> 4GB) to
        an intermediate buffer. This can be used to crash the client or
        store information for later retrieval. This has been patched in
        2.0.0.

    CVE-2020-11043

        In FreeRDP less than or equal to 2.0.0, there is an out-of-bounds
        read in rfx_process_message_tileset. Invalid data fed to RFX decoder
        results in garbage on screen (as colors). This has been patched in
        2.1.0.

    CVE-2020-11044

        In FreeRDP greater than 1.2 and before 2.0.0, a double free in
        update_read_cache_bitmap_v3_order crashes the client application if
        corrupted data from a manipulated server is parsed. This has been
        patched in 2.0.0.

    CVE-2020-11045

        In FreeRDP after 1.0 and before 2.0.0, there is an out-of-bound read
        in in update_read_bitmap_data that allows client memory to be read
        to an image buffer. The result displayed on screen as colour.

    CVE-2020-11046

        In FreeRDP after 1.0 and before 2.0.0, there is a stream
        out-of-bounds seek in update_read_synchronize that could lead to a
        later out-of-bounds read.

    CVE-2020-11047

        In FreeRDP after 1.1 and before 2.0.0, there is an out-of-bounds
        read in autodetect_recv_bandwidth_measure_results. A malicious
        server can extract up to 8 bytes of client memory with a manipulated
        message by providing a short input and reading the measurement
        result data. This has been patched in 2.0.0.

    CVE-2020-11048

        In FreeRDP after 1.0 and before 2.0.0, there is an out-of-bounds
        read. It only allows to abort a session. No data extraction is
        possible. This has been fixed in 2.0.0.

    CVE-2020-11049

        In FreeRDP after 1.1 and before 2.0.0, there is an out-of-bound read
        of client memory that is then passed on to the protocol parser. This
        has been patched in 2.0.0.

    CVE-2020-11058

        In FreeRDP after 1.1 and before 2.0.0, a stream out-of-bounds seek
        in rdp_read_font_capability_set could lead to a later out-of-bounds
        read. As a result, a manipulated client or server might force a
        disconnect due to an invalid data read. This has been fixed in
        2.0.0.

    CVE-2020-11085

        In FreeRDP before 2.1.0, there is an out-of-bounds read in
        cliprdr_read_format_list. Clipboard format data read (by client or
        server) might read data out-of-bounds. This has been fixed in 2.1.0.

    CVE-2020-11086

        In FreeRDP less than or equal to 2.0.0, there is an out-of-bound
        read in ntlm_read_ntlm_v2_client_challenge that reads up to 28 bytes
        out-of-bound to an internal structure. This has been fixed in 2.1.0.

    CVE-2020-11087

        In FreeRDP less than or equal to 2.0.0, there is an out-of-bound
        read in ntlm_read_AuthenticateMessage. This has been fixed in 2.1.0.

    CVE-2020-11088

        In FreeRDP less than or equal to 2.0.0, there is an out-of-bound
        read in ntlm_read_NegotiateMessage. This has been fixed in 2.1.0.

    CVE-2020-11089

        In FreeRDP before 2.1.0, there is an out-of-bound read in irp
        functions (parallel_process_irp_create, serial_process_irp_create,
        drive_process_irp_write, printer_process_irp_write, rdpei_recv_pdu,
        serial_process_irp_write). This has been fixed in 2.1.0.

    CVE-2020-11095

        In FreeRDP before version 2.1.2, an out of bound reads occurs
        resulting in accessing a memory location that is outside of the
        boundaries of the static array PRIMARY_DRAWING_ORDER_FIELD_BYTES.
        This is fixed in version 2.1.2

    CVE-2020-11096

        In FreeRDP before version 2.1.2, there is a global OOB read in
        update_read_cache_bitmap_v3_order. As a workaround, one can disable
        bitmap cache with -bitmap-cache (default). This is fixed in version
        2.1.2.

    CVE-2020-11097

        In FreeRDP before version 2.1.2, an out of bounds read occurs
        resulting in accessing a memory location that is outside of the
        boundaries of the static array PRIMARY_DRAWING_ORDER_FIELD_BYTES.
        This is fixed in version 2.1.2.

    CVE-2020-11098

        In FreeRDP before version 2.1.2, there is an out-of-bound read in
        glyph_cache_put. This affects all FreeRDP clients with
        `+glyph-cache` option enabled This is fixed in version 2.1.2.

    CVE-2020-11099

        In FreeRDP before version 2.1.2, there is an out of bounds read in
        license_read_new_or_upgrade_license_packet. A manipulated license
        packet can lead to out of bound reads to an internal buffer. This is
        fixed in version 2.1.2.

    CVE-2020-13396

        In FreeRDP before version 2.1.2, there is an out of bounds read in
        license_read_new_or_upgrade_license_packet. A manipulated license
        packet can lead to out of bound reads to an internal buffer. This is
        fixed in version 2.1.2.

    CVE-2020-13397

        An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds
        (OOB) read vulnerability has been detected in security_fips_decrypt
        in libfreerdp/core/security.c due to an uninitialized value.

    CVE-2020-13398

        An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds
        (OOB) write vulnerability has been detected in crypto_rsa_common in
        libfreerdp/crypto/crypto.c.

    CVE-2020-15103

        In FreeRDP less than or equal to 2.1.2, an integer overflow exists
        due to missing input sanitation in rdpegfx channel. All FreeRDP
        clients are affected. The input rectangles from the server are not
        checked against local surface coordinates and blindly accepted. A
        malicious server can send data that will crash the client later on
        (invalid length arguments to a `memcpy`) This has been fixed in
        2.2.0. As a workaround, stop using command line arguments /gfx,
        /gfx-h264 and /network:auto

    CVE-2023-39350

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. This issue affects Clients
        only. Integer underflow leading to DOS (e.g. abort due to
        `WINPR_ASSERT` with default compilation flags). When an insufficient
        blockLen is provided, and proper length validation is not performed,
        an Integer Underflow occurs, leading to a Denial of Service (DOS)
        vulnerability. This issue has been addressed in versions 2.11.0 and
        3.0.0-beta3. Users are advised to upgrade. There are no known
        workarounds for this vulnerability.

    CVE-2023-39351

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions of
        FreeRDP are subject to a Null Pointer Dereference leading a crash in
        the RemoteFX (rfx) handling. Inside the
        `rfx_process_message_tileset` function, the program allocates tiles
        using `rfx_allocate_tiles` for the number of numTiles. If the
        initialization process of tiles is not completed for various
        reasons, tiles will have a NULL pointer. Which may be accessed in
        further processing and would cause a program crash. This issue has
        been addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised
        to upgrade. There are no known workarounds for this vulnerability.

    CVE-2023-39352

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions are
        subject to an invalid offset validation leading to Out Of Bound
        Write. This can be triggered when the values `rect->left` and
        `rect->top` are exactly equal to `surface->width` and
        `surface->height`. eg. `rect->left` == `surface->width` &&
        `rect->top` == `surface->height`. In practice this should cause a
        crash. This issue has been addressed in versions 2.11.0 and
        3.0.0-beta3. Users are advised to upgrade. There are no known
        workarounds for this vulnerability.

    CVE-2023-39353

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions are
        subject to a missing offset validation leading to Out Of Bound Read.
        In the `libfreerdp/codec/rfx.c` file there is no offset validation
        in `tile->quantIdxY`, `tile->quantIdxCb`, and `tile->quantIdxCr`. As
        a result crafted input can lead to an out of bounds read access
        which in turn will cause a crash. This issue has been addressed in
        versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There
        are no known workarounds for this vulnerability.

    CVE-2023-39354

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions are
        subject to an Out-Of-Bounds Read in the `nsc_rle_decompress_data`
        function. The Out-Of-Bounds Read occurs because it processes
        `context->Planes` without checking if it contains data of sufficient
        length. Should an attacker be able to leverage this vulnerability
        they may be able to cause a crash. This issue has been addressed in
        versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There
        are no known workarounds for this vulnerability.

    CVE-2023-39355

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Versions of FreeRDP on the
        3.x release branch before beta3 are subject to a Use-After-Free in
        processing `RDPGFX_CMDID_RESETGRAPHICS` packets. If
        `context->maxPlaneSize` is 0, `context->planesBuffer` will be freed.
        However, without updating `context->planesBuffer`, this leads to a
        Use-After-Free exploit vector. In most environments this should only
        result in a crash. This issue has been addressed in version
        3.0.0-beta3 and users of the beta 3.x releases are advised to
        upgrade. There are no known workarounds for this vulnerability.

    CVE-2023-39356

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. In affected versions a
        missing offset validation may lead to an Out Of Bound Read in the
        function `gdi_multi_opaque_rect`. In particular there is no code to
        validate if the value `multi_opaque_rect->numRectangles` is less
        than 45. Looping through `multi_opaque_rect->`numRectangles without
        proper boundary checks can lead to Out-of-Bounds Read errors which
        will likely lead to a crash. This issue has been addressed in
        versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There
        are no known workarounds for this vulnerability.

    CVE-2023-40567

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions are
        subject to an Out-Of-Bounds Write in the
        `clear_decompress_bands_data` function in which there is no offset
        validation. Abuse of this vulnerability may lead to an out of bounds
        write. This issue has been addressed in versions 2.11.0 and
        3.0.0-beta3. Users are advised to upgrade. there are no known
        workarounds for this vulnerability.

    CVE-2023-40181

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions are
        subject to an Integer-Underflow leading to Out-Of-Bound Read in the
        `zgfx_decompress_segment` function. In the context of `CopyMemory`,
        it's possible to read data beyond the transmitted packet range and
        likely cause a crash. This issue has been addressed in versions
        2.11.0 and 3.0.0-beta3. Users are advised to upgrade. There are no
        known workarounds for this issue.

    CVE-2023-40186

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions are
        subject to an IntegerOverflow leading to Out-Of-Bound Write
        Vulnerability in the `gdi_CreateSurface` function. This issue
        affects FreeRDP based clients only. FreeRDP proxies are not affected
        as image decoding is not done by a proxy. This issue has been
        addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to
        upgrade. There are no known workarounds for this issue.

    CVE-2023-40188

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions are
        subject to an Out-Of-Bounds Read in the `general_LumaToYUV444`
        function. This Out-Of-Bounds Read occurs because processing is done
        on the `in` variable without checking if it contains data of
        sufficient length. Insufficient data for the `in` variable may cause
        errors or crashes. This issue has been addressed in versions 2.11.0
        and 3.0.0-beta3. Users are advised to upgrade. There are no known
        workarounds for this issue.

    CVE-2023-40569

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. Affected versions are
        subject to an Out-Of-Bounds Write in the `progressive_decompress`
        function. This issue is likely down to incorrect calculations of the
        `nXSrc` and `nYSrc` variables. This issue has been addressed in
        versions 2.11.0 and 3.0.0-beta3. Users are advised to upgrade. there
        are no known workarounds for this vulnerability.

    CVE-2023-40589

        FreeRDP is a free implementation of the Remote Desktop Protocol
        (RDP), released under the Apache license. In affected versions there
        is a Global-Buffer-Overflow in the ncrush_decompress function.
        Feeding crafted input into this function can trigger the overflow
        which has only been shown to cause a crash. This issue has been
        addressed in versions 2.11.0 and 3.0.0-beta3. Users are advised to
        upgrade. There are no known workarounds for this issue.

    For Debian 10 buster, these problems have been fixed in version
    2.3.0+dfsg1-2+deb10u3.

    We recommend that you upgrade your freerdp2 packages.

    For the detailed security status of freerdp2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/freerdp2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/freerdp2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11017");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11018");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11038");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11039");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11041");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11043");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11044");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11045");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11046");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11047");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11048");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11049");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11086");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11087");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11089");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11095");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11096");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11097");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11098");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-13396");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-13397");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-13398");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-15103");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-4030");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-4031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-4032");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-4033");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39350");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39351");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39352");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39354");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39355");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39356");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40181");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40186");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40188");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40569");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-40589");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/freerdp2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the freerdp2-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13398");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-40569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-shadow-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-client2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-server2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-shadow-subsystem2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-shadow2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuwac0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuwac0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-tools2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winpr-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'freerdp2-dev', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'freerdp2-shadow-x11', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'freerdp2-wayland', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'freerdp2-x11', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libfreerdp-client2-2', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libfreerdp-server2-2', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libfreerdp-shadow-subsystem2-2', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libfreerdp-shadow2-2', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libfreerdp2-2', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libuwac0-0', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libuwac0-dev', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libwinpr-tools2-2', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libwinpr2-2', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libwinpr2-dev', 'reference': '2.3.0+dfsg1-2+deb10u3'},
    {'release': '10.0', 'prefix': 'winpr-utils', 'reference': '2.3.0+dfsg1-2+deb10u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp2-dev / freerdp2-shadow-x11 / freerdp2-wayland / freerdp2-x11 / etc');
}
