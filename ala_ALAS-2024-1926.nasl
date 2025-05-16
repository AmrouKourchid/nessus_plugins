#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2024-1926.
##

include('compat.inc');

if (description)
{
  script_id(192266);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2016-5841",
    "CVE-2017-11166",
    "CVE-2017-12805",
    "CVE-2017-12806",
    "CVE-2017-13139",
    "CVE-2017-18251",
    "CVE-2017-18252",
    "CVE-2017-18254",
    "CVE-2017-18271",
    "CVE-2017-18273",
    "CVE-2017-1000476",
    "CVE-2018-8804",
    "CVE-2018-9133",
    "CVE-2018-10177",
    "CVE-2018-10804",
    "CVE-2018-10805",
    "CVE-2018-11656",
    "CVE-2018-12599",
    "CVE-2018-12600",
    "CVE-2018-13153",
    "CVE-2018-14434",
    "CVE-2018-14435",
    "CVE-2018-14436",
    "CVE-2018-14437",
    "CVE-2018-15607",
    "CVE-2018-16328",
    "CVE-2018-16749",
    "CVE-2018-16750",
    "CVE-2018-18544",
    "CVE-2018-20467",
    "CVE-2019-7175",
    "CVE-2019-7397",
    "CVE-2019-7398",
    "CVE-2019-9956",
    "CVE-2019-10131",
    "CVE-2019-10650",
    "CVE-2019-11470",
    "CVE-2019-11472",
    "CVE-2019-11597",
    "CVE-2019-11598",
    "CVE-2019-12974",
    "CVE-2019-12975",
    "CVE-2019-12976",
    "CVE-2019-12978",
    "CVE-2019-12979",
    "CVE-2019-13133",
    "CVE-2019-13134",
    "CVE-2019-13135",
    "CVE-2019-13295",
    "CVE-2019-13297",
    "CVE-2019-13300",
    "CVE-2019-13301",
    "CVE-2019-13304",
    "CVE-2019-13305",
    "CVE-2019-13306",
    "CVE-2019-13307",
    "CVE-2019-13309",
    "CVE-2019-13310",
    "CVE-2019-13311",
    "CVE-2019-13454",
    "CVE-2019-14980",
    "CVE-2019-14981",
    "CVE-2019-15139",
    "CVE-2019-15140",
    "CVE-2019-15141",
    "CVE-2019-16708",
    "CVE-2019-16709",
    "CVE-2019-16710",
    "CVE-2019-16711",
    "CVE-2019-16712",
    "CVE-2019-16713",
    "CVE-2019-17540",
    "CVE-2019-17541",
    "CVE-2019-19948",
    "CVE-2019-19949"
  );

  script_name(english:"Amazon Linux AMI : ImageMagick (ALAS-2024-1926)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote host is prior to 6.9.10.68-3.22. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2024-1926 advisory.

    Integer overflow in MagickCore/profile.c in ImageMagick before 7.0.2-1 allows remote attackers to cause a
    denial of service (segmentation fault) or possibly execute arbitrary code via vectors involving the offset
    variable. (CVE-2016-5841)

    ImageMagick 7.0.7-12 Q16, a CPU exhaustion vulnerability was found in the function ReadDDSInfo in
    coders/dds.c, which allows attackers to cause a denial of service. (CVE-2017-1000476)

    The ReadXWDImage function in coders\xwd.c in ImageMagick 7.0.5-6 has a memory leak vulnerability that can
    cause memory exhaustion via a crafted length (number of color-map entries) field in the header of an XWD
    file. (CVE-2017-11166)

    In ImageMagick 7.0.6-6, a memory exhaustion vulnerability was found in the function ReadTIFFImage, which
    allows attackers to cause a denial of service. (CVE-2017-12805)

    In ImageMagick 7.0.6-6, a memory exhaustion vulnerability was found in the function format8BIM, which
    allows attackers to cause a denial of service. (CVE-2017-12806)

    In ImageMagick before 6.9.9-0 and 7.x before 7.0.6-1, the ReadOneMNGImage function in coders/png.c has an
    out-of-bounds read with the MNG CLIP chunk. (CVE-2017-13139)

    A memory leak vulnerability has been discovered in ImageMagick in the ReadPCDImage function of
    coders/pcd.c file. An attacker could use this flaw to cause a denial of service via a crafted file.
    (CVE-2017-18251)

    An issue was discovered in ImageMagick 7.0.7. The MogrifyImageList function in MagickWand/mogrify.c allows
    attackers to cause a denial of service (assertion failure and application exit in ReplaceImageInList) via
    a crafted file. (CVE-2017-18252)

    A memory leak vulnerability has been discovered in ImageMagick in the WriteGIFImage function of
    coders/gif.c file. An attacker could use this flaw to cause a denial of service via a crafted file.
    (CVE-2017-18254)

    In ImageMagick 7.0.7-16 Q16 x86_64 2017-12-22, an infinite loop vulnerability was found in the function
    ReadMIFFImage in coders/miff.c, which allows attackers to cause a denial of service (CPU exhaustion) via a
    crafted MIFF image file. (CVE-2017-18271)

    In ImageMagick 7.0.7-16 Q16 x86_64 2017-12-22, an infinite loop vulnerability was found in the function
    ReadTXTImage in coders/txt.c, which allows attackers to cause a denial of service (CPU exhaustion) via a
    crafted image file that is mishandled in a GetImageIndexInList call. (CVE-2017-18273)

    An infinite loop has been found in the way ImageMagick reads Multiple-image Network Graphics (MNG) data.
    An attacker could exploit this to cause a denial of service via crafted MNG file. (CVE-2018-10177)

    ImageMagick version 7.0.7-28 contains a memory leak in WriteTIFFImage in coders/tiff.c. (CVE-2018-10804)

    ImageMagick version 7.0.7-28 contains a memory leak in ReadYCBCRImage in coders/ycbcr.c. (CVE-2018-10805)

    In ImageMagick 7.0.7-20 Q16 x86_64, a memory leak vulnerability was found in the function ReadDCMImage in
    coders/dcm.c, which allows attackers to cause a denial of service via a crafted DCM image file.
    (CVE-2018-11656)

    In ImageMagick 7.0.8-3 Q16, ReadBMPImage and WriteBMPImage in coders/bmp.c allow attackers to cause an out
    of bounds write via a crafted file. (CVE-2018-12599)

    In ImageMagick 7.0.8-3 Q16, ReadDIBImage and WriteDIBImage in coders/dib.c allow attackers to cause an out
    of bounds write via a crafted file. (CVE-2018-12600)

    A memory leak was discovered in ImageMagick in the XMagickCommand function in animate.c file. An array of
    strings, named filelist, is allocated on the heap but not released in case the function ExpandFilenames
    returns an error code. (CVE-2018-13153)

    ImageMagick 7.0.8-4 has a memory leak for a colormap in WriteMPCImage in coders/mpc.c. (CVE-2018-14434)

    ImageMagick 7.0.8-4 has a memory leak in DecodeImage in coders/pcd.c. (CVE-2018-14435)

    ImageMagick 7.0.8-4 has a memory leak in ReadMIFFImage in coders/miff.c. (CVE-2018-14436)

    ImageMagick 7.0.8-4 has a memory leak in parse8BIM in coders/meta.c. (CVE-2018-14437)

    In ImageMagick 7.0.8-11 Q16, a tiny input file 0x50 0x36 0x36 0x36 0x36 0x4c 0x36 0x38 0x36 0x36 0x36 0x36
    0x36 0x36 0x1f 0x35 0x50 0x00 can result in a hang of several minutes during which CPU and memory
    resources are consumed until ultimately an attempted large memory allocation fails. Remote attackers could
    leverage this vulnerability to cause a denial of service via a crafted file. (CVE-2018-15607)

    In ImageMagick before 7.0.8-8, a NULL pointer dereference exists in the CheckEventLogging function in
    MagickCore/log.c. (CVE-2018-16328)

    In ImageMagick 7.0.7-29 and earlier, a missing NULL check in ReadOneJNGImage in coders/png.c allows an
    attacker to cause a denial of service (WriteBlob assertion failure and application exit) via a crafted
    file. (CVE-2018-16749)

    In ImageMagick 7.0.7-29 and earlier, a memory leak in the formatIPTCfromBuffer function in coders/meta.c
    was found. (CVE-2018-16750)

    There is a memory leak in the function WriteMSLImage of coders/msl.c in ImageMagick 7.0.8-13 Q16, and the
    function ProcessMSLScript of coders/msl.c in GraphicsMagick before 1.3.31. (CVE-2018-18544)

    In coders/bmp.c in ImageMagick before 7.0.8-16, an input file can result in an infinite loop and hang,
    with high CPU and memory consumption. Remote attackers could leverage this vulnerability to cause a denial
    of service via a crafted file. (CVE-2018-20467)

    WriteEPTImage in coders/ept.c in ImageMagick 7.0.7-25 Q16 allows remote attackers to cause a denial of
    service (MagickCore/memory.c double free and application crash) or possibly have unspecified other impact
    via a crafted file. (CVE-2018-8804)

    ImageMagick 7.0.7-26 Q16 has excessive iteration in the DecodeLabImage and EncodeLabImage functions
    (coders/tiff.c), which results in a hang (tens of minutes) with a tiny PoC file. Remote attackers could
    leverage this vulnerability to cause a denial of service via a crafted tiff file. (CVE-2018-9133)

    An off-by-one read vulnerability was discovered in ImageMagick in the formatIPTCfromBuffer function in
    coders/meta.c. A local attacker may use this flaw to read beyond the end of the buffer or to crash the
    program. (CVE-2019-10131)

    In ImageMagick 7.0.8-36 Q16, there is a heap-based buffer over-read in the function WriteTIFFImage of
    coders/tiff.c, which allows an attacker to cause a denial of service or information disclosure via a
    crafted image file. (CVE-2019-10650)

    The cineon parsing component in ImageMagick 7.0.8-26 Q16 allows attackers to cause a denial-of-service
    (uncontrolled resource consumption) by crafting a Cineon image with an incorrect claimed image size. This
    occurs because ReadCINImage in coders/cin.c lacks a check for insufficient image data in a file.
    (CVE-2019-11470)

    ReadXWDImage in coders/xwd.c in the XWD image parsing component of ImageMagick 7.0.8-41 Q16 allows
    attackers to cause a denial-of-service (divide-by-zero error) by crafting an XWD image file in which the
    header indicates neither LSB first nor MSB first. (CVE-2019-11472)

    In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer over-read in the function WriteTIFFImage of
    coders/tiff.c, which allows an attacker to cause a denial of service or possibly information disclosure
    via a crafted image file. (CVE-2019-11597)

    In ImageMagick 7.0.8-40 Q16, there is a heap-based buffer over-read in the function WritePNMImage of
    coders/pnm.c, which allows an attacker to cause a denial of service or possibly information disclosure via
    a crafted image file. This is related to SetGrayscaleImage in MagickCore/quantize.c. (CVE-2019-11598)

    A NULL pointer dereference in the function ReadPANGOImage in coders/pango.c and the function ReadVIDImage
    in coders/vid.c in ImageMagick 7.0.8-34 allows remote attackers to cause a denial of service via a crafted
    image. (CVE-2019-12974)

    It was discovered that ImageMagick does not properly release acquired memory when some error conditions
    occur in the WriteDPXImage() function. Applications compiled against ImageMagick libraries that accept
    untrustworthy images may be exploited to use all available memory and make them crash. An attacker could
    abuse this flaw by providing a specially crafted image and cause a Denial of Service by using all
    available memory. (CVE-2019-12975)

    It was discovered that ImageMagick does not properly release acquired memory when some error conditions
    occur in the ReadPCLImage() function. Applications compiled against ImageMagick libraries that accept
    untrustworthy images may be exploited to use all available memory and make them crash.An attacker could
    abuse this flaw by providing a specially crafted image and cause a Denial of Service by using all
    available memory. (CVE-2019-12976)

    ImageMagick 7.0.8-34 has a use of uninitialized value vulnerability in the ReadPANGOImage function in
    coders/pango.c. (CVE-2019-12978)

    ImageMagick 7.0.8-34 has a use of uninitialized value vulnerability in the SyncImageSettings function in
    MagickCore/image.c. This is related to AcquireImage in magick/image.c. (CVE-2019-12979)

    ImageMagick before 7.0.8-50 has a memory leak vulnerability in the function ReadBMPImage in coders/bmp.c.
    (CVE-2019-13133)

    ImageMagick before 7.0.8-50 has a memory leak vulnerability in the function ReadVIFFImage in
    coders/viff.c. (CVE-2019-13134)

    ImageMagick before 7.0.8-50 has a use of uninitialized value vulnerability in the function ReadCUTImage
    in coders/cut.c. (CVE-2019-13135)

    A heap-based buffer over-read was discovered in ImageMagick in the way it selects an individual threshold
    for each pixel based on the range of intensity values in its local neighborhood due to a width of zero
    mishandle error. Applications compiled against ImageMagick libraries that accept untrustworthy images may
    be vulnerable to this flaw. An attacker could abuse this flaw by providing a specially crafted image to
    make the application crash or leak application data. (CVE-2019-13295)

    A heap-based buffer over-read was discovered in ImageMagick in the way it selects an individual threshold
    for each pixel based on the range of intensity values in its local neighborhood due to a height of zero
    mishandle error. Applications compiled against ImageMagick libraries that accept untrustworthy images may
    be vulnerable to this flaw. An attacker could abuse this flaw by providing a specially crafted image to
    make the application crash or leak application data. (CVE-2019-13297)

    A heap-based buffer overflow was discovered in ImageMagick in the way it applies a value with arithmetic,
    relational, or logical operators to an image due to mishandling columns. Applications compiled against
    ImageMagick libraries that accept untrustworthy images and use the evaluate-sequence option or function
    EvaluateImages may be vulnerable to this flaw. An attacker could abuse this flaw by providing a specially
    crafted image to make the application crash or potentially execute code. (CVE-2019-13300)

    ImageMagick 7.0.8-50 Q16 has memory leaks in AcquireMagickMemory because of an AnnotateImage error.
    (CVE-2019-13301)

    A stack-based buffer overflow was discovered in ImageMagick in the way it writes PNM images due to a
    misplaced assignment. Applications compiled against ImageMagick libraries that accept untrustworthy images
    or write PNM images may be vulnerable to this flaw. An attacker could abuse this flaw by providing a
    specially crafted image to make the application crash or potentially execute code. (CVE-2019-13304)

    A stack-based buffer overflow was discovered in ImageMagick in the way it writes PNM images due to a
    misplaced strncpy and off-by-one errors. Applications compiled against ImageMagick libraries that accept
    untrustworthy images or write PNM images may be vulnerable to this flaw. An attacker could abuse this flaw
    by providing a specially crafted image to make the application crash or potentially execute code.
    (CVE-2019-13305)

    A stack-based buffer overflow was discovered in ImageMagick in the way it writes PNM images due to off-by-
    one errors. Applications compiled against ImageMagick libraries that accept untrustworthy images or write
    PNM images may be vulnerable to this flaw. An attacker could abuse this flaw by providing a specially
    crafted image to make the application crash or potentially execute code. (CVE-2019-13306)

    A heap-based buffer overflow was discovered in ImageMagick in the way it parses images when using the
    evaluate-sequence option. Applications compiled against ImageMagick libraries that accept untrustworthy
    images and use the evaluate-sequence option or function EvaluateImages may be vulnerable to this flaw. An
    attacker could abuse this flaw by providing a specially crafted image to make the application crash or
    potentially execute code. (CVE-2019-13307)

    A flaw was found in ImageMagick version 7.0.8-50 Q16, containing memory leaks of AcquireMagickMemory due
    to the mishandling of the NoSuchImage error in CLIListOperatorImages in MagickWand/operation.c. It was
    discovered that ImageMagick does not properly release acquired memory in function MogrifyImageList() when
    some error conditions are met, or the compare option is used. Applications compiled against ImageMagick
    libraries that accept untrustworthy images may be exploited to use all available memory and make them
    crash. An attacker could abuse this flaw by providing a specially crafted image and cause a Denial of
    Service by using all available memory. (CVE-2019-13309)

    A flaw was found in ImageMagick version 7.0.8-50 Q16, containing memory leaks of AcquireMagickMemory due
    to an error found in MagickWand/mogrify.c. It was discovered that ImageMagick does not properly release
    acquired memory when some error conditions occur in the function MogrifyImageList(). Applications compiled
    against ImageMagick libraries that accept untrustworthy images may be exploited to use all available
    memory and make them crash. An attacker could abuse this flaw by providing a specially crafted image and
    cause a Denial of Service by using all available memory. (CVE-2019-13310)

    A flaw was found in ImageMagick, containing memory leaks of AcquireMagickMemory due to a wand/mogrify.c
    error. It was discovered that ImageMagick does not properly release acquired memory when some error
    conditions occur in the function MogrifyImageList(). An attacker could abuse this flaw by providing a
    specially crafted image and cause a Denial of Service by using all available memory. Applications compiled
    against ImageMagick libraries that accept untrustworthy images may be exploited to use all available
    memory and make them crash. (CVE-2019-13311)

    ImageMagick 7.0.8-54 Q16 allows Division by Zero in RemoveDuplicateLayers in MagickCore/layer.c.
    (CVE-2019-13454)

    In ImageMagick 7.x before 7.0.8-42 and 6.x before 6.9.10-42, there is a use after free vulnerability in
    the UnmapBlob function that allows an attacker to cause a denial of service by sending a crafted file.
    (CVE-2019-14980)

    In ImageMagick 7.x before 7.0.8-41 and 6.x before 6.9.10-41, there is a divide-by-zero vulnerability in
    the MeanShiftImage function. It allows an attacker to cause a denial of service by sending a crafted file.
    (CVE-2019-14981)

    The XWD image (X Window System window dumping file) parsing component in ImageMagick 7.0.8-41 Q16 allows
    attackers to cause a denial-of-service (application crash resulting from an out-of-bounds Read) in
    ReadXWDImage in coders/xwd.c by crafting a corrupted XWD image file, a different vulnerability than
    CVE-2019-11472. (CVE-2019-15139)

    coders/mat.c in ImageMagick 7.0.8-43 Q16 allows remote attackers to cause a denial of service (use-after-
    free and application crash) or possibly have unspecified other impact by crafting a Matlab image file that
    is mishandled in ReadImage in MagickCore/constitute.c. (CVE-2019-15140)

    WriteTIFFImage in coders/tiff.c in ImageMagick 7.0.8-43 Q16 allows attackers to cause a denial-of-service
    (application crash resulting from a heap-based buffer over-read) via a crafted TIFF image file, related to
    TIFFRewriteDirectory, TIFFWriteDirectory, TIFFWriteDirectorySec, and TIFFWriteDirectoryTagColormap in
    tif_dirwrite.c of LibTIFF. NOTE: this occurs because of an incomplete fix for CVE-2019-11597.
    (CVE-2019-15141)

    ImageMagick 7.0.8-35 has a memory leak in magick/xwindow.c, related to XCreateImage. (CVE-2019-16708)

    ImageMagick 7.0.8-35 has a memory leak in coders/dps.c, as demonstrated by XCreateImage. (CVE-2019-16709)

    ImageMagick 7.0.8-35 has a memory leak in coders/dot.c, as demonstrated by AcquireMagickMemory in
    MagickCore/memory.c. (CVE-2019-16710)

    ImageMagick 7.0.8-40 has a memory leak in Huffman2DEncodeImage in coders/ps2.c. (CVE-2019-16711)

    ImageMagick 7.0.8-43 has a memory leak in Huffman2DEncodeImage in coders/ps3.c, as demonstrated by
    WritePS3Image. (CVE-2019-16712)

    ImageMagick 7.0.8-43 has a memory leak in coders/dot.c, as demonstrated by PingImage in
    MagickCore/constitute.c. (CVE-2019-16713)

    ImageMagick before 7.0.8-54 has a heap-based buffer overflow in ReadPSInfo in coders/ps.c.
    (CVE-2019-17540)

    ImageMagick before 7.0.8-55 has a use-after-free in DestroyStringInfo in MagickCore/string.c because the
    error manager is mishandled in coders/jpeg.c. (CVE-2019-17541)

    A heap-based buffer overflow flaw was discovered in ImageMagick when writing SGI images with improper
    columns and rows properties. An attacker may trick a victim user into downloading a malicious image file
    and running it through ImageMagick, possibly executing code onto the victim user's system.
    (CVE-2019-19948)

    An out-of-bounds read was discovered in ImageMagick when writing PNG images. An attacker may abuse this
    flaw to trick a victim user into downloading a malicious image file and running it through ImageMagick,
    causing the application to crash. (CVE-2019-19949)

    In ImageMagick before 7.0.8-25, some memory leaks exist in DecodeImage in coders/pcd.c. (CVE-2019-7175)

    In ImageMagick before 7.0.8-25 and GraphicsMagick through 1.3.31, several memory leaks exist in
    WritePDFImage in coders/pdf.c. (CVE-2019-7397)

    In ImageMagick before 7.0.8-25, a memory leak exists in WriteDIBImage in coders/dib.c. (CVE-2019-7398)

    In ImageMagick 7.0.8-35 Q16, there is a stack-based buffer overflow in the function PopHexPixel of
    coders/ps.c, which allows an attacker to cause a denial of service or code execution via a crafted image
    file. (CVE-2019-9956)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2024-1926.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2016-5841.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-1000476.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-11166.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-12805.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-12806.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-13139.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-18251.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-18252.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-18254.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-18271.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-18273.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-10177.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-10804.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-10805.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-11656.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-12599.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-12600.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-13153.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-14434.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-14435.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-14436.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-14437.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-15607.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-16328.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-16749.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-16750.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-18544.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-20467.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-8804.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2018-9133.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-10131.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-10650.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-11470.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-11472.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-11597.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-11598.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-12974.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-12975.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-12976.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-12978.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-12979.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13133.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13134.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13135.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13295.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13297.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13300.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13301.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13304.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13305.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13306.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13307.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13309.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13310.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13311.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-13454.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-14980.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-14981.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-15139.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-15140.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-15141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16708.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16709.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16710.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16711.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16712.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16713.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-17540.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-17541.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-19948.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-19949.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-7175.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-7397.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-7398.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-9956.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ImageMagick' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19948");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ImageMagick-6.9.10.68-3.22.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-6.9.10.68-3.22.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.10.68-3.22.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-6.9.10.68-3.22.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.10.68-3.22.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-c++-devel-6.9.10.68-3.22.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debuginfo-6.9.10.68-3.22.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-debuginfo-6.9.10.68-3.22.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.10.68-3.22.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-devel-6.9.10.68-3.22.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.10.68-3.22.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-doc-6.9.10.68-3.22.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.10.68-3.22.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ImageMagick-perl-6.9.10.68-3.22.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
