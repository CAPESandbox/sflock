from sflock.ident import (
    javascript, powershell, wsf, visualbasic, java, python, batch,
    udf_token_search, hta
)

ttf_hdr = (
    b'\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00'
)

# Empty string is a placeholder for the required version
# In the future this most likely be placed somewhere else in the code
class Deps:
    PYTHON = "python"
    WORD = "microsoft_word"
    POWERPOINT = "microsoft_powerpoint"
    OUTLOOK = "microsoft_outlook"
    GOOGLE_CHROME = "google_chrome"
    PHP = "php"
    RUBY = "ruby"
    EXCEL = "microsoft_excel"
    JAVA = "oracle_java"
    PDF = "acrobat_reader"
    PERL = "perl"
    DOTNET = "microsoft_dotnet"
    MEDIAPLAYER = "mediaplayer"
    FLASH = "flash"
    POWERSHELL = "powershell"
    UNARCHIVE = "unarchive"
    QUICKTIME = "quicktime"
    ACE = "ace"
    ARC = "arc"

class Platform:
    WINDOWS = "windows"
    MACOS = "darwin"
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"
    ANY_DESKTOP = (WINDOWS, MACOS, LINUX)
    ANY = (WINDOWS, MACOS, LINUX, ANDROID, IOS)

def eml_mht(f):
    filestart = f.contents[0:8192]
    for mandatory in (b"MIME-Version:", b"Content-Type:"):
        if mandatory not in filestart:
            return False

    headers = 0
    for header in (b"To:", b"From:", b"Subject:", b"Reply-To:"):
        if header in filestart:
            headers += 1

        if headers >= 3:
            return True, "Email message file", "eml", Platform.ANY

    return True, "MIME HTML single file webpage", "mht", Platform.ANY

def HTML(f):
    if hta(f):
        return True, "HTML Application file", "hta", (Platform.WINDOWS,)

    if wsf(f):
        return True, "Windows script file", "wsf", (Platform.WINDOWS,)

    data = eml_mht(f)
    if data:
        return data

    return True, "Hypertext Markup Language File", "html", Platform.ANY

def XML(f):
    if b"application/vnd.openxmlformats-officedocument.presentationml" in f.contents:
        return True, "Office file", "xml", Platform.ANY, Deps.WORD
    if b"application/vnd.openxmlformats-officedocument.wordprocessingml" in f.contents:
        return True, "Office file", "xml",  Platform.ANY, Deps.WORD
    if b"application/vnd.openxmlformats-officedocument" in f.contents:
        return True, "Office file", "doc",  Platform.ANY, Deps.WORD

    if hta(f):
        return True, "HTML Application file", "hta", (Platform.WINDOWS,)

    if wsf(f):
        return True, "Windows script file", "wsf", (Platform.WINDOWS,)

    return False, "XML file", "xml", Platform.ANY

def SAT(f):
    if f.get_child("ppt/presentation.xml"):
        return True, "Powerpoint", "ppt",  Platform.ANY, Deps.POWERPOINT
    return False

def SECTION(f):
    return False, 'CDF file', 'cdf', (Platform.WINDOWS,)

def Text(f):
    if javascript(f):
        return True, "Javascript file", "js", (Platform.WINDOWS,)
    if powershell(f):
        return True, "Powershell script", "ps1", (Platform.WINDOWS,), Deps.POWERSHELL
    if wsf(f):
        return True, "Windows script file", "wsf", (Platform.WINDOWS,)
    if visualbasic(f):
        return True, "Visual basic script file", "vbs", (Platform.WINDOWS,)
    if batch(f):
        return True, "DOS batch file", "bat", (Platform.WINDOWS,)
    if f.contents.startswith(b"WEB\n1"):
        return True, "IQY web query file", "iqy", Platform.ANY, Deps.EXCEL
    if f.contents.startswith(b"ID;P") and \
            f.contents.rstrip().endswith((b"E", b"E\n")):
        return True, "SYLK file", "slk", Platform.ANY, Deps.EXCEL
    if python(f):
        return True, "Python script", "py", Platform.ANY, Deps.PYTHON

    data = eml_mht(f)
    if data:
        return data

    if f.contents.startswith(b"{\\rt"):
        return True, "Rich Text Format File", "rtf", Platform.ANY

    header_offset = f.contents.find(b"[InternetShortcut]", 0, 1024 * 1024)
    if header_offset != -1 and b"URL=" in f.contents[header_offset:1024*1024]:
        return True, "URL shortcut file", "url", (Platform.WINDOWS,)

    return False, "Text", "txt", Platform.ANY

def ZIP(f):
    r = java(f)
    if r == "jar":
        return True, "Java Archive File", "jar", (Platform.WINDOWS, Platform.MACOS, Platform.LINUX, Platform.ANDROID), Deps.JAVA
    elif r == "apk":
        return True, "Android Package File", "apk", (Platform.ANDROID,)

    match = OFFICEXML(f)
    if match:
        return match

    for i in f.children:
        if i.magic == "AppleDouble encoded Macintosh file":
            return True, "Mountable disk image", "dmg", Platform.MACOS

    return False, "ZIP file", "zip", Platform.ANY, Deps.UNARCHIVE

def JAR(f):
    if java(f) == "apk":
        return True, "Android Package File", "apk", (Platform.ANDROID,)

    # Default
    return True, "Java Archive File", "jar", (Platform.WINDOWS, Platform.MACOS, Platform.LINUX, Platform.ANDROID), Deps.JAVA

def OCTET(f):
    if wsf(f):
        return True, "Windows script file", "wsf", (Platform.WINDOWS,)
    if f.contents.startswith(ttf_hdr):
        return False, "TrueType Font", "ttf", (Platform.WINDOWS,)

    if udf_token_search(f):
        return False, "UDF filesystem data", "iso", Platform.ANY

    return False, "Random bytes/Memory dump", "", ()

# This function is used to distinct DLL and EXE. This was unable to work on
# magic and mime. Because DLL files are matching positive on EXE mime/magic
def PE32(f):
    if "DLL" in f.magic:
        return True, "DLL file", "dll", (Platform.WINDOWS,)
    if ".Net" in f.magic:
        return True, "Exe file", "exe", (Platform.WINDOWS,), Deps.DOTNET
    return True, "Exe file", "exe", (Platform.WINDOWS,)

def FLASH(f):
    if "(compressed)" in f.magic:
        return True, "SWF file", "swf", Platform.ANY_DESKTOP, Deps.FLASH
    return True, "FLV file", "flv", Platform.ANY_DESKTOP, Deps.FLASH

def EXCEL(f):
    content = f.get_child("[Content_Types].xml")
    if not content or not content.contents:
        return False

    if b"ContentType=\"application/vnd.ms-excel.sheet.binary.macroEnabled.main" in content.contents:
        return True, "Microsoft Excel Open XML Spreadsheet", "xlsb", Platform.ANY, Deps.EXCEL
    if b"ContentType=\"application/vnd.ms-excel.sheet.macroEnabled" in content.contents:
        return True, "Microsoft Excel Open XML Spreadsheet", "xlsm", Platform.ANY, Deps.EXCEL
    if b"ContentType=\"application/vnd.ms-excel.addin.macroEnabled" in content.contents:
        return True, "Microsoft Excel Open XML Spreadsheet", "xlam", Platform.ANY, Deps.EXCEL
    if b"ContentType=\"application/vnd.ms-office.vbaProject" in content.contents:
        return True, "Microsoft Excel Open XML Spreadsheet", "xlsm", Platform.ANY, Deps.EXCEL
    return True, "Microsoft Excel Open XML Spreadsheet", "xlsx", Platform.ANY, Deps.EXCEL

def POWERPOINT(f):
    content = f.get_child("[Content_Types].xml")
    if not content or not content.contents:
        return False

    if b"ContentType=\"application/vnd.ms-powerpoint.slideshow.macroEnabled" in content.contents:
        return True, "PowerPoint Open XML Presentation", "ppsm", Platform.ANY, Deps.POWERPOINT
    if b"ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slideshow" in content.contents:
        return True, "PowerPoint Open XML Presentation", "ppsx", Platform.ANY, Deps.POWERPOINT
    if b"ContentType=\"application/vnd.ms-powerpoint.presentation.macroEnabled" in content.contents:
        return True, "PowerPoint Open XML Presentation", "pptm", Platform.ANY, Deps.POWERPOINT
    return True, "PowerPoint Open XML Presentation", "pptx", Platform.ANY, Deps.POWERPOINT

def WORD(f):
    content = f.get_child("[Content_Types].xml")
    if not content or not content.contents:
        return False

    if b"ContentType=\"application/vnd.ms-word.document.macroEnabled" in content.contents:
        return True, "Microsoft Open XML Presentation", "docm", Platform.ANY, Deps.WORD
    if b"ContentType=\"application/vnd.ms-word.template.macroEnabledTemplate" in content.contents:
        return True, "Microsoft Open XML Presentation", "dotm", Platform.ANY, Deps.WORD
    if b"ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.template" in content.contents:
        return True, "Microsoft Open XML Presentation", "dotx", Platform.ANY, Deps.WORD
    return True, "Microsoft Word Open XML Document", "docx", Platform.ANY, Deps.WORD

def _ooxml_excel(f):
    if f.get_child("xl/workbook.bin"):
        return True, "Microsoft Excel Open XML Spreadsheet", "xlsb", Platform.ANY, Deps.EXCEL

    if f.get_child("xl/macrosheets", regex=True) or f.get_child("xl/.*vbaProject", regex=True):
        return True, "Microsoft Excel Open XML Spreadsheet", "xlsm", Platform.ANY, Deps.EXCEL

    return True, "Microsoft Excel Open XML Spreadsheet", "xlsx", Platform.ANY, Deps.EXCEL

def OFFICEXML(f):
    contenttypes = f.get_child("[Content_Types].xml")
    if not contenttypes:
        return False

    contentchecks = {
        "xl": EXCEL,
        "word": WORD,
        "ppt": POWERPOINT
    }

    doctype = None
    contentchecked = False
    for child in f.children:
        if child.relapath.startswith("xl/"):
            doctype = "xl"
        if child.relapath.startswith("word/"):
            doctype = "word"
        if child.relapath.startswith("ppt/"):
            doctype = "ppt"

        if doctype and not contentchecked:
            data = contentchecks[doctype](f)
            if data:
                return data
            contentchecked = True

        if doctype == "xl":
            return _ooxml_excel(f)
        if doctype == "word":
            return True, "Microsoft Word Open XML Document", "doc", Platform.ANY, Deps.WORD
        if doctype == "ppt":
            return True, "PowerPoint Open XML Presentation", "ppt", Platform.ANY, Deps.POWERPOINT

    return False


# The magic and mime of a file will be used to match it to an extension or
# a function.
#   An extension will be used if the magic and mime are enough to distinct
#       different file types.
#   A function will be used to distinct file types on content.
#
# The default matches are designed to be order independent.
# This means the matches are made very specific for an extension.
# At first the string matches are used for identification,
# if the file does not match, the function matches are used.
string_matches = [
    # A string match tuple contains 7 elements.
    #   boolean: set True if string match
    #   boolean: set True if extension should be analysed
    #   list[] of strings:
    #       This list will be matched against the file magic
    #         The magic of the file is tokenized by splitting it on spaces.
    #         ex.: "PE32 (DLL) EXE" --> ["PE32", "(DLL)", "EXE"]
    #   string: Checks if mime contains this string.
    #   string: The extension for the match.
    #   string: A human friendly name of the match.
    #   string tuple: The platforms that support the extension.

    #
    # Office related
    #
    (True, ['Composite', 'Document', 'File', 'V2', 'Document'],
     "ms-excel", "xls",
     "Excel Spreadsheet", Platform.ANY, Deps.EXCEL),
    (True, ['Composite', 'Document', 'File', 'V2', 'Document'],
     "ms-powerpoint", "ppt", "PowerPoint Presentation", Platform.ANY, Deps.POWERPOINT),
    (True, ['Composite', 'Document', 'File', 'V2'], "msword", "doc",
     "Microsoft Word Document", Platform.ANY, Deps.WORD),
    (True, ['OpenDocument', 'Text'], "oasis.opendocument.text", "odt",
     "OpenDocument Text Document", Platform.ANY, Deps.WORD),
    (True, ['OpenOffice'], "octet-stream", "odt",
     "OpenDocument Text Document", Platform.ANY, Deps.WORD),
    (True, ['Hangul', '(Korean)', 'Word', 'Processor'], "hwp", "hwp",
     "Hangul (Korean) Word Processor", Platform.ANY, Deps.WORD),
    (True, ['OpenDocument', 'Spreadsheet'], "opendocument.spreadsheet",
     "ods", "OpenDocument Spreadsheet", Platform.ANY, Deps.EXCEL),
    (True, ['OpenDocument'], "opendocument.presentation", "odp",
     "OpenDocument Presentation", Platform.ANY, Deps.POWERPOINT),
    (True, ['CDFV2', 'Microsoft', 'Excel'], "ms-excel", "xls",
     "Excel Spreadsheet", Platform.ANY, Deps.EXCEL),
    (True, ['Composite', 'Document', 'File', 'V2', 'Document'],
     "ms-office", "cdf", "CDF file", Platform.ANY, Deps.WORD), # TODO, look at these cdf files and the right extension
    (False, ['CDFV2', 'Encrypted'], 'encrypted', "cdf", "CDF file",
     Platform.ANY, Deps.WORD), # TODO, look at these cdf files and the right extension
    (False, ['CDFV2', 'Microsoft', 'Outlook'],
     'ms-outlook', "msg", "Microsoft outlook message", Platform.ANY, Deps.OUTLOOK),


    #
    # Archive/compression related
    #
    (False, ['7-zip'], "x-7z-compressed", "7z", "Compressed archive",
     Platform.ANY_DESKTOP, Deps.UNARCHIVE),
    (False, ['bzip2'], "x-bzip2", "bzip", "Compressed file", (Platform.LINUX,), Deps.UNARCHIVE),
    (False, ['gzip'], "gzip", "gz", "GZIP compressed file", (Platform.LINUX,), Deps.UNARCHIVE),
    (False, ['ACE', 'archive'], "octet-stream", "ace", "ACE archive",
     Platform.ANY_DESKTOP, Deps.ACE),
    (False, ['MS', 'Compress'], "octet-stream", "zip",
     "Microsoft (de)compressor", (Platform.WINDOWS,)),
    (False, ['Microsoft', 'Cabinet', 'archive', 'data'], "vnd.ms-cab",
     "cab", "Windows Cabinet File", (Platform.WINDOWS,)),
    (False, ['POSIX', 'tar'], "tar", "tar",
     "Consolidated Unix File Archive", (Platform.LINUX,)),
    (False, ['RAR'], "rar", "rar", "WinRAR Compressed Archive",
     Platform.ANY_DESKTOP, Deps.UNARCHIVE),
    (False, ['KGB'], "octet-stream", "kgb",
     "Discontinued file archiver ",
     (Platform.WINDOWS, Platform.LINUX)),
    (False, ['ASD', 'archive'], "octet-stream", "asd",
     "ASD archive", (Platform.WINDOWS,)),
    (False, ['ARJ'], "x-arj", "arj", "Compressed file archive",
     (Platform.WINDOWS, Platform.MACOS), Deps.UNARCHIVE),
    (False, ['ARC'], "x-arc", "arc", "Compressed file",
     (Platform.WINDOWS, Platform.MACOS), Deps.ARC),
    (False, ["PowerISO", "Direct-Access-Archive"], "", "daa",
     "PowerISO Direct-Access-Archive", Platform.ANY_DESKTOP,),

    #
    # Apple related
    #
    (False, ['Apple', 'HFS'], "octet-stream", "ico", "Icon File",
     (Platform.MACOS,)),
    (False, ['zlib'], "zlib", "dmg", "Apple Disk Image", (Platform.MACOS,)),
    (False, ['AppleSingle'], "octet-stream", "as",
     "Mac File format", (Platform.MACOS,)),
    (False, ['AppleDouble'], "octet-stream", "adf",
     "iOS application archive file", (Platform.MACOS,)),
    (False, ['Apple', 'binary', 'property'], "octet-stream",
     "plist", "Apple binary", (Platform.MACOS,)),
    (False, ['iOS', 'App'], "x-ios-app", "ipa",
     "iOS application archive file", (Platform.IOS,)),
    (False, ['Macintosh', 'HFS'], "octet-stream", "hfs",
     "Macintosh HFS", (Platform.MACOS,)),
    (False, ['Symbian'], "x-sisx-app", "sisx",
     "Software Installation Script", (Platform.MACOS,)),
    (True, ['Mach-O'], "x-mach-binary", "o", "Bitmap graphic",
     (Platform.MACOS,)),

    #
    # Visual images
    #
    (False, ['PNG'], "png", "png", "Portable Network Graphic", Platform.ANY),
    (False, ['JPEG'], "jpeg", "jpg", "JPEG Image", Platform.ANY),
    (False, ['SVG'], "svg+xml", "svg", "Scalable vector graphics", Platform.ANY),
    (False, ['PC', 'bitmap'], "x-ms-bmp", "bmp", "Bitmap Image File", Platform.ANY),
    (False, ['Targa'], "x-tga", "tga",
     "Truevision Graphics Adapter image file", (Platform.WINDOWS, Platform.MACOS)),
    (False, ['GIF', 'image', 'data'], "gif", "gif",
     "Graphical Interchange Format File", Platform.ANY),
    (False, ['JNG'], "x-jng", "jng", "Image file related to PNG",
     Platform.ANY),
    (False, ['GIMP', 'XCF', 'image'], "x-xcf", "xcf", "GIMP XFC file",
     Platform.ANY),
    (False, ['TIFF'], "tiff", "tiff", "Tagged Image File Format",
     (Platform.WINDOWS, Platform.LINUX)),  # @todo, add android, ios, mac?
    (False, ['icon'], "image/x-icon", "ico", "Icon File", Platform.ANY),

    #
    # Audio / video
    #
    (False, ['RIFF'], "x-wav", "wav", "WAVE Audio File", (Platform.WINDOWS,), Deps.MEDIAPLAYER),
    (True, ['Macromedia', 'Flash', 'data', '(compressed)'],
     "x-shockwave-flash", "swf", "Shockwave Flash Movie", (Platform.WINDOWS,), Deps.FLASH),  # todo
    (True, ['RIFF'], "msvideo", "avi", "Audio Video Interleave File",
     (Platform.WINDOWS,), Deps.MEDIAPLAYER),
    (True, ['Macromedia', 'Flash', 'Video'], "x-flv", "flv",
     "Flash Video File", (Platform.WINDOWS,), Deps.FLASH),
    (False, ['ISO'], "quicktime", "qt", "QuickTime file", (Platform.MACOS,), Deps.QUICKTIME), # todo, make magic more specific
    (False, ['MPEG', 'sequence'], "", "mpeg",
     "Compression for video and audio",
     (Platform.WINDOWS,), Deps.MEDIAPLAYER),
    (False, ['MPEG', 'transport'], "", "mpeg",
     "Compression for video and audio",
     (Platform.WINDOWS,), Deps.MEDIAPLAYER),
    (False, ['PCH', 'ROM'], "octet", "rom", "N64 Game ROM File",
     (Platform.WINDOWS,)),
    (False, ['ISO', 'Media'], "video/mp4", "mp4", "MPEG-4 Video File",
     Platform.ANY, Deps.MEDIAPLAYER),
    (True, ['contains:MPEG'], "mpeg", "mp3", "MP3 Audio File",
     (Platform.ANY), Deps.MEDIAPLAYER),
    (False, ['3GPP', 'MPEG', 'v4'], "octet-stream", "3gp",
     "3GPP Multimedia File", (Platform.WINDOWS,), Deps.MEDIAPLAYER),
    (False, ['FLAC'], "x-flac", "flac", "Free lossless audio codec",
     (Platform.WINDOWS), Deps.MEDIAPLAYER),
    (False, ['FLC'], "x-flc", "flc", "Animation file", (Platform.MACOS,), Deps.MEDIAPLAYER),
    (False, ['RealMedia', 'file'], "vnd.rn-realmedia", "rm", "RealMedia file", (Platform.WINDOWS,), Deps.MEDIAPLAYER),

    #
    #  Scripts
    #
    (True, ['Python', 'script'], "x-python", "py", "Python Script",
     Platform.ANY_DESKTOP, Deps.PYTHON),
    (False, ['PostScript', 'document'], "postscript", "ps",
     "Encapsulated PostScript File", (Platform.WINDOWS,), Deps.PDF),
    (False, ['PHP'], "x-php", "php", "PHP Source Code File",
     (Platform.WINDOWS, Platform.LINUX, Platform.MACOS), Deps.PHP),
    (True, ['Perl', 'script'], "x-perl", "perl", "Perl script",
     (Platform.WINDOWS, Platform.LINUX), Deps.PERL),
    (True, ['Bourne-Again', 'shell'], "x-shellscript", "sh",
     "Shell script", (Platform.LINUX,)),
    (True, ['POSIX', 'shell', 'script', 'ASCII', 'text', 'executable'], "x-shellscript", "sh",
     "Shell script", (Platform.LINUX,)),
    (True, ['Ruby', 'script'], "x-ruby", "rb",
     "Ruby interpreted file", (Platform.WINDOWS,), Deps.RUBY),
    (True, ['DOS', 'batch'], "x-msdos-batch", "bat",
     "DOS batch file", (Platform.WINDOWS,)),
    #
    # Binaries
    #
    (True, ['COM', 'executable'], "application", "com",
     "DOS Command File", (Platform.WINDOWS,)),
    (False, ['Debian', 'binary', 'package'],
     "vnd.debian.binary-package", "deb", "Debian Software Package", (Platform.LINUX,)),
    (True, ['(DLL)'], "x-dosexec", "dll", "Dynamic linked library",
     (Platform.WINDOWS,)),
    (True, ['MS-DOS'], "x-dosexec", "exe", "Executable", (Platform.WINDOWS,)),
    (True, ['ELF'], "application", "elf", "Linux Executable",
     (Platform.LINUX,)),
    (True, ['MS-DOS'], "x-dosexec", "exe", "DOS MZ executable ",
     (Platform.WINDOWS,)),
    (True, ['Composite', 'Document', 'File', 'V2', 'Document'], "msi",
     "msi", "Windows Installer Package", (Platform.WINDOWS,)),
    (False, ['Dzip'], "octet-stream", "dzip", "Witcher 2 game file",
     (Platform.WINDOWS,)),
    (False, ['RPM'], "rpm", "rpm", "Red Hat Package Manager File", (Platform.LINUX,)),
    (True, ['PDF'], "pdf", "pdf", "Portable Document Format File",
     (Platform.WINDOWS,), Deps.PDF),
    (True, ['Rich', 'Text'], "rtf", "rtf", "Rich Text Format File",
     (Platform.WINDOWS,)),
    (True, ['MS', 'Windows', 'shortcut'], "octet-stream", "lnk",
     "Windows Shortcut", (Platform.WINDOWS,)),
    (False, ['Adobe', 'Photoshop', 'Image'], "adobe.photoshop", "psd",
     "Adobe Photoshop Document", (Platform.WINDOWS, Platform.MACOS)),
    (True, ['Microsoft', 'ASF'], "ms-asf", "asf",
     "Advanced Systems Format File", (Platform.WINDOWS,)),
    (True, ['Google', 'Chrome', 'extension'], "x-chrome-extension",
     "crx", "Chrome Extension", (Platform.WINDOWS, Platform.LINUX, Platform.MACOS), Deps.GOOGLE_CHROME),
    (True, ['compiled', 'Java', 'class'], "java-applet", "class",
     "Java Class File", (Platform.WINDOWS, Platform.MACOS), Deps.JAVA),
    (False, ['Intel', 'serial', 'flash'], "octet", "rom",
     "N64 Game ROM File",
     (Platform.WINDOWS,)),  # todo
    (False, ['BitTorrent'], "x-bittorrent", "bittorrent",
     "Bittorent link", (Platform.WINDOWS,Platform.MACOS)),
    (True, ['compiled', 'Java', 'class'], "x-java-applet", "class",
     "Java class file", (Platform.WINDOWS,)),  # todo
    (False, ['MIDI'], "midi", "midi",
     "Musical Instrument Digital Interface", (Platform.WINDOWS,)),
    (False, ['Ogg'], "ogg", "ogg", "Free open container format ",
     (Platform.WINDOWS, Platform.MACOS)),
    (False, ['ISO', '9660'], "x-iso9660-image", "iso", "ISO Image",
     Platform.ANY),
    (False, ['UDF', 'filesystem', 'data'], "x-iso9660-image", "iso", "ISO Image",
     (Platform.WINDOWS,)),
    (False, ['TeX', 'font'], "x-tex-tfm", "latex", "LaTeX file format",
     (Platform.WINDOWS, Platform.LINUX)),  # todo
    (False, ['awk'], "x-awk", "awk", "Script for text processing",
     (Platform.LINUX,)),
    (False, ['Adobe', 'InDesign'], "octet-stream", "indd",
     "InDesign project file", (Platform.WINDOWS,)),  # todo
    (False, ['Windows', 'Enhanced', 'Metafile'], "octet-stream", "emf",
     "Windows enhanced metafile", (Platform.WINDOWS,)),
    (False, ['E-book'], "octet-stream", "ebook", "Ebook file",
     (Platform.WINDOWS,)),
    (False, ['TrueType', 'Font'], "font-sfnt", "ttf", "TrueType Font",
     (Platform.WINDOWS)),
    (False, ['capture'], "tcpdump.pcap", "pcap", "Network traffic data",
     (Platform.WINDOWS,)),
    (False, ['capture'], "octet-stream", "pcap", "Network traffic data",
     (Platform.WINDOWS,)),
    (False, ['Netscape', 'cookie'], "plain", "iecookie", "Cookie for ie",
    (Platform.WINDOWS)),
    (True, ["Internet", "shortcut"], "plain", "url",
     "URL shortcut file", (Platform.WINDOWS,)),
]

# Add function variables
func_matches = [
    (['Composite', 'Document', 'File', 'V2', 'Document', "Can't", 'read',
      'SAT'], "application/CDFV2", SAT),
    (['Composite', 'Document', 'File', 'V2', 'Document', 'Cannot', 'read',
      'section'],
     "application/CDFV2", SECTION),
    (['Zip'], "zip", ZIP),
    (['(JAR)'], "java-archive", JAR),
    (['data'], "octet", OCTET),
    (['XML'], "xml", XML),
    (['HTML', 'document'], "html", HTML),
    (['text'], "text", Text),
    (['text'], "plain", Text),
    (['Generic', 'INItialization', 'configuration'], "", Text),
    (['PE32'], "x-dosexec", PE32),
    (['PE32+'], "x-dosexec", PE32),
    (['Macromedia', 'Flash', 'data'], "x-shockwave-flash", FLASH),
    (['Microsoft', 'Excel'],
     "openxmlformats-officedocument.spreadsheetml.sheet", OFFICEXML),
    (['Microsoft', 'PowerPoint'],
     "openxmlformats-officedocument.presentationml.presentation", OFFICEXML),
    (['Microsoft', 'Word'],
     "openxmlformats-officedocument.wordprocessingml.document", OFFICEXML),
    (["Microsoft"], "openxmlformats-officedocument", OFFICEXML),
    (["Microsoft", "OOXML"], "octet", OFFICEXML),
    (["SMTP"], "", eml_mht),
    (["MIME"], "", eml_mht),
    (["news", "mail"], "", eml_mht),
]

def identify(f):
    # return: selected, name, extension, platform, dependencies
    # Loop through every potential match
    fmagic = [i.replace(",", "") for i in f.magic.split(" ")]

    for match in string_matches:
        selected, magic, mime = match[:3]
        # Check if it matches
        tokens = all(elem in fmagic for elem in magic)

        if tokens and mime in f.mime:
            # If the match is a function
            # Check if there is already a match found (on a non function match)
            # The non function matches are narrower
            if len(match) == 7:
                return selected, match[4], match[3], match[5], match[6]

            return selected, match[4], match[3], match[5], ''

    for match in func_matches:
        magic, mime = match[:2]
        # Check if it matches
        tokens = all(elem in fmagic for elem in magic)
        if tokens and mime in f.mime:
            # If the match is a function
            # Check if there is already a match found (on a non function match)
            # The non function matches are narrower
            data = match[2](f)
            if data:
                if len(data) == 4:
                    return (*data, "")
                return (*data,)

    return None