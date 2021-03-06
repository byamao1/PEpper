import lief
from . import colors
from constants.const import EXCEPTION_VALUE

# check if PE has a version


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "VERSION", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    try:
        if binary.has_resources and not binary.resources_manager.has_version:
            print((colors.RED + "[X]" + colors.DEFAULT + " PE has no version"))
            csv.write("0,")
        else:
            binary.resources_manager # Check if exist
            print((colors.GREEN + "[" + '\u2713' +
                   "]" + colors.DEFAULT + " PE has a version"))
            print((str(binary.resources_manager.version.string_file_info)))
            csv.write("1,")
    except Exception as e:
        csv.write(f"{EXCEPTION_VALUE},")
