import lief
from . import colors
from constants.const import EXCEPTION_VALUE

# check whether the PE has a manifest


def get(malware, csv):
    print((colors.WHITE + "\n------------------------------- {0:^13}{1:3}".format(
        "MANIFEST", " -------------------------------") + colors.DEFAULT))
    binary = lief.parse(malware)
    try:
        if binary.has_resources and not binary.resources_manager.has_manifest:
            print((colors.RED + "[X]" + colors.DEFAULT + " None"))
            csv.write("0,")
        else:
            binary.resources_manager  # Check if exist
            print((colors.GREEN + "[" + '\u2713' +
                   "]" + colors.DEFAULT + " PE has a manifest"))
            print(binary.resources_manager.manifest)
            csv.write("1,")
    except Exception as e:
        csv.write(f"{EXCEPTION_VALUE},")
