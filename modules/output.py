from . import colors

# print the output


def get(csv_name):
    print("\n------------------------------- {0:^13}{1:3}".format(
        "DONE", " -------------------------------"))
    print(colors.GREEN + "[" + str('\u2713') + "]" +
          colors.DEFAULT + f" Output written in {csv_name}")
