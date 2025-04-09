import understand
import sys
import subprocess

from pprint import pprint


def printCallByTree(ent, depth, seen, label="|", file=None):
    if depth > 8:
        return

    if file:
        with open(file, "a") as f:
            f.write((label * depth) + " " + ent.name() + "\n")
    else:
        print((label * depth), ent.name())

    if ent.id() in seen:
        return
    seen[ent.id()] = 1

    for ref in sorted(ent.refs("useby", "", True), key=lambda ref: ref.ent().name()):
        if file:
            with open(file, "a") as f:
                f.write(("/" * (depth + 1)) + " " + ref.ent().name() + "\n")
        else:
            print(("/" * (depth + 1)), ent.name())
    for ref in sorted(
        ent.refs("assignby functionPtr", "", True), key=lambda ref: ref.ent().name()
    ):
        if file:
            with open(file, "a") as f:
                f.write(("\\" * (depth + 1)) + " " + ref.ent().name() + "\n")
        else:
            print(("\\" * (depth + 1)), ent.name())

    for ref in sorted(ent.refs("callby", "", True), key=lambda ref: ref.ent().name())[:10]:
        printCallByTree(ref.ent(), depth + 1, seen, "|", file)


def do_test():
    db = understand.open("/home/v1me/workspace/quick_work/misc_kernel/linux.und")
    objs = db.lookup("newseg", "Function")
    assert len(objs) == 1
    obj = objs[0]

    printCallByTree(obj, 0, {}, file="startgrid/newseg.txt")


def do_run():
    db = understand.open("/home/v1me/workspace/quick_work/misc_kernel/linux.und")
    with open("function_list.txt", "r") as f:
        function_list = f.read().splitlines()

    subprocess.run("rm -rf startgrid/*", shell=True)

    err_list = []

    for function in function_list:
        print(f"Function: {function}")
        objs = db.lookup(function, "C Function")
        objs = [obj for obj in objs if obj.name() == f"{function}"]
        # objs = db.lookup_uniquename(function)
        # names = [obj.name() for obj in objs]
        # print(names)
        print([obj.name() for obj in objs])
        if len(objs) != 1:
            err_list.append(function)
            continue
        obj = objs[0]
        printCallByTree(obj, 0, {}, file=f"startgrid/{function}")

    print("Error list:", err_list)
    with open("error_list", "w") as f:
        f.write("\n".join(err_list))

if __name__ == "__main__":
    # do_test()
    do_run()
