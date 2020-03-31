import ops
import iopc

pkg_path = ""
output_dir = ""
dst_include_dir = ""

def set_global(args):
    global pkg_path
    global output_dir 
    global dst_include_dir
    pkg_path = args["pkg_path"]
    output_dir = args["output_path"]
    dst_include_dir = ops.path_join("include",args["pkg_name"])

def MAIN_ENV(args):
    set_global(args)

    ops.exportEnv(ops.setEnv("SUPPORT_UDS", "y"))
    ops.exportEnv(ops.setEnv("SUPPORT_DB", "n"))
    ops.exportEnv(ops.setEnv("SUPPORT_INPUT", "n"))
    ops.exportEnv(ops.setEnv("SUPPORT_LXC", "n"))
    ops.exportEnv(ops.setEnv("SUPPORT_QMP", "y"))

    return False

def MAIN_EXTRACT(args):
    set_global(args)

    ops.copyto(ops.path_join(pkg_path, "src/."), output_dir)

    return True

def MAIN_PATCH(args, patch_group_name):
    set_global(args)
    for patch in iopc.get_patch_list(pkg_path, patch_group_name):
        if iopc.apply_patch(build_dir, patch):
            continue
        else:
            sys.exit(1)

    return True

def MAIN_CONFIGURE(args):
    set_global(args)

    return True

def MAIN_BUILD(args):
    set_global(args)

    #extra_conf = []
    #extra_conf.append("CROSS_COMPILE=" + crosscc)
    #iopc.make(output_dir, extra_conf)
    iopc.make(output_dir)

    return False

def MAIN_INSTALL(args):
    set_global(args)

    iopc.installBin(args["pkg_name"], ops.path_join(output_dir, "include/."), dst_include_dir)
    iopc.installBin(args["pkg_name"], ops.path_join(output_dir, "iopcshellmgr"), "usr/bin")

    return False

def MAIN_SDKENV(args):
    set_global(args)

    return False

def MAIN_CLEAN_BUILD(args):
    set_global(args)

    return False

def MAIN(args):
    print "iopclauncher"

