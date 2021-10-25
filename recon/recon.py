import importlib, pkgutil
import inspect, sys

from collections import defaultdict

def get_scans():
    """ Iterates over the recon package and its modules to find all of the *Scan classes.
    *** A contract exists here that says any scans need to end with the word scan in order to be found by this function.
    Returns:
        dict() containing mapping of {modulename: classname} for all potential recon-pipeline commands
        ex:  defaultdict(<class 'list'>, {'AmassScan': ['recon.amass'], 'MasscanScan': ['recon.masscan'], ... })
    """
    scans = defaultdict(list)
    # recursively walk packages; import each module in each package
    # walk_packages yields ModuleInfo objects for all modules recursively on path
    # prefix is a string to output on the front of every module name on output.
    for loader, module_name, is_pkg in pkgutil.walk_packages(path=recon.__path__, prefix="recon."):
        importlib.import_module(module_name)
    # walk all modules, grabbing classes that we've written and add them to the classlist defaultdict
    # getmembers returns all members of an object in a list of tuples (name, value)
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.ismodule(obj) and not name.startswith("_"):
            # we're only interested in modules that don't begin with _ i.e. magic methods __len__ etc...
            for subname, subobj in inspect.getmembers(obj):
                if inspect.isclass(subobj) and subname.lower().endswith("scan"):
                    # now we only care about classes that end in [Ss]can
                    scans[subname].append(name)
    return scans