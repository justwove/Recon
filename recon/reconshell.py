import cmd2
from pathlib import Path
import style
import pickle
import socket

import subprocess, shlex

import luigi
from luigi.util import inherits

from recon.config import tool_paths, defaults
from recon.recon import get_scans


class ReconShell(cmd2.Cmd):

    tools = {
    "luigi-service": {
        "installed": False,
        "dependencies": ["luigi"],
        "commands": [
            f"cp {str(Path(__file__).parent.parent / 'luigid.service')} /lib/systemd/system/luigid.service",
            f"cp $(which luigid) /usr/local/bin",
            "systemctl daemon-reload",
            "systemctl start luigid.service",
            "systemctl enable luigid.service",
        ],
        "shell": True,
    },
    "luigi": {"installed": False, "dependencies": ["pipenv"], "commands": ["pipenv install luigi"]},
    "pipenv": {
        "installed": False,
        "dependencies": None,
        "commands": ["apt-get install -y -q pipenv"],
    },
    "masscan": {
        "installed": False,
        "dependencies": None,
        "commands": [
            "git clone https://github.com/robertdavidgraham/masscan /tmp/masscan",
            "make -s -j -C /tmp/masscan",
            f"mv /tmp/masscan/bin/masscan {tool_paths.get('masscan')}",
            "rm -rf /tmp/masscan",
        ],
    },

}

    def __init__(self,  *args, **kwargs):
        self.prompt = "recon-pipeline>"

    def install_parser(self):

         # imported tools variable is in global scope, and we reassign over it later
        global tools

        # options for ReconShell's 'install' command
        install_parser = cmd2.Cmd2ArgumentParser()
        install_parser.add_argument(
            "tool", help="which tool to install", choices=list(tools.keys()) + ["all"]
        )

    @cmd2.with_argparser(install_parser)
    def do_install(self, args):
        """ Install any/all of the libraries/tools necessary to make the recon-pipeline function. """
        
         # imported tools variable is in global scope, and we reassign over it later
        global tools

        # create .cache dir in the home directory, on the off chance it doesn't exist
        cachedir = Path.home() / ".cache"
        cachedir.mkdir(parents=True, exist_ok=True)

        persistent_tool_dict = cachedir / ".tool-dict.pkl"

        if args.tool == "all":
            # show all tools have been queued for installation
            [
                self.async_alert(style(f"[-] {x} queued", fg="bright_white"))
                for x in tools.keys()
                if not tools.get(x).get("installed")
            ]

            for tool in tools.keys():
                self.do_install(tool)

            return

        if persistent_tool_dict.exists():
            tools = pickle.loads(persistent_tool_dict.read_bytes())

        if tools.get(args.tool).get("dependencies"):
            # get all of the requested tools dependencies

            for dependency in tools.get(args.tool).get("dependencies"):
                if tools.get(dependency).get("installed"):
                    # already installed, skip it
                    continue

                self.async_alert(
                    style(
                        f"[!] {args.tool} has an unmet dependency; installing {dependency}",
                        fg="yellow",
                        bold=True,
                    )
                )

                # install the dependency before continuing with installation
                self.do_install(dependency)

        if tools.get(args.tool).get("installed"):
            return self.async_alert(style(f"[!] {args.tool} is already installed.", fg="yellow"))
        else:

            # list of return values from commands run during each tool installation
            # used to determine whether the tool installed correctly or not
            retvals = list()

            self.async_alert(style(f"[*] Installing {args.tool}...", fg="bright_yellow"))

            for command in tools.get(args.tool).get("commands"):
                # run all commands required to install the tool

                # print each command being run
                self.async_alert(style(f"[=] {command}", fg="cyan"))

                if tools.get(args.tool).get("shell"):

                    # go tools use subshells (cmd1 && cmd2 && cmd3 ...) during install, so need shell=True
                    proc = subprocess.Popen(
                        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                else:

                    # "normal" command, split up the string as usual and run it
                    proc = subprocess.Popen(
                        shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )

                out, err = proc.communicate()

                if err:
                    self.async_alert(style(f"[!] {err.decode().strip()}", fg="bright_red"))

                retvals.append(proc.returncode)

            if all(x == 0 for x in retvals):
                # all return values in retvals are 0, i.e. all exec'd successfully; tool has been installed

                self.async_alert(style(f"[+] {args.tool} installed!", fg="bright_green"))

                tools[args.tool]["installed"] = True
            else:
                # unsuccessful tool install

                tools[args.tool]["installed"] = False

                self.async_alert(
                    style(
                        f"[!!] one (or more) of {args.tool}'s commands failed and may have not installed properly; check output from the offending command above...",
                        fg="bright_red",
                        bold=True,
                    )
                )

        # store any tool installs/failures (back) to disk
        pickle.dump(tools, persistent_tool_dict.open("wb"))

    def scan_parser(self, args):

        scan_parser = cmd2.Cmd2ArgumentParser()
        scan_parser.add_argument(
            "--results-dir",
        completer_method=cmd2.Cmd.path_complete,
        help="directory in which to save scan results",
        )
        scan_parser.add_argument(
            "--interface",
            choices_function=lambda: [x[1] for x in socket.if_nameindex()],
            help="which interface masscan should use",
        )
         # options for ReconShell's 'scan' command
        scan_parser.add_argument("scantype", choices_function=get_scans)
        
    @cmd2.with_argparser(scan_parser)
    def do_scan(self, args):
        """ Scan something.

        Possible scans include
            AmassScan           CORScannerScan      GobusterScan        SearchsploitScan
            ThreadedNmapScan    WebanalyzeScan      AquatoneScan        FullScan
            MasscanScan         SubjackScan         TKOSubsScan         HTBScan
        """
        self.async_alert(
            style(
                "If anything goes wrong, rerun your command with --verbose to enable debug statements.",
                fg="cyan",
                dim=True,
            )
        )

        # get_scans() returns mapping of {classname: [modulename, ...]} in the recon module
        # each classname corresponds to a potential recon-pipeline command, i.e. AmassScan, CORScannerScan ...
        scans = get_scans()

        # command is a list that will end up looking something like what's below
        # luigi --module recon.web.webanalyze WebanalyzeScan --target-file tesla --top-ports 1000 --interface eth0
        command = ["luigi", "--module", scans.get(args.scantype)[0]]
        command.extend(args.__statement__.arg_list)

        if args.verbose:
            # verbose is not a luigi option, need to remove it
            command.pop(command.index("--verbose"))

            subprocess.run(command)