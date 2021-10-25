import luigi
from luigi.util import inherits
from luigi.contrib.external_program import ExternalProgramTask

from recon.config import tool_paths, defaults
from recon.web.targets import GatherWebTargets

@inherits(GatherWebTargets)
class TKOSubsScan(ExternalProgramTask):
    """ Use tko-subs to scan for potential subdomain takeovers.

    tko-subs commands are structured like the example below.

    tko-subs -domains=tesla.subdomains -data=/root/go/src/github.com/anshumanbh/tko-subs/providers-data.csv -output=tkosubs.tesla.csv

    An example of the corresponding luigi command is shown below.

    PYTHONPATH=$(pwd) luigi --local-scheduler --module recon.web.subdomain_takeover TKOSubsScan --target-file tesla --top-ports 1000 --interface eth0

    Args:
        exempt_list: Path to a file providing blacklisted subdomains, one per line. *--* Optional for upstream Task
        top_ports: Scan top N most popular ports *--* Required by upstream Task
        ports: specifies the port(s) to be scanned *--* Required by upstream Task
        interface: use the named raw network interface, such as "eth0" *--* Required by upstream Task
        rate: desired rate for transmitting packets (packets per second) *--* Required by upstream Task
        target_file: specifies the file on disk containing a list of ips or domains *--* Required by upstream Task
    """
    def requires(self):
        """ TKOSubsScan depends on GatherWebTargets to run.

        GatherWebTargets accepts exempt_list and expects rate, target_file, interface,
                         and either ports or top_ports as parameters

        Returns:
            luigi.Task - GatherWebTargets
        """
        args = {
            "rate": self.rate,
            "target_file": self.target_file,
            "top_ports": self.top_ports,
            "interface": self.interface,
            "ports": self.ports,
            "exempt_list": self.exempt_list,
        }
        return GatherWebTargets(**args)

    def output(self):
        """ Returns the target output for this task.

        Naming convention for the output file is tkosubs.TARGET_FILE.csv.

        Returns:
            luigi.local_target.LocalTarget
        """
        return luigi.LocalTarget(f"tkosubs{self.target_file}.csv")


    def program_args(self):
        """ Defines the options/arguments sent to tko-subs after processing.

        Returns:
            list: list of options/arguments, beginning with the name of the executable to run
        """
        command = [
            tool_paths.get("tko-subs"),
            f"-domains={self.input().path}",
            f"-data={tool_paths.get('tko-subs-dir')}/providers-data.csv",
            f"-output={self.output().path}",

        ]
        return command

@inherits(GatherWebTargets)
class SubjackScan(ExternalProgramTask):
    """ Use subjack to scan for potential subdomain takeovers.

    subjack commands are structured like the example below.

    subjack -w webtargets.tesla.txt -t 100 -timeout 30 -o subjack.tesla.txt -ssl

    An example of the corresponding luigi command is shown below.

    PYTHONPATH=$(pwd) luigi --local-scheduler --module recon.web.subdomain_takeover SubjackScan --target-file tesla --top-ports 1000 --interface eth0

    Args:
        threads: number of threads for parallel subjack command execution
        exempt_list: Path to a file providing blacklisted subdomains, one per line. *--* Optional for upstream Task
        top_ports: Scan top N most popular ports *--* Required by upstream Task
        ports: specifies the port(s) to be scanned *--* Required by upstream Task
        interface: use the named raw network interface, such as "eth0" *--* Required by upstream Task
        rate: desired rate for transmitting packets (packets per second) *--* Required by upstream Task
        target_file: specifies the file on disk containing a list of ips or domains *--* Required by upstream Task
    """
    threads = luigi.Parameter(default=defaults.get('threads', ""))

    def requires(self):
        """ SubjackScan depends on GatherWebTargets to run.

        GatherWebTargets accepts exempt_list and expects rate, target_file, interface,
                         and either ports or top_ports as parameters

        Returns:
            luigi.Task - GatherWebTargets
        """
        args = {
            "rate": self.rate,
            "target_file": self.target_file,
            "top_ports": self.top_ports,
            "interface": self.interface,
            "ports": self.ports,
            "exempt_list": self.exempt_list,
        }
        return GatherWebTargets(**args)

    def output(self):
        """ Returns the target output for this task.

        Naming convention for the output file is tkosubs.TARGET_FILE.csv.

        Returns:
            luigi.local_target.LocalTarget
        """
        return luigi.LocalTarget(f"subjack{self.target_file}.txt")

    def program_args(self):
        """ Defines the options/arguments sent to subjack after processing.

        Returns:
            list: list of options/arguments, beginning with the name of the executable to run
        """

        command = [
            tool_paths.get("subjack"),
            "-w",
            self.input().path,
            "-t",
            self.threads,
            "-a",
            "-timeout",
            "30",
            "-o",
            self.output().path,
            "-v",
            "-ssl",
            "-c",
            tool_paths.get("subjack-fingerprints"),
        ]

        return command
