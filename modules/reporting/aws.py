# Copyright (C) 2016 Mike Sconzo (sooshie@gmail.com).
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import shutil
import json
import os
import re

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File

import boto.s3
import boto.s3.key

log = logging.getLogger("aws")

class AWS(Report):
    """Stores reports and files in S3."""
    order = 10000
    s3_region = ''

    def relocate_to_s3(self, sample_id, local_path, dst_bucket_name):
        """Wrapper for writing multiple files in a directory to S3"""
        if os.path.isdir(local_path):
            for local_file in os.listdir(local_path):
                current = os.path.join(local_path, local_file)
                with open(current, 'rb') as infile:
                    self.save_to_s3(dst_bucket_name, "{0}/{1}".format(sample_id, local_file), infile.read())

    def save_to_s3(self, s3_bucket_name, s3_key_name, s3_key_contents):
        """Save a specific file to a specific location in S3"""
        try:
            s3_connection = boto.s3.connect_to_region(self.s3_region, aws_access_key_id=self.s3_access_key, aws_secret_access_key=self.s3_secret_key)
            s3_bucket = s3_connection.get_bucket(s3_bucket_name)
            s3_key = boto.s3.key.Key(s3_bucket)
            s3_key.key = s3_key_name
        except Exception as e:
            log.error("Can't write {0} to AWS bucket {1}".format(s3_key_name, s3_bucket_name))
            log.error(str(e))
            return str(e)
        if not s3_key.exists():
            new_s3_key = s3_bucket.new_key(s3_key_name)
            new_s3_key.set_contents_from_string(s3_key_contents)
        return ''

    def get_from_s3(self, s3_bucket_name, s3_key_name):
        """Retreive a file from S3"""
        s3_connection = boto.s3.connect_to_region(self.s3_region, aws_access_key_id=self.s3_access_key, aws_secret_access_key=self.s3_secret_key)
        s3_bucket = s3_connection.get_bucket(s3_bucket_name)
        s3_key = s3_bucket.get_key(s3_key_name)
        if s3_key:
            return s3_key.get_contents_as_string()
        else:
            log.error("Can't retrieve {0} from AWS bucket {1}".format(s3_key_name, s3_bucket_name))
            return ''

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to S3.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        self.s3_region = self.options.get("region", "us-west-2")
        self.s3_access_key = self.options.get("access_key", "")
        self.s3_secret_key = self.options.get("secret_key", "")
        s3_reports_bucket_name = self.options.get("reports_bucket", "")
        s3_shots_bucket_name = self.options.get("shots_bucket", "")
        s3_samples_bucket_name = self.options.get("samples_bucket", "")
        s3_files_bucket_name = self.options.get("files_bucket", "")
        s3_aux_bucket_name = self.options.get("aux_bucket", "")
        s3_logs_bucket_name = self.options.get("logs_bucket", "")
        s3_pcap_bucket_name = self.options.get("pcap_bucket", "")
        s3_md5_bucket_name = self.options.get("md5_bucket", "")
        cleanup = self.options.get("cleanup", False)

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = dict(results)

        if not "network" in report:
            report["network"] = {}

        # Add screenshot paths
        report["shots"] = []
        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            shots = [shot for shot in os.listdir(shots_path)
                     if shot.endswith(".jpg")]
            for shot_file in sorted(shots):
                shot_path = os.path.join(self.analysis_path, "shots",
                                         shot_file)
                screenshot = File(shot_path)
                if screenshot.valid():
                    #report["shots"].append("{0}/{1}".format(results['info']['id'], shot_file))
                    report["shots"].append(shot_file.replace(".jpg", ""))

        # Store chunks of API calls in a different collection and reference
        # those chunks back in the report.
        # Also allows paging of the reports.
        if "behavior" in report and "processes" in report["behavior"]:
            new_processes = []
            for process in report["behavior"]["processes"]:
                new_process = dict(process)

                chunk = []
                chunks_ids = []
                chunk_count = 0
                # Using this type of prefix is useful because you can always re-construct it from
                # the original results
                #chunk_prefix = str(results['info']['id']) + '/' + process['process_name']
                chunk_prefix = str(results['info']['id']) + '/' + str(process['process_id'])
                # Loop on each process call.
                for index, call in enumerate(process["calls"]):
                    # If the chunk size is 100 or if the loop is completed then
                    # store the chunk in S1.

                    if len(chunk) == 100:
                        chunk_name = "{0}.{1}".format(chunk_prefix, chunk_count)
                        #log.debug("INFO TIME!")
                        #log.debug("%s %s %s" %(s3_reports_bucket_name, chunk_name, chunk_prefix))
                        #log.debug(chunk_prefix)
                        err = self.save_to_s3(s3_reports_bucket_name, chunk_name, json.dumps(chunk))
                        if err != '':
                            log.error("Non-size related issue saving analysis JSON to S3 for chunk {0} - {1}".format(chunk_name, err))
                        else:
                            chunks_ids.append("{0}.{1}".format(chunk_prefix, chunk_count))
                            chunk_count += 1
                        chunk = []

                    # Append call to the chunk.
                    chunk.append(call)

                # Store leftovers.
                if chunk:
                    chunk_name = "{0}.{1}".format(chunk_prefix, chunk_count)
                    #log.debug("%s %s %s" %(s3_reports_bucket_name, chunk_name, chunk_prefix))
                    err = self.save_to_s3(s3_reports_bucket_name, chunk_name, json.dumps(chunk))
                    if err != '':
                        log.error("Non-size related issue saving analysis JSON to S3 for chunk {0} - {1}".format(chunk_name, err))
                    else:
                        chunks_ids.append("{0}.{1}".format(chunk_prefix, chunk_count))

                # Add list of chunks.
                new_process["calls"] = chunks_ids
                new_processes.append(new_process)

            # Store the results in the report.
            report["behavior"] = dict(report["behavior"])
            report["behavior"]["processes"] = new_processes

        #Other info we want Quick access to from the web UI
        if results.has_key("virustotal") and results["virustotal"] and results["virustotal"].has_key("positives") and results["virustotal"].has_key("total"):
            report["virustotal_summary"] = "%s/%s" % (results["virustotal"]["positives"], results["virustotal"]["total"])
        if results.has_key("suricata") and results["suricata"]:
            if results["suricata"].has_key("tls") and len(results["suricata"]["tls"]) > 0:
                report["suri_tls_cnt"] = len(results["suricata"]["tls"])
            if results["suricata"].has_key("alerts") and len(results["suricata"]["alerts"]) > 0:
                report["suri_alert_cnt"] = len(results["suricata"]["alerts"])
            if results["suricata"].has_key("files") and len(results["suricata"]["files"]) > 0:
                report["suri_file_cnt"] = len(results["suricata"]["files"])
            if results["suricata"].has_key("http") and len(results["suricata"]["http"]) > 0:
                report["suri_http_cnt"] = len(results["suricata"]["http"])
            if results["suricata"].has_key("ssh") and len(results["suricata"]["ssh"]) > 0:
                report["suri_ssh_cnt"] = len(results["suricata"]["ssh"])
            if results["suricata"].has_key("dns") and len(results["suricata"]["dns"]) > 0:
                report["suri_dns_cnt"] = len(results["suricata"]["dns"])

        # Store the report (it's 'object id' is simply the analysis id)
        # First make sure it's not too big (5gb limit)
        data = json.dumps(report)
        if len(data) < 5000000000:
            err = self.save_to_s3(s3_reports_bucket_name, results['info']['id'], data)
            if err != '':
                log.error("Non-size related issue saving analysis JSON to S3 for report {0} - {1}".format(results['info']['id'], err))
        else:
            log.error("JSON for analysis id {0} is greater than 5GB".format(results['info']['id']))

        #processes the rest of the analysis files and put them in S3
        if s3_shots_bucket_name != '':
            shots_path = os.path.join(results['info']['id'], self.analysis_path, "shots")
            self.relocate_to_s3(results['info']['id'], shots_path, s3_shots_bucket_name)
        if s3_pcap_bucket_name != '':
            if os.path.isfile(self.analysis_path + '/dump.pcap'):
                with open(self.analysis_path + '/dump.pcap', 'rb') as infile:
                    self.save_to_s3(s3_pcap_bucket_name, "{0}/dump.pcap".format(results['info']['id']), infile.read())
            if os.path.isfile(self.analysis_path + '/dump_sorted.pcap'):
                with open(self.analysis_path + '/dump_sorted.pcap', 'rb') as infile:
                    self.save_to_s3(s3_pcap_bucket_name, "{0}/dump_sorted.pcap".format(results['info']['id']), infile.read())
        if s3_aux_bucket_name != '':
            aux_path = os.path.join(results['info']['id'], self.analysis_path, "aux")
            self.relocate_to_s3(results['info']['id'], aux_path, s3_aux_bucket_name)
        if s3_logs_bucket_name != '':
            logs_path = os.path.join(results['info']['id'], self.analysis_path, "logs")
            self.relocate_to_s3(results['info']['id'], logs_path, s3_logs_bucket_name)
        if s3_samples_bucket_name != '':
            sample = os.path.realpath(self.analysis_path + '/binary')
            with open(sample, 'rb') as infile:
                self.save_to_s3(s3_samples_bucket_name, results['target']['file']['sha256'], infile.read())
        #log.debug(s3_files_bucket_name)
        if s3_files_bucket_name != '':
            #log.debug(self.analysis_path)
            for root, dirnames, filenames in os.walk(self.analysis_path + '/files'):
                #log.debug(filenames)
                for filename in filenames:
                    key_name = str(results['info']['id']) + '/' + root.split(os.sep)[-1] + '/' + filename
                    if not filename.endswith('_info.txt'):
                        key_name = str(results['info']['id']) + '/' + root.split(os.sep)[-1]
                    #log.debug(key_name)
                    with open(os.path.join(root, filename), 'rb') as infile:
                        self.save_to_s3(s3_files_bucket_name, key_name, infile.read())
        if s3_md5_bucket_name != '':
            info = {}
            info.update(report['info'])
            info.update(report['target'])
            self.save_to_s3(s3_md5_bucket_name, results['target']['file']['md5'], json.dumps(info))

        if cleanup:
            shutil.rmtree(self.analysis_path)
