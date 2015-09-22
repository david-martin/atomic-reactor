"""
Copyright (c) 2015 Red Hat, Inc
All rights reserved.

This software may be modified and distributed under the terms
of the BSD license. See the LICENSE file for details.
"""

from __future__ import unicode_literals

from collections import namedtuple
import json
import hashlib
import os
import subprocess
from tempfile import NamedTemporaryFile
import time

import koji
from atomic_reactor import __version__ as atomic_reactor_version
from atomic_reactor.plugin import ExitPlugin
from atomic_reactor.source import GitSource
from atomic_reactor.plugins.post_rpmqa import PostBuildRPMqaPlugin
from atomic_reactor.plugins.pre_check_and_set_rebuild import is_rebuild
from atomic_reactor.constants import PROG
from atomic_reactor.util import get_version_of_tools
from osbs.conf import Configuration
from osbs.api import OSBS

try:
    from atomic_reactor.plugins.post_push_to_pulp import PulpPushPlugin
    PULP_PUSH_KEY = PulpPushPlugin.key
except (ImportError, SyntaxError):
    PULP_PUSH_KEY = None


# An output file and its metadata
Output = namedtuple('output', ['file', 'metadata'])


class KojiPromotePlugin(ExitPlugin):
    """
    Promote this build to Koji

    Submits a successful build to Koji using the Content Generator API,
    https://fedoraproject.org/wiki/Koji/ContentGenerators

    Authentication is with Kerberos unless the koji_ssl_certs
    configuration parameter is given, in which case it should be a
    path at which 'cert', 'ca', and 'serverca' are the certificates
    for SSL authentication.

    Runs as an exit plugin in order to capture logs from all other
    plugins.
    """

    key = "koji_promote"
    is_allowed_to_fail = False

    def __init__(self, tasker, workflow, kojihub, url,
                 verify_ssl=True, use_auth=True,
                 koji_ssl_certs=None, koji_proxy_user=None):
        """
        constructor

        :param tasker: DockerTasker instance
        :param workflow: DockerBuildWorkflow instance
        :param kojihub: string, koji hub (xmlrpc)
        :param url: string, URL for OSv3 instance
        :param verify_ssl: bool, verify OSv3 SSL certificate?
        :param use_auth: bool, initiate authentication with OSv3?
        :param koji_ssl_certs: str, path to 'cert', 'ca', 'serverca'
        :param koji_proxy_user: str, user to log in as (requires hub config)
        """
        super(KojiPromotePlugin, self).__init__(tasker, workflow)

        self.kojihub = kojihub
        self.koji_ssl_certs = koji_ssl_certs
        self.koji_proxy_user = koji_proxy_user

        osbs_conf = Configuration(conf_file=None, openshift_uri=url,
                                  use_auth=use_auth, verify_ssl=verify_ssl)
        self.osbs = OSBS(osbs_conf, osbs_conf)
        self.build_id = None
        self.namespace = None

    @staticmethod
    def parse_rpm_output(output, tags):
        """
        Parse output of the rpm query.

        :param output: str, decoded output from the rpm subprocess
        :param tags: list, str fields used for query output
        :return: list, dicts describing each rpm package
        """

        def field(tag):
            """
            Get a field value by name
            """
            try:
                value = fields[tags.index(tag)]
            except ValueError:
                return None

            if value == '(none)':
                return None

            return value

        components = []
        for rpm in output.split('\n'):
            fields = rpm.split(',')
            if len(fields) < len(tags):
                continue

            component_rpm = {
                'type': 'rpm',
                'name': field('NAME'),
                'version': field('VERSION'),
                'release': field('RELEASE'),
                'arch': field('ARCH'),
                'epoch': field('EPOCH'),
                'sigmd5': field('SIGMD5'),
                'signature': (field('SIGPGP') or
                              field('SIGGPG') or
                              None),
            }

            if component_rpm['name'] != 'gpg-pubkey':
                components.append(component_rpm)

        return components

    def get_rpms(self):
        """
        Build a list of installed RPMs in the format required for the
        metadata.
        """

        tags = [
            'NAME',
            'VERSION',
            'RELEASE',
            'ARCH',
            'EPOCH',
            'SIGMD5',
            'SIGPGP',
            'SIGGPG',
        ]

        fmt = ",".join(["%%{%s}" % tag for tag in tags])
        cmd = "/bin/rpm -qa --qf '{0}\n'".format(fmt)
        try:
            # py3
            (status, output) = subprocess.getstatusoutput(cmd)
        except AttributeError:
            # py2
            with open('/dev/null', 'r+') as devnull:
                p = subprocess.Popen(cmd,
                                     shell=True,
                                     stdin=devnull,
                                     stdout=subprocess.PIPE,
                                     stderr=devnull)

                (stdout, stderr) = p.communicate()
                status = p.wait()
                output = stdout.decode()

        if status != 0:
            self.log.debug("%s: stderr output: %s", cmd, stderr)
            raise RuntimeError("%s: exit code %s" % (cmd, status))

        return self.parse_rpm_output(output, tags)

    @staticmethod
    def get_metadata(path, filename):
        """
        Describe a file by its metadata.
        """

        metadata = {'filename': filename,
                    'filesize': os.path.getsize(path)}
        s = hashlib.sha256()
        blocksize = 65536
        with open(path, mode='rb') as f:
            buf = f.read(blocksize)
            while len(buf) > 0:
                s.update(buf)
                buf = f.read(blocksize)

        metadata.update({'checksum': s.hexdigest(),
                         'checksum_type': 'sha256'})
        return metadata

    def get_builder_image_id(self):
        """
        Find out the docker ID of the buildroot image we are in.
        """

        buildroot_tag = os.environ["OPENSHIFT_CUSTOM_BUILD_BASE_IMAGE"]
        kwargs = {}
        if self.namespace is not None:
            kwargs['namespace'] = self.namespace
        pod = self.osbs.get_pod_for_build(self.build_id, **kwargs)
        all_images = pod.get_container_image_ids()

        try:
            return all_images[buildroot_tag]
        except KeyError:
            self.log.error("Unable to determine buildroot image ID for %s",
                           buildroot_tag)
            return buildroot_tag

    def get_buildroot(self, build_id):
        """
        Build the buildroot entry of the metadata.
        """

        docker_version = self.tasker.get_version()
        docker_info = self.tasker.get_info()
        host_arch = docker_version['Arch']
        if host_arch == 'amd64':
            host_arch = 'x86_64'

        buildroot = {
            'id': 1,
            'host': {
                'os': docker_info['OperatingSystem'],
                'arch': host_arch,
            },
            'content_generator': {
                'name': PROG,
                'version': atomic_reactor_version,
            },
            'container': {
                'type': 'docker',
                'arch': os.uname()[4],
            },
            'tools': get_version_of_tools() + [
                {
                    'name': 'docker',
                    'version': docker_version['Version'],
                },
            ],
            'components': self.get_rpms(),
            'extra': {
                'osbs': {
                    'build_id': build_id,
                    'builder_image_id': self.get_builder_image_id(),
                }
            },
        }

        return buildroot

    def get_logs(self):
        """
        Build the logs entry for the metadata 'output' section
        """

        # Collect logs from server
        kwargs = {}
        if self.namespace is not None:
            kwargs['namespace'] = self.namespace
        logs = self.osbs.get_build_logs(self.build_id, **kwargs)

        # Deleted once closed
        logfile = NamedTemporaryFile(prefix=self.build_id,
                                     suffix=".log",
                                     mode='w')
        logfile.write(logs)
        logfile.flush()

        docker_logs = NamedTemporaryFile(prefix="docker-%s" % self.build_id,
                                         suffix=".log",
                                         mode='w')
        docker_logs.write("\n".join(self.workflow.build_logs))
        docker_logs.flush()

        return [Output(file=docker_logs,
                       metadata=self.get_metadata(docker_logs.name,
                                                  "build.log")),
                Output(file=logfile,
                       metadata=self.get_metadata(logfile.name,
                                                  "openshift-final.log"))]

    def get_image_components(self):
        """
        Re-package the output of the rpmqa plugin into the format required
        for the metadata.
        """

        try:
            output = self.workflow.postbuild_results[PostBuildRPMqaPlugin.key]
        except KeyError:
            self.log.error("%s plugin did not run!",
                           PostBuildRPMqaPlugin.key)
            return []

        return self.parse_rpm_output(output, PostBuildRPMqaPlugin.rpm_tags)

    def get_output(self, buildroot_id):
        """
        Build the 'output' section of the metadata.
        """

        def add_buildroot_id(output):
            logfile, metadata = output
            metadata.update({'buildroot_id': buildroot_id})
            return Output(file=logfile, metadata=metadata)

        def add_log_type(output):
            logfile, metadata = output
            metadata.update({'type': 'log', 'arch': 'noarch'})
            return Output(file=logfile, metadata=metadata)

        output_files = [add_log_type(add_buildroot_id(metadata))
                        for metadata in self.get_logs()]

        image_path = self.workflow.exported_image_sequence[-1].get('path')
        metadata = self.get_metadata(image_path, os.path.basename(image_path))
        image_id = self.workflow.builder.image_id
        # Parent of squashed built image is base image
        parent_id = self.workflow.builder.base_image_inspect['Id']
        pulp_result = None
        if PULP_PUSH_KEY is not None:
            pulp_result = self.workflow.postbuild_results.get(PULP_PUSH_KEY)

        if pulp_result is None:
            # Pulp plugin not installed or not configured
            raise NotImplementedError

        destination_repo = pulp_result[0].to_str()
        tag = self.workflow.tag_conf.unique_images[0].to_str()
        metadata.update({
            'arch': os.uname()[4],
            'type': 'docker-image',
            'components': self.get_image_components(),
            'extra': {
                'docker': {
                    'id': image_id,
                    'parent_id': parent_id,
                    'destination_repo': destination_repo,
                    'tag': tag,
                },
            },
        })
        image = add_buildroot_id(Output(file=None, metadata=metadata))
        output_files.append(image)

        return output_files

    def run(self):
        """
        Run the plugin.
        """

        # Only run if the build was successful
        if self.workflow.build_process_failed:
            self.log.info("Not promoting failed build to koji")
            return

        if not is_rebuild(self.workflow):
            self.log.info("Not promoting to koji: not a rebuild")
            return

        try:
            build_json = json.loads(os.environ["BUILD"])
        except KeyError:
            self.log.error("No $BUILD env variable. Probably not running in build container.")
            raise

        try:
            metadata = build_json["metadata"]
            build_start_time = metadata["creationTimestamp"]
            self.build_id = metadata["name"]
            self.namespace = metadata.get("namespace")
        except KeyError:
            self.log.error("No build metadata")
            raise

        metadata_version = 0

        try:
            # Decode UTC RFC3339 date with no fractional seconds
            # (the format we expect)
            start_time_struct = time.strptime(build_start_time,
                                              '%Y-%m-%dT%H:%M:%SZ')
            start_time = str(int(time.mktime(start_time_struct)))
        except ValueError:
            self.log.error("Invalid time format (%s)", build_start_time)
            raise

        name = None
        version = None
        release = None
        for image_name in self.workflow.tag_conf.primary_images:
            if '-' in image_name.tag:
                name = image_name.repo
                version, release = image_name.tag.split('-', 1)

        if name is None or version is None or release is None:
            raise RuntimeError('Unable to determine name-version-release')

        source = self.workflow.source
        if not isinstance(source, GitSource):
            raise RuntimeError('git source required')

        buildroot = self.get_buildroot(build_id=self.build_id)
        output_files = self.get_output(buildroot['id'])

        koji_metadata = {
            'metadata_version': metadata_version,
            'build': {
                'name': name,
                'version': version,
                'release': release,
                'source': "{0}#{1}".format(source.uri, source.commit_id),
                'start_time': start_time,
                'end_time': str(int(time.time()))
            },
            'buildroots': [buildroot],
            'output': [output.metadata for output in output_files],
        }

        xmlrpc = koji.ClientSession(self.kojihub)
        kwargs = {}
        if self.koji_proxy_user:
            kwargs['proxyuser'] = self.koji_proxy_user

        if self.koji_ssl_certs:
            self.log.info("Using SSL certificates for Koji authentication")
            xmlrpc.ssl_login(os.path.join(self.koji_ssl_certs, 'cert'),
                             os.path.join(self.koji_ssl_certs, 'ca'),
                             os.path.join(self.koji_ssl_certs, 'serverca'),
                             **kwargs)
        else:
            # Assume Kerberos
            self.log.info("Using Kerberos for Koji authentication")
            xmlrpc.krb_login(**kwargs)

        # subject to change
        xmlrpc.importGeneratedContent(koji_metadata)

        self.log.debug("Submitted with metadata: %s",
                       json.dumps(koji_metadata, sort_keys=True, indent=4))
