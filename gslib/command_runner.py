# -*- coding: utf-8 -*-
# Copyright 2011 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Class that runs a named gsutil command."""

from __future__ import absolute_import

import difflib
import logging
import os
import pkgutil
import sys
import textwrap
import time

import boto
from boto.storage_uri import BucketStorageUri
import gslib
from gslib.cloud_api_delegator import CloudApiDelegator
from gslib.command import Command
from gslib.command import CreateGsutilLogger
from gslib.command import GetFailureCount
from gslib.command import OLD_ALIAS_MAP
from gslib.command import ShutDownGsutil
import gslib.commands
from gslib.cs_api_map import ApiSelector
from gslib.cs_api_map import GsutilApiClassMapFactory
from gslib.cs_api_map import GsutilApiMapFactory
from gslib.exception import CommandException
from gslib.gcs_json_api import GcsJsonApi
from gslib.no_op_credentials import NoOpCredentials
from gslib.tab_complete import MakeCompleter
from gslib.util import CheckMultiprocessingAvailableAndInit
from gslib.util import CompareVersions
from gslib.util import GetGsutilVersionModifiedTime
from gslib.util import GSUTIL_PUB_TARBALL
from gslib.util import IsRunningInteractively
from gslib.util import LAST_CHECKED_FOR_GSUTIL_UPDATE_TIMESTAMP_FILE
from gslib.util import LookUpGsutilVersion
from gslib.util import RELEASE_NOTES_URL
from gslib.util import SECONDS_PER_DAY
from gslib.util import UTF8


def HandleArgCoding(args):
  """Handles coding of command-line args.

  Args:
    args: array of command-line args.

  Returns:
    array of command-line args.

  Raises:
    CommandException: if errors encountered.
  """
  # Python passes arguments from the command line as byte strings. To
  # correctly interpret them, we decode ones other than -h and -p args (which
  # will be passed as headers, and thus per HTTP spec should not be encoded) as
  # utf-8. The exception is x-goog-meta-* headers, which are allowed to contain
  # non-ASCII content (and hence, should be decoded), per
  # https://cloud.google.com/storage/docs/gsutil/addlhelp/WorkingWithObjectMetadata
  processing_header = False
  for i in range(len(args)):
    arg = args[i]
    # Commands like mv can run this function twice; don't decode twice.
    try:
      decoded = arg if isinstance(arg, unicode) else arg.decode(UTF8)
    except UnicodeDecodeError:
      raise CommandException('\n'.join(textwrap.wrap(
          'Invalid encoding for argument (%s). Arguments must be decodable as '
          'Unicode. NOTE: the argument printed above replaces the problematic '
          'characters with a hex-encoded printable representation. For more '
          'details (including how to convert to a gsutil-compatible encoding) '
          'see `gsutil help encoding`.' % repr(arg))))
    if processing_header:
      if arg.lower().startswith('x-goog-meta'):
        args[i] = decoded
      else:
        try:
          # Try to encode as ASCII to check for invalid header values (which
          # can't be sent over HTTP).
          decoded.encode('ascii')
        except UnicodeEncodeError:
          # Raise the CommandException using the decoded value because
          # _OutputAndExit function re-encodes at the end.
          raise CommandException(
              'Invalid non-ASCII header value (%s).\nOnly ASCII characters are '
              'allowed in headers other than x-goog-meta- headers' % decoded)
    else:
      args[i] = decoded
    processing_header = (arg in ('-h', '-p'))
  return args


class CommandRunner(object):
  """Runs gsutil commands and does some top-level argument handling."""

  def __init__(self, bucket_storage_uri_class=BucketStorageUri,
               gsutil_api_class_map_factory=GsutilApiClassMapFactory,
               command_map=None):
    """Instantiates a CommandRunner.

    Args:
      bucket_storage_uri_class: Class to instantiate for cloud StorageUris.
                                Settable for testing/mocking.
      gsutil_api_class_map_factory: Creates map of cloud storage interfaces.
                                    Settable for testing/mocking.
      command_map: Map of command names to their implementations for
                   testing/mocking. If not set, the map is built dynamically.
    """
    self.bucket_storage_uri_class = bucket_storage_uri_class
    self.gsutil_api_class_map_factory = gsutil_api_class_map_factory
    if command_map:
      self.command_map = command_map
    else:
      self.command_map = self._LoadCommandMap()

  def _LoadCommandMap(self):
    """Returns dict mapping each command_name to implementing class."""
    # Import all gslib.commands submodules.
    for _, module_name, _ in pkgutil.iter_modules(gslib.commands.__path__):
      __import__('gslib.commands.%s' % module_name)

    command_map = {}
    # Only include Command subclasses in the dict.
    for command in Command.__subclasses__():
      command_map[command.command_spec.command_name] = command
      for command_name_aliases in command.command_spec.command_name_aliases:
        command_map[command_name_aliases] = command
    return command_map

  def _ConfigureCommandArgumentParserArguments(
      self, parser, arguments, gsutil_api):
    """Configures an argument parser with the given arguments.

    Args:
      parser: argparse parser object.
      arguments: array of CommandArgument objects.
      gsutil_api: gsutil Cloud API instance to use.
    Raises:
      RuntimeError: if argument is configured with unsupported completer
    """
    for command_argument in arguments:
      action = parser.add_argument(
          *command_argument.args, **command_argument.kwargs)
      if command_argument.completer:
        action.completer = MakeCompleter(command_argument.completer, gsutil_api)

  def ConfigureCommandArgumentParsers(self, subparsers):
    """Configures argparse arguments and argcomplete completers for commands.

    Args:
      subparsers: argparse object that can be used to add parsers for
                  subcommands (called just 'commands' in gsutil)
    """

    # This should match the support map for the "ls" command.
    support_map = {
        'gs': [ApiSelector.XML, ApiSelector.JSON],
        's3': [ApiSelector.XML]
    }
    default_map = {
        'gs': ApiSelector.JSON,
        's3': ApiSelector.XML
    }
    gsutil_api_map = GsutilApiMapFactory.GetApiMap(
        self.gsutil_api_class_map_factory, support_map, default_map)

    logger = CreateGsutilLogger('tab_complete')
    gsutil_api = CloudApiDelegator(
        self.bucket_storage_uri_class, gsutil_api_map,
        logger, debug=0)

    for command in set(self.command_map.values()):
      command_parser = subparsers.add_parser(
          command.command_spec.command_name, add_help=False)
      if isinstance(command.command_spec.argparse_arguments, dict):
        subcommand_parsers = command_parser.add_subparsers()
        subcommand_argument_dict = command.command_spec.argparse_arguments
        for subcommand, arguments in subcommand_argument_dict.iteritems():
          subcommand_parser = subcommand_parsers.add_parser(
              subcommand, add_help=False)
          self._ConfigureCommandArgumentParserArguments(
              subcommand_parser, arguments, gsutil_api)
      else:
        self._ConfigureCommandArgumentParserArguments(
            command_parser, command.command_spec.argparse_arguments, gsutil_api)

  def RunNamedCommand(self, command_name, args=None, headers=None, debug=0,
                      trace_token=None, parallel_operations=False,
                      skip_update_check=False, logging_filters=None,
                      do_shutdown=True, perf_trace_token=None):
    """Runs the named command.

    Used by gsutil main, commands built atop other commands, and tests.

    Args:
      command_name: The name of the command being run.
      args: Command-line args (arg0 = actual arg, not command name ala bash).
      headers: Dictionary containing optional HTTP headers to pass to boto.
      debug: Debug level to pass in to boto connection (range 0..3).
      trace_token: Trace token to pass to the underlying API.
      parallel_operations: Should command operations be executed in parallel?
      skip_update_check: Set to True to disable checking for gsutil updates.
      logging_filters: Optional list of logging.Filters to apply to this
          command's logger.
      do_shutdown: Stop all parallelism framework workers iff this is True.
      perf_trace_token: Performance measurement trace token to pass to the
          underlying API.

    Raises:
      CommandException: if errors encountered.

    Returns:
      Return value(s) from Command that was run.
    """
    command_changed_to_update = False
    if (not skip_update_check and
        self.MaybeCheckForAndOfferSoftwareUpdate(command_name, debug)):
      command_name = 'update'
      command_changed_to_update = True
      args = ['-n']

    if not args:
      args = []

    # Include api_version header in all commands.
    api_version = boto.config.get_value('GSUtil', 'default_api_version', '1')
    if not headers:
      headers = {}
    headers['x-goog-api-version'] = api_version

    if command_name not in self.command_map:
      close_matches = difflib.get_close_matches(
          command_name, self.command_map.keys(), n=1)
      if close_matches:
        # Instead of suggesting a deprecated command alias, suggest the new
        # name for that command.
        translated_command_name = (
            OLD_ALIAS_MAP.get(close_matches[0], close_matches)[0])
        print >> sys.stderr, 'Did you mean this?'
        print >> sys.stderr, '\t%s' % translated_command_name
      elif command_name == 'update' and gslib.IS_PACKAGE_INSTALL:
        sys.stderr.write(
            'Update command is not supported for package installs; '
            'please instead update using your package manager.')

      raise CommandException('Invalid command "%s".' % command_name)
    if '--help' in args:
      new_args = [command_name]
      original_command_class = self.command_map[command_name]
      subcommands = original_command_class.help_spec.subcommand_help_text.keys()
      for arg in args:
        if arg in subcommands:
          new_args.append(arg)
          break  # Take the first match and throw away the rest.
      args = new_args
      command_name = 'help'

    args = HandleArgCoding(args)

    command_class = self.command_map[command_name]
    command_inst = command_class(
        self, args, headers, debug, trace_token, parallel_operations,
        self.bucket_storage_uri_class, self.gsutil_api_class_map_factory,
        logging_filters, command_alias_used=command_name,
        perf_trace_token=perf_trace_token)
    return_code = command_inst.RunCommand()

    if CheckMultiprocessingAvailableAndInit().is_available and do_shutdown:
      ShutDownGsutil()
    if GetFailureCount() > 0:
      return_code = 1
    if command_changed_to_update:
      # If the command changed to update, the user's original command was
      # not executed.
      return_code = 1
      print '\n'.join(textwrap.wrap(
          'Update was successful. Exiting with code 1 as the original command '
          'issued prior to the update was not executed and should be re-run.'))
    return return_code

  def MaybeCheckForAndOfferSoftwareUpdate(self, command_name, debug):
    """Checks the last time we checked for an update and offers one if needed.

    Offer is made if the time since the last update check is longer
    than the configured threshold offers the user to update gsutil.

    Args:
      command_name: The name of the command being run.
      debug: Debug level to pass in to boto connection (range 0..3).

    Returns:
      True if the user decides to update.
    """
    return False
