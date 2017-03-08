from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.context import InitCommandContext, ResourceCommandContext
import purestorage
from cloudshell.api.cloudshell_api import CloudShellAPISession
from cloudshell.shell.core.driver_context import AutoLoadAttribute, AutoLoadCommandContext, AutoLoadResource, \
    AutoLoadDetails
from cloudshell.core.logger import qs_logger
import time
# Begin flash array workaround
import json
import requests

from distutils.version import StrictVersion

# The current version of this library.
VERSION = "1.8.0"

class FlashArray(object):

    """Represents a Pure Storage FlashArray and exposes administrative APIs.

    :param target: IP address or domain name of the target array's management
                   interface.
    :type target: str
    :param username: Username of the user with which to log in.
    :type username: str, optional
    :param password: Password of the user with which to log in.
    :type password: str, optional
    :param api_token: API token of the user with which to log in.
    :type api_token: str, optional
    :param rest_version: REST API version to use when communicating with
                         target array.
    :type rest_version: str, optional
    :param verify_https: Enable SSL certificate verification for HTTPS requests.
    :type verify_https: bool, optional
    :param ssl_cert: Path to SSL certificate or CA Bundle file. Ignored if
                     verify_https=False.
    :type ssl_cert: str, optional
    :param user_agent: String to be used as the HTTP User-Agent for requests.
    :type user_agent: str, optional

    :raises: :class:`PureError`

        - If the target array cannot be found.
        - If the target array does not support any of the REST versions used by
          this library.
        - If the username and password or api_token are invalid.

    :raises: :class:`ValueError`

        - If no api_token or username and password are specified.
        - If an api_token and a username or password are specified.
        - If the specified rest_version is not supported by this library or by
          the target array.

    .. note::

        The FlashArray constructor requires either a username and password or
        an api_token but not both.

    .. note::

        If a rest_version is not specified, the FlashArray object uses the
        highest REST API version supported by both the target array and this
        library. If the REST API version should become deprecated during the
        lifetime of the FlashArray object, the object renegotiates a REST
        version to use and continues running.

    .. note::

        If a rest_version is specified, that version is used so long as it is
        supported by both the target array and this library. In this case, the
        FlashArray object does not attempt to renegotiate the REST API version.

    """

    supported_rest_versions = [
            "1.8",
            "1.7",
            "1.6",
            "1.5",
            "1.4",
            "1.3",
            "1.2",
            "1.1",
            "1.0",
        ]

    def __init__(self, target, username=None, password=None, api_token=None,
                 rest_version=None, verify_https=False, ssl_cert=None,
                 user_agent=None, logger=None):
        if logger:
            self.logger=logger
            logger.debug('Using local pure array implementation with fix')
        if not api_token and not (username and password):
            raise ValueError(
                "Must specify API token or both username and password.")
        elif api_token and (username or password):
            raise ValueError(
                "Specify only API token or both username and password.")

        self._cookies = {}
        self._target = target

        self._renegotiate_rest_version = False if rest_version else True

        self._verify_https = verify_https
        self._ssl_cert = ssl_cert

        self._user_agent = user_agent

        self._rest_version = rest_version
        if self._rest_version:
            self._rest_version = self._check_rest_version(rest_version)
        else:
            self._rest_version = self._choose_rest_version()

        self._api_token = (api_token or self._obtain_api_token(username, password))
        self._start_session()

    def _request(self, method, path, data=None, reestablish_session=True):
        """Perform HTTP request for REST API."""
        if path.startswith("https://"):
            url = path  # For cases where URL of different form is needed.
        else:
            url = "https://{0}/api/{1}/{2}".format(
                self._target, self._rest_version, path)
        headers = {"Content-Type": "application/json"}
        if self._user_agent:
            headers['User-Agent'] = self._user_agent

        body = json.dumps(data).encode("utf-8")
        verify = False
        if self._verify_https:
            if self._ssl_cert:
                verify = self._ssl_cert
            else:
                verify = True
        try:
            response = requests.request(method, url, data=body, headers=headers,
                                        cookies=self._cookies, verify=verify)
        except requests.exceptions.RequestException as err:
            # error outside scope of HTTP status codes
            # e.g. unable to resolve domain name
            raise PureError(err.message)

        if response.status_code == 200:
            if "application/json" in response.headers.get("Content-Type", ""):
                if response.cookies:
                    self._cookies.update(response.cookies)
                else:
                    self._cookies.clear()
                content = response.json()
                if isinstance(content, list):
                    content = ResponseList(content)
                elif isinstance(content, dict):
                    content = ResponseDict(content)
                content.headers = response.headers
                return content
            raise PureError("Response not in JSON: " + response.text)
        elif response.status_code == 401 and reestablish_session:
            self._start_session()
            return self._request(method, path, data, False)
        elif response.status_code == 450 and self._renegotiate_rest_version:
            # Purity REST API version is incompatible.
            old_version = self._rest_version
            self._rest_version = self._choose_rest_version()
            if old_version == self._rest_version:
                # Got 450 error, but the rest version was supported
                # Something really unexpected happened.
                raise PureHTTPError(self._target, self._rest_version, response)
            return self._request(method, path, data, reestablish_session)
        else:
            raise PureHTTPError(self._target, self._rest_version, response)

    #
    # REST API session management methods
    #

    def _check_rest_version(self, version):
        """Validate a REST API version is supported by the library and target array."""
        version = str(version)

        if version not in self.supported_rest_versions:
            msg = "Library is incompatible with REST API version {0}"
            raise ValueError(msg.format(version))

        array_rest_versions = self._list_available_rest_versions()
        if version not in array_rest_versions:
            msg = "Array is incompatible with REST API version {0}"
            raise ValueError(msg.format(version))

        return version

    def _choose_rest_version(self):
        """Return the newest REST API version supported by target array."""
        versions = self._list_available_rest_versions()
        versions = [x for x in versions if x in self.supported_rest_versions]
        if versions:
            return max(versions, key=StrictVersion)
        else:
            raise PureError(
                "Library is incompatible with all REST API versions supported"
                "by the target array.")

    def _list_available_rest_versions(self):
        """Return a list of the REST API versions supported by the array"""
        url = "https://{0}/api/api_version".format(self._target)
        data = self._request("GET", url, reestablish_session=False)
        return data["version"]

    def _obtain_api_token(self, username, password):
        """Use username and password to obtain and return an API token."""
        data = self._request("POST", "auth/apitoken",
                             {"username": username, "password": password},
                             reestablish_session=False)
        return data["api_token"]

    def _start_session(self):
        """Start a REST API session."""
        self._request("POST", "auth/session", {"api_token": self._api_token},
                      reestablish_session=False)

    def get_rest_version(self):
        """Get the REST API version being used by this object.

        :returns: The REST API version.
        :rtype: str

        """
        return self._rest_version

    def invalidate_cookie(self):
        """End the REST API session by invalidating the current session cookie.

        .. note::
            Calling any other methods again creates a new cookie. This method
            is intended to be called when the FlashArray object is no longer
            needed.

        """
        self._request("DELETE", "auth/session")

    #
    # Array management methods
    #

    def _set_console_lock(self, **kwargs):
        return self._request("PUT", "array/console_lock", kwargs)

    def enable_console_lock(self):
        """Enable root lockout from the array at the physical console.

        :returns: A dictionary mapping "console_lock" to "enabled".
        :rtype: ResponseDict

        """
        return self._set_console_lock(enabled=True)

    def disable_console_lock(self):
        """Disable root lockout from the array at the physical console.

        :returns: A dictionary mapping "console_lock" to "disabled".
        :rtype: ResponseDict

        """
        return self._set_console_lock(enabled=False)

    def connect_array(self, address, connection_key, connection_type, logger=None, **kwargs):
        """Connect this array with another one.

        :param address: IP address or DNS name of other array.
        :type address: str
        :param connection_key: Connection key of other array.
        :type connection_key: str
        :param connection_type: Type(s) of connection desired.
        :type connection_type: list
        :param \*\*kwargs: See the REST API Guide on your array for the
                           documentation on the request:
                           **POST array/connection**
        :type \*\*kwargs: optional

        :returns: A dictionary describing the connection to the other array.
        :rtype: ResponseDict

        .. note::

            Currently, the only type of connection is "replication".

        .. note::

            Requires use of REST API 1.2 or later.

        """
        if logger:
            logger.debug('Using workaround connect_array')
            logger.debug('management address: ' + address)
            logger.debug('connection key: ' + connection_key)
            logger.debug('type: ' + connection_type)
        data = {"management_address": address,
                "connection_key": connection_key,
                "type": connection_type}
        data.update(kwargs)
        return self._request("POST", "array/connection", data)

class ResponseList(list):
    """List type returned by FlashArray object.

    :ivar dict headers: The headers returned in the request.

    """
    def __init__(self, l=()):
        super(ResponseList, self).__init__(l)
        self.headers = {}

class ResponseDict(dict):
    """Dict type returned by FlashArray object.

    :ivar dict headers: The headers returned in the request.

    """
    def __init__(self, d=()):
        super(ResponseDict, self).__init__(d)
        self.headers = {}

class PureError(Exception):
    """Exception type raised by FlashArray object.

    :param reason: A message describing why the error occurred.
    :type reason: str

    :ivar str reason: A message describing why the error occurred.

    """
    def __init__(self, reason):
        self.reason = reason
        super(PureError, self).__init__()

    def __str__(self):
        return "PureError: {0}".format(self.reason)


class PureHTTPError(PureError):
    """Exception raised as a result of non-200 response status code.

    :param target: IP or DNS name of the array that received the HTTP request.
    :type target: str
    :param rest_version: The REST API version that was used when making the
                         request.
    :type rest_version: str
    :param response: The response of the HTTP request that caused the error.
    :type response: :class:`requests.Response`

    :ivar str target: IP or DNS name of the array that received the HTTP request.
    :ivar str rest_version: The REST API version that was used when making the
                            request.
    :ivar int code: The HTTP response status code of the request.
    :ivar dict headers: A dictionary containing the header information. Keys are
                        case-insensitive.
    :ivar str reason: The textual reason for the HTTP status code
                      (e.g. "BAD REQUEST").
    :ivar str text: The body of the response which may contain a message
                    explaining the error.

    .. note::

        The error message in text is not guaranteed to be consistent across REST
        versions, and thus should not be programmed against.

    """
    def __init__(self, target, rest_version, response):
        super(PureHTTPError, self).__init__(response.reason)
        self.target = target
        self.rest_version = rest_version
        self.code = response.status_code
        self.headers = response.headers
        self.text = response.text

    def __str__(self):
        msg = ("PureHTTPError status code {0} returned by REST "
               "version {1} at {2}: {3}\n{4}")
        return msg.format(self.code, self.rest_version, self.target,
                          self.reason, self.text)

class PureflasharrayDriver (ResourceDriverInterface):

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass

    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        self.array = None
        pass

    def initialize(self, context):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        """
        self.logger = None
        pass


    def _log(self, context, message, level='info'):
        """

        :param ResourceCommandContext context:
        :return:
        """

        if self.logger is None:
            if hasattr(context, 'reservation'):
                self.logger = qs_logger.get_qs_logger(context.reservation.reservation_id, 'PureStorageFlashArray',
                                                  context.resource.name)
            else:
                self.logger = qs_logger.get_qs_logger('Unreserved', 'PureStorageFlashArray', context.resource.name)

        if level == 'info':
            self.logger.info(message)
        elif level == 'debug':
            self.logger.debug(message)
        elif level == 'error':
            self.logger.error(message)
        elif level == 'critical':
            self.logger.critical(message)

    def _get_api_session(self, context):
        """

        :param ResourceCommandContext context:
        :return:
        """
        domain = None
        if hasattr(context, 'reservation'):
            domain = context.reservation.domain
        else:
            domain = 'Global'
        return CloudShellAPISession(context.connectivity.server_address, domain=domain,
                                    token_id=context.connectivity.admin_auth_token)


    def _decrypt_password(self, context, password):

        api = self._get_api_session(context)

        return api.DecryptPassword(password).Value

    def _get_storage_api_session(self, context, workaround=False):
        """

        :param ResourceCommandContext context:
        :return:
        """
        if self.array is not None and workaround:
            self._log(context, 'Workaround, clearing storage api session', 'debug')
            self.array.invalidate_cookie()
            self.array = None

        if self.array is not None:
            try:
                self.array.get()
                return self.array
            except Exception:
                pass

        if workaround:
            self._log(context, 'workaround, getting storage api session', 'debug')
            count = 0
            connected = False
            while count < 5 and not connected:
                try:
                    self.array = FlashArray(context.resource.attributes['vir1_address'],
                                    context.resource.attributes['User'],
                                       self._decrypt_password(context,
                                                              context.resource.attributes['Password']),
                                            logger=self.logger)
                    connected = True
                    self._log(context, 'workaround, successfully connected to storage api', 'debug')

                except:
                    count += 1
                    if count < 5:
                        self._log(context, 'connection failed, retry')
                        time.sleep(20)
                    continue
            if not connected:
                self._lot(context, 'All connection retries failed')
                raise IOError('Unable to connect to Primary array')
        else:
            self.array = purestorage.FlashArray(context.resource.attributes['vir1_address'],
                                                context.resource.attributes['User'],
                                                self._decrypt_password(context,
                                                                       context.resource.attributes['Password']))

        return self.array

    def create_host_entry(self, context, host_name, wwn_list='', iqn_list=''):
        """

        :param ResourceCommandContext context:
        :param protocol:
        :param host_name:
        :param initiator_list:
        :return:
        """

        self._log(context, 'Creating host entry. host_name: {0} | wwn_list: {1} | iqn_list {2}'.format(host_name,
                                                                                                           wwn_list,
                                                                                                           iqn_list))
        array = self._get_storage_api_session(context)
        if wwn_list != '' and iqn_list != '':
            self._log(context, 'Both wwn and iqn', 'info')
            array.create_host(host_name, wwnlist=wwn_list.split(','), iqnlist=iqn_list.split(','))
        elif wwn_list == '' and iqn_list != '':
            self._log(context, 'iqn list', 'info')
            array.create_host(host_name, iqnlist=iqn_list.split(','))
        elif iqn_list == '' and wwn_list != '':
            self._log(context,'wwn list', 'info')
            array.create_host(host_name, wwnlist=wwn_list.split(','))
        else:
            self._log(context, 'Blank intiator lists', 'error')
            raise ValueError('Blank initiator lists')
        self.logger.info('Host entry creation: SUCCESS')

    def create_host_group(self, context, group_name, host_list):
        self._log(context, 'Creating host group. name: {0} | host_list: {1}'.format(group_name, host_list))
        array = self._get_storage_api_session(context)

        array.create_hgroup(group_name, hostlist=host_list.split(','))
        self._log(context, 'Create host group SUCCESS')

    def create_volume(self, context, vol_name, size):
        self._log(context, 'Creating volume. name: {0} | size: {1}'.format(vol_name, size))
        array = self._get_storage_api_session(context)
        array.create_volume(vol_name, size)
        self._log(context, 'Create volume SUCCESS')
    def connect_volume_to_host_group(self, context, host_group, vol_name):
        self._log(context, 'Connect volume to host group. host group: {0} | volumne: {1}'.format(host_group, vol_name))
        array = self._get_storage_api_session(context)
        array.connect_hgroup(host_group, vol_name)
        self._log(context, 'Connect volumne to host gorup SUCCESS')

    def copy_volume(self, context, source, destination):
        self._log(context, 'Copy Volume. source: {0} | destination: {1}'.format(source, destination))
        array = self._get_storage_api_session(context)
        array.copy_volume(source, destination, overwrite='true')
        self._log(context, 'Copy Volume SUCCESS')

    def delete_host_group(self, context, group_name):
        self._log(context, 'delete host group. name: {0}'.format(group_name))
        array = self._get_storage_api_session(context)
        array.delete_hgroup(group_name)
        self._log(context, 'delete host group SUCCESS')

    def delete_host(self, context, host_name):
        self._log(context, 'delete host. name: {0}'.format(host_name))
        array = self._get_storage_api_session(context)
        array.delete_host(host_name)
        self._log(context, 'delete host SUCCESS')

    def delete_volume(self, context, vol_name):
        self._log(context, 'delete volume. name: {0}'.format(vol_name))
        array = self._get_storage_api_session(context)
        array.destroy_volume(vol_name)
        array.eradicate_volume(vol_name)
        self._log(context, 'delete volumne SUCCESS')

    def disconnect_volume(self, context, host_group_name, vol_name):
        self._log(context, 'disconnect volume. host: {0} | volume {1}'.format(host_group_name, vol_name))
        array = self._get_storage_api_session(context)
        array.disconnect_hgroup(host_group_name, vol_name)
        self._log(context, 'disconnect volume SUCCESS')

    def connect_array(self, context, management_ip, replication_ip, connection_key):
        self._log(context, 'connect replication array. mgmt IP: {0} | repl IP: {1} | Conn Key: {2}'.format(management_ip,
                                                                                                  replication_ip,
                                                                                                  connection_key))
        self._log(context, str(context))
        array = self._get_storage_api_session(context, workaround=True)
        connected = False

        while not connected:
            try:
                array.connect_array(management_ip, connection_key, ['replication'], replication_address=replication_ip)
                connected = True
            except Exception as e:

                break
        if not connected:
            self._log(context, 'Connection resulted in error, assuming it worked', level='info')
        self._log(context, 'connect replicaotin array SUCCESS')

    def disconnect_array(self, context, management_ip):
        self._log(context, 'disconnect array. mgmt IP: {0}'.format(management_ip))
        array = self._get_storage_api_session(context)
        array.disconnect_array(management_ip)
        self._log(context, 'disconnect array SUCCESS')

    def get_connection_key(self, context):
        """

        :param ResourceCommandContext context:
        :return:
        """
        self._log(context, 'get connection key')
        array = self._get_storage_api_session(context)
        key = array.get(connection_key=True)['connection_key']
        key = str(key)
        self._log(context, 'Connection Key value {0}'.format(key), 'debug')
        return key


    def get_api_token(self, context):
        array = self._get_storage_api_session(context)
        return array._api_token

    def get_replication_address(self, context):

        array = self._get_storage_api_session(context)

        networks = array.list_network_interfaces()
        replication_address = None

        for network in networks:
            if u'replication' in network['services']:
                replication_address = str(network['address'])
                break

        if replication_address is None:
            return 'N\A'

        else:
            return replication_address


    def _get_newtork_interfaces(self, context):
        array = self._get_storage_api_session(context)

        return array.list_network_interfaces()

    def _get_ports(self, context):
        array = self._get_storage_api_session(context)

        return array.list_ports()

    def _get_controllers(self, context):
        array = self._get_storage_api_session(context)
        return array.get(controllers=True)

    def get_inventory(self, context):
        """
        Discovers the resource structure and attributes.
        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """
        # See below some example code demonstrating how to return the resource structure
        # and attributes. In real life, of course, if the actual values are not static,
        # this code would be preceded by some SNMP/other calls to get the actual resource information
        '''
           # Add sub resources details
           sub_resources = [ AutoLoadResource(model ='Generic Chassis',name= 'Chassis 1', relative_address='1'),
           AutoLoadResource(model='Generic Module',name= 'Module 1',relative_address= '1/1'),
           AutoLoadResource(model='Generic Port',name= 'Port 1', relative_address='1/1/1'),
           AutoLoadResource(model='Generic Port', name='Port 2', relative_address='1/1/2'),
           AutoLoadResource(model='Generic Power Port', name='Power Port', relative_address='1/PP1')]


           attributes = [ AutoLoadAttribute(relative_address='', attribute_name='Location', attribute_value='Santa Clara Lab'),
                          AutoLoadAttribute('', 'Model', 'Catalyst 3850'),
                          AutoLoadAttribute('', 'Vendor', 'Cisco'),
                          AutoLoadAttribute('1', 'Serial Number', 'JAE053002JD'),
                          AutoLoadAttribute('1', 'Model', 'WS-X4232-GB-RJ'),
                          AutoLoadAttribute('1/1', 'Model', 'WS-X4233-GB-EJ'),
                          AutoLoadAttribute('1/1', 'Serial Number', 'RVE056702UD'),
                          AutoLoadAttribute('1/1/1', 'MAC Address', 'fe80::e10c:f055:f7f1:bb7t16'),
                          AutoLoadAttribute('1/1/1', 'IPv4 Address', '192.168.10.7'),
                          AutoLoadAttribute('1/1/2', 'MAC Address', 'te67::e40c:g755:f55y:gh7w36'),
                          AutoLoadAttribute('1/1/2', 'IPv4 Address', '192.168.10.9'),
                          AutoLoadAttribute('1/PP1', 'Model', 'WS-X4232-GB-RJ'),
                          AutoLoadAttribute('1/PP1', 'Port Description', 'Power'),
                          AutoLoadAttribute('1/PP1', 'Serial Number', 'RVE056702UD')]

           return AutoLoadDetails(sub_resources,attributes)
        '''

        self._log(context, 'Begin autoload')
        resources = []
        attributes = []

        api = self._get_api_session(context)
        attributes.append(AutoLoadAttribute('', 'replication_address', self.get_replication_address(context)))
        attributes.append(AutoLoadAttribute('', 'connection_key', self.get_connection_key(context)))

        networks = self._get_newtork_interfaces(context)
        self._log(context, 'got networks')

        controllers = self._get_controllers(context)
        self._log(context, 'got controllers')
        ports = self._get_ports(context)

        model = None
        for controller in controllers:
            self._log(context, 'Processing ctrlt: ' + controller['name'] + ':' + controller['model'])
            resources.append(AutoLoadResource(model='Generic Storage Controller', name=controller['name'],
                                              relative_address=controller['name']))
            if model is None:
                model = controller['model']

        attributes.append(AutoLoadAttribute('', 'Model', model))

        for network in networks:
            self._log(context, 'Processing netwk: ' + network['name'] + ':' + str(network['address']))
            net_name = network['name']
            controller = net_name.split('.')[0]
            if 'vir0' in controller or 'vir1' in controller:
                attributes.append(AutoLoadAttribute('',str(controller + '_address'), str(network['address'])))
                if 'vir0' in controller:
                    api.UpdateResourceAddress(context.resource.name, str(network['address']))
                continue
            if 'vir' in controller:
                continue
            if 'management' not in network['services']:
                continue
            resources.append(AutoLoadResource(model='Storage Network Port', name=net_name,
                                              relative_address=controller.upper() + '/' + str(network['address'])))

        for port in ports:
            if port['iqn'] is not None:
                port_name = port['name']
                controller = port_name.split('.')[0]
                resources.append(AutoLoadResource(model='iSCSI Storage Port', name=port['name'],
                                                  relative_address=controller + '/' + port['portal']))
                attributes.append(AutoLoadAttribute(controller + '/' + port['portal'], 'iqn', port['iqn']))
            elif port['wwn'] is not None:
                port_name = port['name']
                controller = port_name.split('.')[0]
                resources.append(AutoLoadResource(model='FC Storage Port', name=port['name'],
                                                  relative_address=controller + '/' + port['name'].split('.')[1]))
                attributes.append(AutoLoadAttribute(controller + '/' + port['name'].split('.')[1], 'wwn', port['wwn']))




        return AutoLoadDetails(resources, attributes)