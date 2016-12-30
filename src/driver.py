from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.context import InitCommandContext, ResourceCommandContext
import purestorage
from cloudshell.api.cloudshell_api import CloudShellAPISession
from cloudshell.shell.core.driver_context import AutoLoadAttribute, AutoLoadCommandContext, AutoLoadResource, \
    AutoLoadDetails
from cloudshell.core.logger import qs_logger


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

    def _get_storage_api_session(self, context):
        """

        :param ResourceCommandContext context:
        :return:
        """
        if self.array is not None:
            try:
                self.array.get()
                return self.array
            except Exception:
                pass

        self.array = purestorage.FlashArray(context.resource.address, context.resource.attributes['User'],
                                       self._decrypt_password(context, context.resource.attributes['Password']))

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
            array.create_host(host_name, wwnlist=wwn_list.split(','), iqnlist=iqn_list.split(','))
        elif wwn_list == '' and iqn_list != '':
            array.create_host(host_name, iqnlist=iqn_list.split(','))
        elif iqn_list == '' and wwn_list != '':
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
        array.copy_volume(source, destination)
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
        self._log(context, 'delete volumne SUCCESS')

    def connect_array(self, context, management_ip, replication_ip, connection_key):
        self._log(context, 'connect replication array. mgmt IP: {0} | repl IP: {1} | Conn Key: {2}'.format(management_ip,
                                                                                                  replication_ip,
                                                                                                  connection_key))
        array = self._get_storage_api_session(context)
        array.connect_array(management_ip, connection_key, 'replication', replication_address=replication_ip)
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
        return key
        self._log(context, 'Connection Key value {0}'.format(key),'debug')

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