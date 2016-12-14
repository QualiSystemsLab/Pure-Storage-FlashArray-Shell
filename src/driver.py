from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.context import InitCommandContext, ResourceCommandContext
import purestorage
from cloudshell.api.cloudshell_api import CloudShellAPISession


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
        pass

    def _get_api_session(self, context):
        """

        :param ResourceCommandContext context:
        :return:
        """
        return CloudShellAPISession(context.connectivity.server_address, domain=context.reservation.domain,
                                    token_id=context.connectivity.admin_auth_token)
        CloudShellAPISession.UpdateUsersLimitations()

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

    def create_host_entry(self, context, protocol, host_name, initiator_list):

        array = self._get_storage_api_session(context)
        if protocol.lower() == 'fc':
            array.create_host(host_name, wwnlist=initiator_list.split(','))

        elif protocol.lower() == 'iscsi':
            array.create_host(host_name, iqnlist=initiator_list.split(','))

        else:
            raise ValueError('Invalid protocol name')

    def create_host_group(self, context, group_name, host_list):

        array = self._get_storage_api_session(context)

        array.create_hgroup(group_name, hostlist=host_list.split(','))

    def create_volume(self, context, vol_name, size):

        array = self._get_storage_api_session(context)
        array.create_volume(vol_name, size)

    def connect_volume_to_host_group(self, context, host_group, vol_name):
        array = self._get_storage_api_session(context)
        array.connect_hgroup(host_group, vol_name)

    def copy_volume(self, context, source, destination):
        array = self._get_storage_api_session(context)
        array.copy_volume(source, destination)

    def delete_host_group(self, context, group_name):
        array = self._get_storage_api_session(context)
        array.delete_hgroup(group_name)

    def delete_host(self, context, host_name):
        array = self._get_storage_api_session(context)
        array.delete_host(host_name)

    def delete_volume(self, context, vol_name):
        array = self._get_storage_api_session(context)
        array.destroy_volume(vol_name)

    def connect_array(self, context, management_ip, replication_ip, connection_key):
        array = self._get_storage_api_session(context)
        array.connect_array(management_ip, connection_key, 'replication', replication_address=replication_ip)

    def disconnect_array(self, context, management_ip):
        array = self._get_storage_api_session(context)
        array.disconnect_array(management_ip)

    def get_connection_key(self, context):
        """

        :param ResourceCommandContext context:
        :return:
        """
        return context.resource.attributes['connection_key']

    def get_replication_address(self, context):

        return context.resource.attributes['replication_address']

    def get_inventory(self, context):
        pass