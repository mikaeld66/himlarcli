#!/usr/bin/env python
import time
from himlarcli.keystone import Keystone
from himlarcli.nova import Nova
from himlarcli.parser import Parser
from himlarcli.printer import Printer
from himlarcli.notify import Notify
from himlarcli import utils as himutils

himutils.is_virtual_env()

parser = Parser()
options = parser.parse_args()
printer = Printer(options.format)

ksclient = Keystone(options.config, debug=options.debug)
ksclient.set_dry_run(options.dry_run)
logger = ksclient.get_logger()

if hasattr(options, 'region'):
    regions = ksclient.find_regions(region_name=options.region)
else:
    regions = ksclient.find_regions()

if not regions:
    himutils.sys_error('no valid regions found!')


def action_all():
    pass

def action_instance():
    for region in regions:
        novaclient = Nova(options.config, debug=options.debug, log=logger, region=region)
        instances = novaclient.get_instances()
        mapping = dict(region=region.upper(), project='test')
        body_content = himutils.load_template(inputfile=options.template,
                                              mapping=mapping,
                                              log=logger)
        subject = options.subject
        notify = Notify(options.config, debug=False, log=logger)
        notify.set_keystone_client(ksclient)
        notify.set_dry_run(options.dry_run)
        users = notify.mail_instance_owner(instances=instances,
                                           body=body_content,
                                           subject=subject,
                                           admin=True,
                                           options=['project', 'az'])
        notify.close()
        print users

        #admins = dict()
        #for i in instances:
        #    project = ksclient.get_by_id('project', i.tenant_id)
        #    if not hasattr(project, 'admin'):
        #        himutils.sys_error('ERROR! Project %s missing admin' % project.name, 0)
        #        continue
        #    print i.tenant_id



# Run local function with the same name as the action
action = locals().get('action_' + options.action)
if not action:
    himutils.sys_error("Function action_%s() not implemented" % options.action)
action()
