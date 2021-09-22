#!/usr/bin/env python
import sys
import platform
import re
import utils
import pprint
import yaml

from himlarcli.keystone import Keystone
from himlarcli.foremanclient import ForemanClient
from himlarcli import utils as himutils

# Fix foreman functions and logger not-callable
# pylint: disable=E1101,E1102,W0702

desc = 'Setup Foreman for himlar'
options = utils.get_options(desc, hosts=False)
keystone = Keystone(options.config, debug=options.debug)
logger = keystone.get_logger()
domain = keystone.get_config('openstack', 'domain')

foreman = ForemanClient(options.config, options.debug, log=logger)
client = foreman.get_client()

configfile = 'config/foreman/default.yaml'
host_domain = platform.node().split('.', 1)[1]
if "prod" in host_domain:
    env = 'prod'
else:
    env = 'test'

#
# Set some static defaults
# May be overridden in configuration files ('config/foreman/defaults.yaml')
#
# To raykrist: Denne (config) er her mest av nostalgiske grunner ... :-)

config = {
    'global_params': [
        {'name': 'enable-epel', 'value': 'false', 'id': ''},
        {'name': 'enable-norcams-epel', 'value': 'true', 'id': ''},
        {'name': 'enable-norcams-repo', 'value': 'true', 'id': ''},
        {'name': 'enable-puppetlabs-repo', 'value': 'false', 'id': ''},
        {'name': 'enable-puppetlabs-pc1-repo', 'value': 'false', 'id': ''},
        {'name': 'enable-puppet5', 'value': 'true', 'id': ''},
        {'name': 'run-puppet-in-installer', 'value': 'true', 'id': ''},
        {'name': 'puppet_systemd_firstboot', 'value': 'true', 'id': ''},
        {'name': 'time-zone', 'value': 'Europe/Oslo', 'id': ''},
        {'name': 'ntp-server', 'value': 'no.pool.ntp.org', 'id': ''},
    ],

    'media': {
        'name': 'CentOS download.iaas.uio.no',
        'path': '',					# will be URL of main repository
        'os_family': 'Redhat',
        'id': '',
    },

    'subnets': {
        'name': 'mgmt',
        'mask': '',
        'domain_ids': '',				# will be foreman_domain_id,
        'tftp_id': '',                                  # will be foreman_proxy_id
    },

    # main operating system
    'operatingsystems': {
        'name': 'CentOS',
        'major': '7',
        'minor': '9.2009',
        'password_hash': 'SHA256',
        'architecture_ids': [],				# will be ID of architecure ('x86_64')
        'provisioning_template_ids': [],			# will be IDs of provisioning templates
        'ptable_ids': [],					# will be IDs of partition templates
        'medium_ids': [],					# will be ID of main medium
        'os_ids': [],					# will be ID of main operating systems
    },

    # host groups
    # Rules:
    #     - parents must be defined above children!
    #     - only one group may have a specific name (even with another parent)!
    'hostgroups': [
        {
            'name': 'base',
            'id': '',
            'parent_name': None,
            'environment_id': '',
            'operatingsystem_id': '',
            'architecture_id': '',
            'pxe_loader': 'PXELinux BIOS',
            'medium_id': '',
            'ptable_id': '',
            'subnet_id': '',
            'domain_id': '',
            'puppet_proxy_id': '',
            'puppet_ca_proxy_id': '',
            'group_parameters_attributes': [{'name': 'environment', 'value': env}]
        },
        {
            'name': 'storage',
            'parent_name': 'base',
            'group_parameters_attributes': [{'name': 'installdevice', 'value': 'sdh'}]
        },
        {
            'name': 'compute',
            'parent_name': 'base',
            'group_parameters_attributes': [{'name': 'installdevice', 'value': 'sda'}]
        },
    ],

    # name of our partition and provisioning templates
    'provisioning_templates': [
        'norcams-Kickstart default',
        'norcams-Kickstart default PXELinux',
        'norcams-Kickstart default PXEGrub2'
    ],

    'ptable_templates': [
        'norcams-Kickstart default',
        'norcams-Kickstart default uefi'
    ],

    # misc parameters
    'architectures': [{'name': 'x86_64', 'id': ''}],	# first architecture is the primary
    'environments': [{'name': 'production', 'id': ''}],	# first environment is the primary
    'repofile': '/etc/yum.repos.d/CentOS-Base.repo',
}

# existing data
existing = {
    'provisioning_templates': [],
    'ptables': [],
    'architectures': [],
    'environment': [],
    'hostgroups': [],
    'os': [],
    'subnets': [],
}


########################################################
#
# sub routines
#

bcolors = {
    'HEADER': '\033[95m',
    'OKBLUE': '\033[94m',
    'OKCYAN': '\033[96m',
    'OKGREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
}

# TODO
#     add log file logging here ? or does it already exist inside some library ?

#
# sub routine for printing nice information messages
#
def info(infomsg):
    print
    print bcolors['OKGREEN'],
    print "INFO :",
    print bcolors['ENDC'],
    print infomsg


#
# sub routine to exit with an error message
#
def bail(errormsg):
    print
    print bcolors['FAIL'],
    print "ERROR :",
    print bcolors['ENDC'],
    print errormsg
    print
    print bcolors['BOLD'], "Exiting!", bcolors['ENDC']
    sys.exit(1)


#
# sub routine to extract message from API return message
#
def extract_msg(errormsg, usertxt='', unknown=''):
    pattern = r'.*full_messages\":\[\"([^"]*).*'
    found_msg = re.search(pattern, str(errormsg))
    if found_msg:
        usertxt += found_msg.group(1)
    else:
        usertxt += unknown

    return usertxt


########################################################
#
# Read configuration from file(s) if exists
# If so they override (merge)
#


with open(configfile, 'r') as config_file:
    try:
        config_file_data = yaml.safe_load(config_file)
    except yaml.YAMLError as exc:
        print exc
        bail("Could not find default configuration file (\'config/foreman/default.yaml\')")

if config_file_data:
    config.update(config_file_data)


########################################################
#
# Start of main routine
#


# -------------------------------------------
#
# lookup organization and location ids

info("Looking up ids for default organization and location ...")
try:
    location_id = client.locations.index(search="Default Location")['results'][0]['id']
except:
    bail("No Default Location found")

try:
    organization_id = client.organizations.index(search="Default Organization")['results'][0]['id']
except:
    bail("No Default Organization found")

info("... found Location ID: " + str(location_id) + \
     " and Organizational ID: " + str(organization_id))


# -------------------------------------------
#
# create environments

info("Creating environments ...")

for e in config['environments']:
    # data list for the environment
    environment_data = {
        'name': e['name'],
        'location_ids': [location_id],
        'organization_ids': [organization_id],
    }

    result = client.environments.index(search=e['name'])['results']

    # if environment does not exist, create it
    if not result:
        info("... creating \'" + e['name'] + "\'")
        try:
            existing['environment'].append(client.environments.create(environment=environment_data))
        except:
            error = extract_msg(sys.exc_info()[1], \
                               "Foreman did not accept our updating parameters: ", \
                               "Unknown error")
            bail(error)

    # else update already existing environment
    else:
        info("... \'" + e['name'] + "\' already existing, updating instead ...")
        existing['environment'].append(result[0])
        try:
            client.environments.update(id=result[0]['id'], environment=environment_data)
        except:
            error = extract_msg(sys.exc_info()[1], \
                               "Foreman did not accept our updating parameters: ", \
                               "Unknown error")
            bail(error)


# -------------------------------------------
#
# create foreman domain based on config

info("Looking up domain, create if not existing ...")

# get domain id
# if not in default configuration look for it in himlarcli config
if not config['subnets']['name']:
    try:
        config['subnets']['name'] = foreman.get_config('foreman', 'domain')
    except:
        bail("Domain was not found neither in himlarcli config nor in foreman configuration")

# search for an already existing domain with this name in Foreman
domains_found = client.domains.index(search=config['subnets']['name'])['results']

if not domains_found:
    # domain not found; create it
    info("... domain does not exist, create it")
    try:
        domain_id = client.create_domains({'name': config['subnets']['name']})['id']
    except:
        error = extract_msg(sys.exc_info()[1], "Foreman would not create domain: ", "Unknown error")
        bail(error)
else:
    domain_id = domains_found[0]['id']

info("... found domain id: " + str(domain_id))


# -------------------------------------------
#
# get smart proxy id

# we do this by iterating through the list of smart proxies and select the first
# which offers the TFTP capability

info("Searching for smart proxy supporting TFTP ...")
smart_proxies_found = client.smart_proxies.index()['results']

if smart_proxies_found:
    for s in smart_proxies_found:
        for f in s['features']:
            if 'TFTP' in f['name']:
                foreman_proxy_id = s['id']

try:
    foreman_proxy_id
except:
    bail("Did not find any smart proxy with TFTP capability!")

info("... found smart proxy id: " + str(foreman_proxy_id))


# -------------------------------------------
#
# search for the repository URL (main media path)

info("Extracting the media path from the repository definition (file: " + config['repofile'] + ") ...")

with open(config['repofile']) as rf:
    try:
        media_url = re.search(r'^baseurl=\s*([^\n]+)', rf.read(), re.MULTILINE).group(1)
    except:
        msg = 'Did not find a valid repo url (\"baseurl\") in \'' + config['repofile'] + '\', cannot continue'
        bail(msg)

config['media']['path'] = media_url
info("... found media url: " + media_url)


# -------------------------------------------
#
# Set global parameters

info("Setting global parameters ...")

# Get a list of all current global values (and their corresponding 'id')
common_params = client.common_parameters.index()['results']

# search for the parameter id if it exists
for g_p in config['global_params']:
    global_param = {
        'name': '',
        'value': '',
        'id': [],
    }

    global_param = {'name': g_p['name'], 'value': g_p['value']}
    try:
        g_p['id'] = next((sub for sub in common_params if sub['name'] == g_p['name']), None)['id']
        try:
            client.common_parameters.update(id=g_p['id'], common_parameter=global_param)
        except:
            bail("Could not update the global parameter '" + g_p['name'] + "'")
    except:
        try:
            client.common_parameters.create(common_parameter=global_param)
        except:
            error = extract_msg(sys.exc_info()[1], \
                                "Foreman did not accept our parameters when updating: ", \
                                "Unknown error")
            bail(error)


# TODO - which bug ????????????????????????????????
# -------------------------------------------
#
# check if we can avoid safemode_render bug, and if so
# safemode-render true


# -------------------------------------------
#
# Create medium based on local repository

info("Creating (or updating) local media ...")
existing['media'] = client.media.index(search=config['media']['name'])['results']

if existing['media']:
    info("... updating existing")
    client.media.update(existing['media'][0]['id'], config['media'])
else:
    try:
        info("... creating new media")
        existing['media'].append(client.media.create(medium=config['media']))
    except:
        error = extract_msg(sys.exc_info()[1], \
                            "Foreman did not accept our parameters: ", \
                            "Unknown error")
        bail(error)


# -------------------------------------------
#
# sync templates from external git repository

info("Syncing templates from external repository ...")
result = client.templates.import_(location_id=location_id, organization_id=organization_id)


# -------------------------------------------
#
# find misc. existing data (for use further down)

info("Looking up misc. information (like templates, partition tables and architectures available) ...")

# find provisioning templates - these should exists after previous step
try:
    existing['provisioning_templates'] = client.provisioning_templates.index()['results']
except:
    bail("Did not find any provisioning templates available")


# find partition tables - ditto
try:
    existing['ptables'] = client.ptables.index()['results']
except:
    bail("Did not find any partition table templates, even after sync (" + \
          str(config['ptable_templates']) + \
         ")")


# find architectures
try:
    existing['architectures'] = client.architectures.index()['results']
except:
    bail("Did not find any architectures available")


# find hostgroups
existing['hostgroups'] = client.hostgroups.index()['results']


# find operating systems
existing['os'] = client.operatingsystems.index()['results']


# find subnets
existing['subnets'] = client.subnets.index()['results']


# -------------------------------------------
#
# Create subnet

# For now only support _one_ subnet from configuration

# mgmt network + netmask from config
# dns-primary, dns-secondary, gateway are all blank

info("Creating subnet ...")

# initial preparation for support of more than one subnet in configuration
s = config['subnets']

subnet = {
    'name': s['name'],
    'network': s['network'],
    'cidr': s['cidr'],
    'domain_ids': [domain_id],
    'tftp_id': foreman_proxy_id,
}

subnet_found = next((sub for sub in existing['subnets'] if sub['name'] == s['name']), None)
if not subnet_found:
    info("... did not find subnet '" + s['name'] + "', creating it")
    existing['subnets'].append(client.subnets.create(subnet=subnet))
else:
    info("... subnet '" + s['name'] + "' does already exist, updating it")
    try:
        client.subnets.update(id=subnet_found['id'], subnet=subnet)
    except:
        error = extract_msg(sys.exc_info()[1], \
                            "Foreman did not accept our parameters: ", \
                            "Unknown error")
        bail(error)

# historical use furter down (maybe get rid of this)
subnet_id = existing['subnets'][0]['id']


# -------------------------------------------
#
# create architectures

info("Creating missing architectures (if any) ...")

# for each configured architecture look up existing data and create if not existing
# architectures does not (at this time) contain more than names besides their id, so
# no point updating anything that already exists with the same name

for a in config['architectures']:
    architectures = {
        'name': a['name'],
        'operatingsystem_ids': [],
    }

    arch = next((sub for sub in existing['architectures'] if sub['name'] == a['name']), None)
    if not arch:
        info("... did not find architecture '" + a['name'] + "', creating it")
        existing['architectures'].append(client.architectures.create(architecture=architectures))
    else:
        info("... architecture '" + a['name'] + "' does already exist. Skipping it")


# -------------------------------------------
#
# create and update operating system

info("Creating or updating operating system ...")
info("... have the following expected os data:\n")
pprint.pprint(config['operatingsystems'])

# for each configured os look up data and create or update Foreman accordingly
for os in config['operatingsystems']:

    operatingsystem = {
        'name': config['operatingsystems'][os]['name'],
        'major': config['operatingsystems'][os]['major'],
        'minor': config['operatingsystems'][os]['minor'],
        'password_hash': 'SHA256',
        'architecture_ids': [],
        'provisioning_template_ids': [],
        'ptable_ids': [],
        'medium_ids': [],
        'os_ids': [],
    }


    # fill in missing data

    # find relevant provisioning template id's
    # /api/*/index seems to have a bug handling search criteria containing spaces,
    # especially strings containing more than one space
    # thus use our 'existing' tables in place of api searching
    for pt in config['operatingsystems'][os]['provisioningtemplates']:
        try:
            operatingsystem['provisioning_template_ids'].append((next(sub for sub in existing['provisioning_templates'] if sub['name'] == pt), None)[0]['id'])
        except:
            info("Did not find provisioning template '" + pt + "', which is configured for " + os + "!")

    # find relevant partition table id's
    for pt in config['operatingsystems'][os]['ptables']:
        try:
            operatingsystem['ptable_ids'].append((next(sub for sub in existing['ptables'] if sub['name'] == pt), None)[0]['id'])
        except:
            info("Did not find partition table '" + pt + "', which is configured for " + os + "!")

    # find relevant architecture id's
    for a in config['operatingsystems'][os]['architectures']:
        try:
            operatingsystem['architecture_ids'].append((next(sub for sub in existing['architectures'] if sub['name'] == a), None)[0]['id'])
        except:
            info("Did not find architecture '" + a + "', which is configured for " + os + "!")

    # we simplify this because we know" it is just one medium
    operatingsystem['medium_ids'].append(existing['media'][0]['id'])

    # look for any already existing operating system with this name and version
    search = operatingsystem['name'] +" " + operatingsystem['major'] + "." + operatingsystem['minor']

    # create if not existing ...
    os_found = next((o for o in existing['os'] if o['title'] == search), None)
    if not os_found:
        info(search + " not found - creating ...")
        try:
            os_found = client.operatingsystems.create(operatingsystem=operatingsystem)
        except:
            error = extract_msg(sys.exc_info()[1], \
                               "Foreman did not accept our creation parameters: ", \
                               "Unknown error")
            bail(error)
    # ... otherwise update it with configured parameters
    else:
        info("Updating os parameters for " + search + " ...")
        try:
            client.operatingsystems.update(id=os_found['id'], operatingsystem=operatingsystem)
        except:
            error = extract_msg(sys.exc_info()[1], \
                               "Foreman did not accept our updating parameters: ", \
                               "Unknown error")
            bail(error)

    # find any existing os template combinations for this operating system (if any)
    odt = client.operatingsystems.os_default_templates_index(operatingsystem_id=os_found['id'], provisioning_template_id=pt)['results']

    info("... making our templates default (first of each kind is selected) ...")
    for pt in operatingsystem['provisioning_template_ids']:
        os_default_template = {
            'provisioning_template_id': None,
            'template_kind_id': None,
        }

        tk_id = next((sub for sub in existing['provisioning_templates'] if sub['id'] == pt), None)['template_kind_id']
        os_default_template['provisioning_template_id'] = pt
        os_default_template['template_kind_id'] = tk_id

        # if this kind of provisioning template is not already defined for this operating system, then configure it
        if not next((sub for sub in odt if sub['template_kind_id'] == tk_id), None):
            try:
                client.operatingsystems.os_default_templates_create(operatingsystem_id=os_found['id'], os_default_template=os_default_template)
            except:
                print sys.exc_info()[1]
                error = extract_msg(sys.exc_info()[1], \
                                   "Foreman did not accept our updating parameters: ", \
                                   "Unknown error")
                bail(error)


# -------------------------------------------
#
# create hostgroups
#

info("Creating or updating host groups ...")
info("... have the following expected host group data:\n")
pprint.pprint(config['hostgroups'])
print

# This is a really dumb solution, but since the order of a dict (in the for loop context)
# is arbitrary, and we must handle the base groups first, we loop through the list twice

# child group run or not
child_run = 0

while child_run < 2:
    for hg in config['hostgroups']:

        hg_params = {
            'name': "",
            'medium_id': existing['media'][0]['id'],
            'domain_id': domain_id,
            'subnet_id': subnet_id,
            'parent_id': [],
            'puppet_proxy_id': foreman_proxy_id,
            'puppet_ca_proxy_id': foreman_proxy_id,
            'environment_id': [],
            'ptable_id': [],
            'architecture_id': [],
            'operatingsystem_id': [],
            'pxe_loader': '',
            'group_parameters_attributes': [],
        }

        # check whether we deal with a child or a parent and if this is the appropriate round
        if 'parent' in config['hostgroups'][hg]:
            if child_run == 0:
                continue
            # if this is a child we must find parent id
            # expect parent to exist
            hg_params['parent_id'] = client.hostgroups.index(search=config['hostgroups'][hg]['parent'])['results'][0]['id']
        else:
            if child_run == 1:
                continue
            # every base hostgroup must have a parameter named 'environment' set to "test" or "prod"
            hg_params['group_parameters_attributes'].append({'name': 'environment', 'value': env, 'parameter_type': 'string'})

        # name should always be present
        try:
            hg_params['name'] = config['hostgroups'][hg]['name']
        except:
            bail("Can not find required parameter 'name' in hostgroup definition '" + hg + "'")


        # look up misc. id's
        # these might not all be defined in configuration as they may be optionals

        # find relevant environment id
        if 'environment' in config['hostgroups'][hg]:
            try:
                hg_params['environment_id'] = next((sub for sub in existing['environment'] if sub['name'] == config['hostgroups'][hg]['environment']), None)['id']
            except:
                bail("Did not find environment '" + config['hostgroups'][hg]['environment'] + "', which is configured for " + hg + "!")

        # find relevant partition table id's
        if 'ptable' in config['hostgroups'][hg]:
            try:
                hg_params['ptable_id'] = next((sub for sub in existing['ptables'] if sub['name'] == config['hostgroups'][hg]['ptable']), None)['id']
            except:
                bail("Did not find partition table '" + config['hostgroups'][hg]['ptable'] + "', which is configured for " + hg + "!")

        # find relevant architecture id
        if 'architecture' in config['hostgroups'][hg]:
            try:
                hg_params['architecture_id'] = next((sub for sub in existing['architectures'] if sub['name'] == config['hostgroups'][hg]['architecture']), None)['id']
            except:
                bail("Did not find architecture '" + config['hostgroups'][hg]['architecture'] + "', which is configured for " + hg + "!")

        # find relevant operating system id
        if 'operatingsystem' in config['hostgroups'][hg]:
            try:
                hg_params['operatingsystem_id'] = client.operatingsystems.index(search=config['hostgroups'][hg]['operatingsystem'])['results'][0]['id']
            except:
                bail("Did not find operating system '" + config['hostgroups'][hg]['operatingsystem'] + "', which is configured for " + hg + "!")

        # add PXE loader if configured
        # TODO : validate this is one of the accepted/valid strings:
        # None, PXELinux BIOS, PXELinux UEFI, Grub UEFI, Grub2 BIOS, Grub2 ELF, Grub2 UEFI, Grub2 UEFI SecureBoot, Grub2 UEFI HTTP, Grub2 UEFI HTTPS, Grub2 UEFI HTTPS SecureBoot, iPXE Embedded, iPXE UEFI HTTP, iPXE Chain BIOS, iPXE Chain UEFI
        if 'pxe_loader' in config['hostgroups'][hg]:
            hg_params['pxe_loader'] = config['hostgroups'][hg]['pxe_loader']

        # add any other parameters configured (if any)
        if 'parameters' in config['hostgroups'][hg]:
            for p in config['hostgroups'][hg]['parameters']:
                hg_params['group_parameters_attributes'].append(p)


        #
        # all necessary data collected - now create or update existing host group
        #

        found = 0								# no existing similar group found yet
        # search through all existing groups for the current group
        for hg_f in existing['hostgroups']:

            if hg_params['name'] == hg_f['name']:

                # we found an existing group, update it with our values
                found = 1
                hg_params['id'] = hg_f['id']					# save id for later
                try:
                    info("... found '" + hg_params['name'] + "; updating")
                    client.hostgroups.update(id=hg_params['id'], hostgroup=hg_params)
                except:
                    error = extract_msg(sys.exc_info()[1], \
                                       "Foreman did not accept our hostgroup update parameters (" + \
                                        hg_params['name'] + ") : ", \
                                       "Unknown error")
                    bail(error)
                break								# no point searching further

        # host group does not exist; create it
        if not found:

            try:
                info("... did not find '" + hg_params['name'] + "; creating")
                hg_params['id'] = client.hostgroups.create(location_id=location_id, organization_id=organization_id, hostgroup=hg_params)['id']
            except:
                error = extract_msg(sys.exc_info()[1], \
                                   "Foreman did not accept our hostgroup create parameters (" + \
                                    hg_params['name'] + ") : ", \
                                   "Unknown error")
                bail(error)


    # ready to handle next type of host group
    child_run += 1

#bail("INGENTING GALT")


# TODO - raykrist
# -------------------------------------------
#
# create compute resources
#

info("Creating or updating compute resources ...")

resource_config = himutils.load_config('config/compute_resources.yaml')
if keystone.region not in resource_config:
    num_resources = resource_config['default']['num_resources']
else:
    num_resources = resource_config[keystone.region]['num_resources']
logger.debug("=> number of compute resources for %s: %s" % (keystone.region, num_resources))
found_resources = foreman.get_compute_resources()

for x in range(1, (num_resources+1)):
    name = '%s-controller-0%s' % (keystone.region, x)
    resource = dict()
    resource['name'] = name
    resource['provider'] = 'Libvirt'
    resource['set_console_password'] = 0
    resource['url'] = 'qemu+tcp://%s.%s:16509/system' % (name, domain)
    if name not in found_resources:
        logger.debug('=> add new compute resource %s' % name)
        result = client.create_computeresources(resource)
        found_resources[name] = result['id']
    else:
        logger.debug('=> update compute resource %s' % name)
        result = client.update_computeresources(found_resources[name], resource)


# -------------------------------------------
#
# create compute profiles
#

info("Create compute profiles if missing ...")

profile_config = himutils.load_config('config/compute_profiles.yaml')
if keystone.region not in profile_config:
    profiles = profile_config['default']
else:
    profiles = profile_config[keystone.region]

found_profiles = foreman.get_compute_profiles()

verified_profiles = list()

if found_profiles:
    for found_profile in found_profiles.keys():
        if found_profile not in profiles:
            # We only want profiles defined in config/compute_profiles.yaml
            logger.debug("=> deleting profile %s" % found_profile)
            client.destroy_computeprofiles(found_profiles[found_profile])
        else:
            verified_profiles.append(found_profile)

for profile_name in profiles.keys():
    if profile_name not in verified_profiles:
        profile_result = client.create_computeprofiles({'name': profile_name})
        logger.debug("=> create profile result %s" % profile_result)
        for r in found_resources:
            attr_result = client.create_computeattributes(
                compute_profile_id=profile_result['id'],
                compute_resource_id=found_resources[r],
                compute_attribute=profiles[profile_name])
            logger.debug("=> create attributes result %s" % attr_result)
    else:
        ext_profile = client.show_computeprofiles(found_profiles[profile_name])
        for attr in ext_profile['compute_attributes']:
            name = attr['compute_profile_name']
            if attr['vm_attrs'] == profiles[name]['vm_attrs']:
                logger.debug("=> no change for %s" % name)
            else:
                for r in found_resources:
                    result = client.update_computeattributes(
                        compute_profile_id=attr['compute_profile_id'],
                        compute_resource_id=found_resources[r],
                        id=attr['id'],
                        compute_attribute=profiles[name])
                    logger.debug("=> update result %s" % result)


# -------------------------------------------
#
# finished!
#

info("All set, good to go ...")
print
