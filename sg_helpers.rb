# helper functions for updating security groups
#
# AWS credentials should be in environment variables AWS_ACCESS_KEY_ID and
# AWS_SECRET_ACCESS_KEY

require 'fog/aws'

FAIL_RESPONSE = {'status' => false, 'sg_id' => nil, 'add_perms' => nil, 'del_perms' => nil}

# Validate security group against spec
#
# Parameters
# * group_spec<Hash>
#   * 'group_name'<String> - Name of security group.
#   * 'group_description'<String> - Description of security group.
#   * 'vpc_id'<String> - ID of the VPC
#   * 'region'<String> - Region of security group.
#   * 'permissions'<Array>
#     * permission<Hash>
#       * 'ips'<Array>
#         * ip<String>
#       * 'from_port'<Integer> - Start of port range (-1 for ICMP wildcard)
#       * 'to_port'<Integer> - End of port range (-1 for ICMP wildcard)
#       * 'protocol'<String> - IP protocol, must be in ['tcp', 'udp', 'icmp']

# Returns
# * result<Hash>
#   * 'status'<Boolean> - true if group is up-to-date, false otherwise
#   * 'sg_id'<String> - ID of security group
#   * 'add_perms'<Array> - permissions in spec but not actual group
#     * permission<Hash>
#   * 'del_perms'<Array> - permissions in actual group but not spec
#     * permission<Hash>
def sg_audit(group_spec)
  update(group_spec, true)
end

# Create new security group
#
# Parameters
# * group_spec<Hash>
#   * 'group_name'<String> - Name of security group.
#   * 'group_description'<String> - Description of security group.
#   * 'vpc_id'<String> - ID of the VPC
#   * 'region'<String> - Region of security group.
#   * 'permissions'<Array>
#     * permission<Hash>
#       * 'ips'<Array>
#         * ip<String>
#       * 'from_port'<Integer> - Start of port range (-1 for ICMP wildcard)
#       * 'to_port'<Integer> - End of port range (-1 for ICMP wildcard)
#       * 'protocol'<String> - IP protocol, must be in ['tcp', 'udp', 'icmp']

# Returns
# * result<Hash>
#   * 'status'<Boolean> - true if create succeeded, false otherwise
#   * 'sg_id'<String> - ID of security group
#   * 'add_perms'<Array> - permissions added to group
#     * permission<Hash>
#   * 'del_perms'<Array> - permissions deleted from group
#     * permission<Hash>
def sg_create(group_spec)
  begin
    ec2 = get_ec2(group_spec['region'])
    response = ec2.create_security_group(group_spec['group_name'],
      group_spec['group_description'] || 'none', group_spec['vpc_id'])
      unless response.body['return']
        puts "Failed to create group #{group_spec['group_name']}"
        return FAIL_RESPONSE
      end
  rescue => exception
    warn exception.message
    return FAIL_RESPONSE
  end
  update(group_spec)
end

# Update security group
#
# Parameters
# * group_spec<Hash>
#   * 'group_name'<String> - Name of security group.
#   * 'group_description'<String> - Description of security group.
#   * 'vpc_id'<String> - ID of the VPC
#   * 'region'<String> - Region of security group.
#   * 'permissions'<Array>
#     * permission<Hash>
#       * 'ips'<Array>
#         * ip<String>
#       * 'from_port'<Integer> - Start of port range (-1 for ICMP wildcard)
#       * 'to_port'<Integer> - End of port range (-1 for ICMP wildcard)
#       * 'protocol'<String> - IP protocol, must be in ['tcp', 'udp', 'icmp']

# Returns
# * result<Hash>
#   * 'status'<Boolean> - true if update succeeded, false otherwise
#   * 'sg_id'<String> - ID of security group
#   * 'add_perms'<Array> - permissions added to group
#     * permission<Hash>
#   * 'del_perms'<Array> - permissions deleted from group
#     * permission<Hash>
def sg_update(group_spec)
  update(group_spec)
end

# Returns group spec for existing security group
#
# Parameters
# * sg_id<String> - ID of security group
# * vpc_id<String> - ID of the VPC
# * region<String> - Region of security group

# Returns
# * group_spec<Hash>
#   * 'group_name'<String> - Name of security group.
#   * 'group_description'<String> - Description of security group.
#   * 'vpc_id'<String> - ID of the VPC
#   * 'region'<String> - Region of security group.
#   * 'permissions'<Array>
#     * permission<Hash>
#       * 'ips'<Array>
#         * ip<String>
#       * 'from_port'<Integer> - Start of port range (-1 for ICMP wildcard)
#       * 'to_port'<Integer> - End of port range (-1 for ICMP wildcard)
#       * 'protocol'<String> - IP protocol, must be in ['tcp', 'udp', 'icmp']
def sg_dump(sg_id, vpc_id, region)
  ec2 = get_ec2(region)
  group = ec2.describe_security_groups('group-id' => [sg_id]).body['securityGroupInfo'][0]

  unless group
    puts "Security group #{sg_id} does not exist"
    return nil
  end

  group_spec = {'group_name' => group['groupName'],
                'group_description' => group['groupDescription'],
                'vpc_id' => vpc_id,
                'region' => region,
                'permissions' => []}
  response = sg_audit(group_spec)
  group_spec['permissions'] = response['del_perms']
  group_spec
end

def add_perm(group_id, ec2, perm)
  response = ec2.authorize_security_group_ingress('GroupId' => group_id,
                                                  'IpPermissions' => [{'FromPort' => perm['from_port'],
                                                                      'IpProtocol' => perm['protocol'],
                                                                      'IpRanges' => perm['ips'].map {|x| {'CidrIp' => x}},
                                                                      'ToPort' => perm['to_port']}])
  response.body['return']
end

def del_perm(group_id, ec2, perm)
  response = ec2.revoke_security_group_ingress('GroupId' => group_id,
                                                'IpPermissions' => [{'FromPort' => perm['from_port'],
                                                                    'IpProtocol' => perm['protocol'],
                                                                    'IpRanges' => perm['ips'].map {|x| {'CidrIp' => x}},
                                                                    'ToPort' => perm['to_port']}])
  response.body['return']
end

def get_ec2(region)
  Fog::Compute.new :provider => 'AWS',
                   :region => region,
                   :aws_access_key_id => ENV['AWS_ACCESS_KEY_ID'],
                   :aws_secret_access_key => ENV['AWS_SECRET_ACCESS_KEY']
end

def same_perm_type(spec_perm, cur_perm)
  spec_perm['protocol'] == cur_perm['ipProtocol'] and \
    spec_perm['from_port'] == cur_perm['fromPort'] and \
    spec_perm['to_port'] == cur_perm['toPort']
end

def update(group_spec, audit = false)
  ec2 = get_ec2(group_spec['region'])
  group = ec2.describe_security_groups('group-name' => [group_spec['group_name']]).body['securityGroupInfo'][0]

  unless group
    puts "Security group #{group_spec['group_name']} does not exist"
    return FAIL_RESPONSE
  end

  status = true

  cur_perms = group['ipPermissions']
  spec_perms = group_spec['permissions']

  add_perms = []
  del_perms = []

  # update permissions in spec
  spec_perms.each do |perm|
    index = cur_perms.index {|x| same_perm_type(perm, x)}
    unless index
      add_perms << perm
      status = add_perm(group['groupId'], ec2, perm) and status unless audit
      next
    end
    cur_ips = cur_perms[index]['ipRanges'].map {|x| x['cidrIp']}
    spec_ips = perm['ips']

    missing_ips = spec_ips - cur_ips
    unless missing_ips.empty?
      missing_perm = perm.clone
      missing_perm['ips'] = missing_ips
      add_perms << missing_perm
      status = add_perm(group['groupId'], ec2, missing_perm) and status unless audit
    end

    extra_ips = cur_ips - spec_ips
    unless extra_ips.empty?
      extra_perm = perm.clone
      extra_perm['ips'] = extra_ips
      del_perms << extra_perm
      status = del_perm(group['groupId'], ec2, extra_perm) and status unless audit
    end

    cur_perms.delete_at(index)
  end

  # delete permissions not in spec
  cur_perms.each do |cur_perm|
    cur_ips = cur_perm['ipRanges'].map {|x| x['cidrIp']}
    perm = {'ips' => cur_ips,
            'protocol' => cur_perm['ipProtocol'],
            'from_port' => cur_perm['fromPort'],
            'to_port' => cur_perm['toPort']}
    del_perms << perm
    status = del_perm(group['groupId'], ec2, perm) and status unless audit
  end

  status = false if audit and not (add_perms.empty? and del_perms.empty?)

  {'status' => status, 'sg_id' => group['groupId'], 'add_perms' => add_perms, 'del_perms' => del_perms}
end
