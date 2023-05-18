import EC2, { 
    DescribeSecurityGroupsRequest, 
    IpPermission, 
    AuthorizeSecurityGroupIngressRequest 
} from 'aws-sdk/clients/ec2'
import axios from 'axios'

const ec2 = new EC2({
    region: process.env.AWS_REGION,
    apiVersion: '2023-05-05',
})

async function getGithubIpList(): Promise<string[]> {
    try {
        const response = await axios.get('https://api.github.com/meta')
        return response.data.hooks
    } catch(error: any) {
        throw new Error(error)
    }
}   

async function getAwsSecurityGroup(groupId: string[]){

    const params: DescribeSecurityGroupsRequest = {
        GroupIds: groupId
    }

    const group = await ec2.describeSecurityGroups(params).promise()
    
    if(!group.SecurityGroups){
        throw new Error("Group not found")
    }
    
    return group.SecurityGroups[0]
}

function verifyRuleAlreadyExist(rule: IpPermission, ip: string): boolean {
    
    let ruleExist

    if(ip.includes(".")){
        ruleExist = rule.IpRanges?.find((ipRange) => ipRange.CidrIp == ip && ipRange.Description == 'Jenkins') 
    } else {
        ruleExist = rule.Ipv6Ranges?.find((ipRange) => ipRange.CidrIpv6 == ip && ipRange.Description == 'Jenkins')
    }

    if(ruleExist){
        return true
    }
       
    return false
}

async function createRule(groupId: string, ip: string) {

    let ruleParams: AuthorizeSecurityGroupIngressRequest

    if(ip.includes('.')){
        ruleParams = {
            GroupId: groupId,
            IpPermissions: [{
                IpProtocol: 'tcp',
                FromPort: 8080,
                ToPort: 8080,
                IpRanges: [{ CidrIp: ip, Description: 'Jenkins' }]
            }]
        }
    } else {
        ruleParams = {
            GroupId: groupId,
            IpPermissions: [{
                IpProtocol: 'tcp',
                FromPort: 8080,
                ToPort: 8080,
                Ipv6Ranges: [{ CidrIpv6: ip, Description: 'Jenkins' }]
            }]
        } 
    }   
    await ec2.authorizeSecurityGroupIngress(ruleParams).promise()
}

export async function handler(){

    const groupId = process.env.SECURITY_GROUP!
    
    const [
        securityGroup, 
        githubIpList
    ] = await Promise.all([getAwsSecurityGroup([groupId]), getGithubIpList()])

    const onlyJenkinsPort = securityGroup.IpPermissions?.filter((ipPermission) => ipPermission.FromPort == 8080)

    githubIpList.forEach((ip)=> {
        onlyJenkinsPort?.forEach((rule) => {
            if(!verifyRuleAlreadyExist(rule, ip)){
                createRule(groupId, ip)
            }
        })
    })
}





